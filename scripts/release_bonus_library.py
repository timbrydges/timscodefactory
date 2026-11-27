"""One audited Bonus Library production release.

  python scripts/release_bonus_library.py --sha <40-hex> --repo <bonus-library clone> \
      --approval "Release <sha> to production" [--migrations-applied FILE ...] [--dry-run]

Replaces the three manual release steps with one idempotent run:
  1. budget: set the AI-cover budget record's app_commit to the release (DynamoDB,
     conditional on the record existing; skipped when it already matches);
  2. activation: upsert BONUS_AI_COVER_ACTIVATION_SHA for production on Vercel;
  3. deploy: create a production deployment of exactly that commit, unless one
     for the same commit is already READY.

Gates, all checked before any write: the owner's exact phrase for this SHA; the
SHA is the tip of the clone's origin/main; every Supabase migration added since
the currently released commit is named in --migrations-applied (the owner runs
SQL; this script never does). Each run, including --dry-run, writes a new
audit record that is never overwritten: time, branch, SHA, previous release,
the Factory reviewer verdicts in the released commits, the budget record and
each step's outcome, chained to the previous record by digest.

Credentials: AWS from the standard environment/profile; Vercel from VERCEL_TOKEN.
Neither is printed or written. It never merges, rolls back or edits code.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import urllib.request

TABLE, REGION = 'tims-software-factory-state', 'ca-central-1'
BUDGET_KEY = {'PK': {'S': 'BONUS_LIBRARY#AI_COVER#20261101'}, 'SK': {'S': 'BUDGET'}}
TEAM, PROJECT, PROJECT_ID = 'team_ws5Iux3Q0xQIYj8s622ZW1t9', 'bonus-library', 'prj_UgiH06vtoFglvEMcUdi23DltFEbP'
ENV_KEY = 'BONUS_AI_COVER_ACTIVATION_SHA'
SHA = re.compile(r'[0-9a-f]{40}')
VERDICT = re.compile(r'Factory attempt ([a-z0-9-]+); reviewer verdict (APPROVE|REJECT)')
AUDIT = Path(os.environ.get('FACTORY_RUNNER_ROOT', Path.home() / 'FactoryRunner')) / 'release-audit'


def phrase_for(sha):
    return f'Release {sha} to production'


def git(repo, *args):
    return subprocess.run(['git', '-C', str(repo), *args], check=True, capture_output=True, text=True).stdout


class Vercel:
    """Fixed-host Vercel REST calls; the token stays in memory."""
    def __init__(self, token):
        if not token or len(token) < 16:
            raise ValueError('VERCEL_TOKEN is not set')
        self._token = token

    def call(self, method, path, body=None):
        request = urllib.request.Request('https://api.vercel.com' + path, method=method,
            data=None if body is None else json.dumps(body).encode(),
            headers={'Authorization': f'Bearer {self._token}', 'Content-Type': 'application/json'})
        with urllib.request.urlopen(request, timeout=60) as response:
            return json.loads(response.read(2_000_000))

    def ready_production(self, sha):
        found = self.call('GET', f'/v6/deployments?projectId={PROJECT_ID}&teamId={TEAM}&target=production&limit=20')
        return [d for d in found.get('deployments', [])
                if d.get('meta', {}).get('githubCommitSha') == sha and d.get('state') == 'READY']

    def upsert_activation(self, sha):
        return self.call('POST', f'/v10/projects/{PROJECT}/env?upsert=true&teamId={TEAM}',
                         {'key': ENV_KEY, 'value': sha, 'type': 'encrypted', 'target': ['production']})

    def deploy(self, sha):
        return self.call('POST', f'/v13/deployments?forceNew=1&teamId={TEAM}',
            {'name': PROJECT, 'project': PROJECT, 'target': 'production',
             'gitSource': {'type': 'github', 'org': 'timbrydges', 'repo': 'bonus-library', 'ref': 'main', 'sha': sha}})


def dynamodb():
    import boto3
    from botocore.config import Config
    return boto3.client('dynamodb', region_name=REGION, config=Config(retries={'max_attempts': 0}))


def released_commit(db):
    item = db.get_item(TableName=TABLE, Key=BUDGET_KEY, ConsistentRead=True).get('Item')
    if not item:
        raise ValueError('AI-cover budget record does not exist')
    budget = {k: next(iter(v.values())) for k, v in item.items()
              if k not in ('PK', 'SK') and set(v) <= {'S', 'N', 'BOOL'}}
    return item.get('app_commit', {}).get('S'), budget


def preflight(*, sha, repo, approval, migrations_applied, db):
    if not SHA.fullmatch(sha or ''):
        raise ValueError('full 40-character release SHA required')
    if approval != phrase_for(sha):
        raise ValueError(f'the owner\'s exact phrase is required: "{phrase_for(sha)}"')
    git(repo, 'fetch', '-q', 'origin', 'main')
    if git(repo, 'rev-parse', 'origin/main').strip() != sha:
        raise ValueError('release SHA must be the tip of bonus-library main')
    previous, budget = released_commit(db)
    span = f'{previous}..{sha}' if previous and SHA.fullmatch(previous) else sha
    added = [p for p in git(repo, 'diff', '--name-only', '--diff-filter=A', span, '--',
                            'supabase/migrations').split() if p] if previous else []
    unconfirmed = [p for p in added if Path(p).name not in set(migrations_applied)]
    if unconfirmed:
        raise ValueError('apply and confirm these migrations first: ' + ', '.join(unconfirmed))
    verdicts = [{'attempt': a, 'verdict': v} for a, v in VERDICT.findall(git(repo, 'log', '--format=%B', span))]
    if any(v['verdict'] != 'APPROVE' for v in verdicts):
        raise ValueError('a released Factory commit lacks an APPROVE verdict')
    return {'previous_release': previous, 'budget_record': budget, 'migrations': added, 'reviewer_verdicts': verdicts}


def write_audit(entry, directory=None):
    directory = Path(directory or AUDIT)
    directory.mkdir(parents=True, exist_ok=True)
    records = sorted(directory.glob('release-*.json'))
    entry = dict(entry, previous_audit_digest=('sha256:' + hashlib.sha256(records[-1].read_bytes()).hexdigest()
                                               if records else None))
    stamp = entry['timestamp'].replace(':', '').replace('-', '')[:15]
    path = directory / f"release-{stamp}-{entry['sha'][:12]}{'-dry-run' if entry['dry_run'] else ''}.json"
    with path.open('x') as handle:  # Never overwritten.
        handle.write(json.dumps(entry, indent=2, sort_keys=True) + '\n')
    return path


def release(*, sha, repo, approval, migrations_applied=(), dry_run=False, db=None, vercel=None,
            audit_dir=None, now=None, out=print):
    now = now or datetime.now(timezone.utc)
    db = db or dynamodb()
    entry = {'kind': 'bonus_library_release_audit_v1', 'timestamp': now.isoformat(), 'branch': 'main',
             'sha': sha, 'dry_run': dry_run, 'approval_phrase_matched': approval == phrase_for(sha), 'steps': {}}
    try:
        entry.update(preflight(sha=sha, repo=repo, approval=approval,
                               migrations_applied=migrations_applied, db=db))
        vercel = vercel or Vercel(os.environ.get('VERCEL_TOKEN', ''))
        steps = entry['steps']
        if entry['previous_release'] == sha:
            steps['budget'] = 'ALREADY_SET'
        elif dry_run:
            steps['budget'] = 'WOULD_SET'
        else:
            db.update_item(TableName=TABLE, Key=BUDGET_KEY, UpdateExpression='SET app_commit = :c',
                           ConditionExpression='attribute_exists(PK)',
                           ExpressionAttributeValues={':c': {'S': sha}})
            steps['budget'] = 'SET'
        steps['activation'] = 'WOULD_UPSERT' if dry_run else (vercel.upsert_activation(sha) and 'UPSERTED')
        ready = vercel.ready_production(sha)
        if ready:
            steps['deploy'] = {'status': 'ALREADY_READY', 'deployment': ready[0].get('uid') or ready[0].get('id')}
        elif dry_run:
            steps['deploy'] = {'status': 'WOULD_DEPLOY'}
        else:
            created = vercel.deploy(sha)
            steps['deploy'] = {'status': 'CREATED', 'deployment': created.get('id'), 'url': created.get('url')}
        entry['status'] = 'DRY_RUN_OK' if dry_run else 'RELEASED'
    except Exception as error:
        entry['status'] = 'STOPPED'
        entry['error'] = f'{type(error).__name__}: {str(error)[:300]}'
    path = write_audit(entry, audit_dir)
    out(f"{entry['status']}: {sha[:12]} audit {path}")
    return entry


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--sha', required=True)
    parser.add_argument('--repo', required=True)
    parser.add_argument('--approval', required=True)
    parser.add_argument('--migrations-applied', nargs='*', default=[])
    parser.add_argument('--dry-run', action='store_true')
    args = parser.parse_args(argv)
    entry = release(sha=args.sha, repo=args.repo, approval=args.approval,
                    migrations_applied=args.migrations_applied, dry_run=args.dry_run)
    return 0 if entry['status'] in ('RELEASED', 'DRY_RUN_OK') else 1


if __name__ == '__main__':
    raise SystemExit(main())
