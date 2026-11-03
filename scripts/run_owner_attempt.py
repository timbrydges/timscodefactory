"""One owner command for one approved private-source development attempt.

Runs the local preflight checks, prepares the pinned attempt files (the owner's
approval), loads the OpenAI key without echo, runs the attempt exactly once and
summarizes the journal. Running it with --owner-authorized is the approval for
one attempt at the printed cap. It never retries, merges, publishes or deploys,
and never prints or stores the key.
"""
import argparse
from datetime import datetime, timezone
from decimal import Decimal
import getpass
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'src'))
from factory_runtime.private_source_composition import (ATTEMPT_VOLUME_MAX_BYTES,
    read_private_source_configuration)

_spec = importlib.util.spec_from_file_location('prepare_development_attempt',
                                               ROOT/'scripts'/'prepare_development_attempt.py')
prepare_module = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(prepare_module)

PINNED_MANIFEST = 'sha256:72afb0498ff1d0a248324ef1d13686ab052363f28377bfcdbd42426d703e6db3'
KEY = re.compile(r'sk-[A-Za-z0-9_\-]{16,512}')
STAGES = ('builder', 'reviewer', 'repair_builder', 'repair_reviewer',
          'repair2_builder', 'repair2_reviewer')


def committed_manifest_matches(root):
    git = ['git', '-C', str(root)]
    manifest = subprocess.run(git + ['show', 'HEAD:MANIFEST.sha256'], check=True,
                              capture_output=True, timeout=60).stdout.decode('utf-8')
    expected = {}
    for line in manifest.splitlines():
        digest, _, path = line.partition('  ')
        if not re.fullmatch(r'[0-9a-f]{64}', digest) or not path:
            return False
        expected[path] = digest
    listing = subprocess.run(git + ['ls-tree', '-r', '-z', 'HEAD'], check=True,
                             capture_output=True, timeout=60).stdout.split(b'\0')
    blobs = {}
    for record in filter(None, listing):
        meta, path = record.split(b'\t', 1)
        blobs[path.decode('utf-8')] = meta.split()[2].decode()
    if not expected or any(path not in blobs for path in expected):
        return False
    names = list(expected)
    batch = subprocess.run(git + ['cat-file', '--batch'], input=''.join(blobs[p] + '\n' for p in names).encode(),
                           check=True, capture_output=True, timeout=120).stdout
    offset = 0
    for path in names:
        header_end = batch.index(b'\n', offset)
        size = int(batch[offset:header_end].split()[2])
        content = batch[header_end + 1:header_end + 1 + size]
        offset = header_end + 1 + size + 1
        if hashlib.sha256(content).hexdigest() != expected[path]:
            return False
    return True


class HostOps:
    """Real host effects; tests replace these with offline fakes."""
    runner_root = r'C:\FactoryRunner'
    def docker_image_digest(self, image):
        # Registry images have a repo digest; locally built check images use their image ID.
        out = subprocess.run(['docker', 'image', 'inspect', image, '--format',
                              '{{if .RepoDigests}}{{index .RepoDigests 0}}{{else}}{{.Id}}{{end}}'],
                             check=True, capture_output=True, text=True, timeout=30).stdout.strip()
        return out

    def volume_total(self, path):
        return shutil.disk_usage(path).total

    def factory_head(self):
        head = subprocess.check_output(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'], text=True).strip()
        dirty = subprocess.check_output(['git', '-C', str(ROOT), 'status', '--porcelain'], text=True)
        return head, bool(dirty)

    def self_update(self):
        """Fast-forward to the latest owner-merged main; never merges, rebases or discards."""
        git = ['git', '-C', str(ROOT)]
        try:
            subprocess.run(git + ['fetch', '-q', 'origin', 'main'], check=True, capture_output=True, timeout=60)
        except (OSError, subprocess.SubprocessError):
            return 'offline'
        head = subprocess.check_output(git + ['rev-parse', 'HEAD'], text=True).strip()
        latest = subprocess.check_output(git + ['rev-parse', 'origin/main'], text=True).strip()
        if head == latest:
            return 'current'
        if subprocess.run(git + ['merge-base', '--is-ancestor', head, latest], capture_output=True).returncode:
            return 'diverged'
        subprocess.run(git + ['merge', '--ff-only', '-q', latest], check=True, capture_output=True, timeout=60)
        return 'updated'

    def verify_integrity(self):
        """The committed Factory files must match the reviewed MANIFEST.sha256.

        Hashes Git's stored content, so Windows line-ending conversion does not matter;
        local edits are caught separately by the clean-checkout check (git status).
        """
        return committed_manifest_matches(ROOT)

    def restart(self, argv):
        env = {**os.environ, 'FACTORY_SELF_UPDATED': '1'}
        return subprocess.call([sys.executable, str(Path(__file__).resolve()), *argv], env=env)

    def wait_for_key_copy(self):
        # Hidden input: even an accidental paste here is never echoed.
        getpass.getpass('Copy the OpenAI key now, then press Enter (input is hidden): ')

    def read_clipboard(self):
        return subprocess.run(['powershell', '-NoProfile', '-Command', 'Get-Clipboard'],
                              check=True, capture_output=True, text=True, timeout=15).stdout

    def clear_clipboard(self):
        subprocess.run(['powershell', '-NoProfile', '-Command', 'Set-Clipboard -Value " "'],
                       check=False, capture_output=True, timeout=15)

    def publish(self, attempt_id):
        import tempfile
        spec = importlib.util.spec_from_file_location('publish_approved_attempt',
                                                      ROOT/'scripts'/'publish_approved_attempt.py')
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        root = Path(self.runner_root)
        with tempfile.TemporaryDirectory(prefix='factory-publish-') as workdir:
            return module.publish(attempt_dir=root/'dev-attempts'/attempt_id, attempt_id=attempt_id,
                                  results_file=root/'dev-results'/f'{attempt_id}.json', workdir=workdir)

    def run_attempt(self, args, env):
        return subprocess.run([sys.executable, str(ROOT/'scripts'/'development_attempt.py'), *args],
                              env=env, capture_output=True, text=True).stdout


def next_attempt_id(attempts, inputs, prefix='pagination'):
    used = set()
    for folder in (attempts, inputs):
        if folder.is_dir():
            for item in folder.iterdir():
                match = re.fullmatch(prefix + r'-(\d{3})(?:\.consumed\.json)?', item.name)
                if match:
                    used.add(int(match.group(1)))
    return f'{prefix}-{max(used, default=0)+1:03d}'


def summarize(directory):
    """Bounded, key-free summary of the attempt journal and artifact."""
    summary = {'stages': {}, 'total_cost_usd': '0', 'uncertain_max_usd': '0'}
    total, uncertain = Decimal(0), Decimal(0)
    for stage in STAGES:
        for state in ('completed', 'failed'):
            path = directory/f'{stage}.{state}.json'
            if not path.is_file():
                continue
            data = json.loads(path.read_text(encoding='utf-8'))
            entry = {'state': state.upper()}
            if state == 'completed':
                entry['cost_usd'] = data.get('cost_usd')
                total += Decimal(data.get('cost_usd') or '0')
                proposal = data.get('proposal') or {}
                if stage.endswith('reviewer'):
                    entry['verdict'] = proposal.get('verdict')
                    entry['findings'] = proposal.get('findings', [])[:20]
                else:
                    entry['decision_type'] = proposal.get('type')
                    entry['summary'] = str(proposal.get('summary', proposal.get('reason', '')))[:500]
            else:
                # A failed call may still have been billed, up to its stage cap.
                entry['failure_code'] = data.get('failure_code')
                entry['max_cost_usd'] = data.get('max_cost_usd')
                uncertain += Decimal(data.get('max_cost_usd') or '0')
            summary['stages'][stage] = entry
    summary['total_cost_usd'] = str(total)
    summary['uncertain_max_usd'] = str(uncertain)
    for name in ('tests.json', 'repair-tests.json', 'repair2-tests.json'):
        path = directory/name
        if path.is_file():
            observation = json.loads(path.read_text(encoding='utf-8')).get('test_observation', {})
            summary[name.replace('.json', '')] = observation.get('status')
    return summary


def load_key(ops):
    key = os.environ.get('FACTORY_OPENAI_API_KEY', '').strip()
    if not key:
        ops.wait_for_key_copy()
        key = ops.read_clipboard().strip()
        ops.clear_clipboard()
    if not KEY.fullmatch(key):
        raise ValueError('clipboard did not hold an OpenAI key (expected sk-...); nothing was run')
    return key


def run(*, runner_root, attempt_id, repair_rounds, input_price, output_price, pricing_source,
        image, manifest, hours, ops, out=print, now=None, key=None, task='bonus-library-pagination'):
    root = Path(runner_root)
    config_path = root/'bonus-source-fetch.json'
    raw = config_path.read_bytes()
    config_digest = 'sha256:' + hashlib.sha256(raw).hexdigest()
    config = read_private_source_configuration(config_path, config_digest, owner_authorized=True)
    head, dirty = ops.factory_head()
    if dirty:
        raise ValueError('Factory checkout has local changes; run git status in factory-src')
    if not ops.verify_integrity():
        raise ValueError('Factory files do not match MANIFEST.sha256; nothing was run')
    total = ops.volume_total(config.attempt_parent)
    if not 0 < total <= ATTEMPT_VOLUME_MAX_BYTES:
        raise ValueError('source volume is not attached; reattach source-attempts.vhdx')
    image_ref = ops.docker_image_digest(image)
    inputs, attempts, results = root/'dev-inputs', root/'dev-attempts', root/'dev-results'
    for folder in (inputs, attempts, results):
        folder.mkdir(exist_ok=True)
    task_file = prepare_module.task_path(task)
    attempt_id = attempt_id or next_attempt_id(attempts, inputs, task.removeprefix('bonus-library-'))
    prepared = prepare_module.prepare(output=inputs/attempt_id, attempt_id=attempt_id,
        image_ref=image_ref, source_config_sha256=config_digest, manifest=manifest,
        input_price=input_price, output_price=output_price, pricing_source=pricing_source,
        now=now or datetime.now(timezone.utc), hours=hours, source_commit=head,
        repair_rounds=repair_rounds, task=task_file)
    out(f"Prepared {attempt_id} ({task}): cap US${prepared['total_cap_usd']}, "
        f"repair rounds {repair_rounds}, approval valid until {prepared['approval_expires_at']}")
    if key is None:
        key = load_key(ops)
        out('Key loaded (not shown).')
    out('Running; this can take several minutes...')
    folder = inputs/attempt_id
    args = ['--execute-approved-once', '--owner-authorized',
            '--pins', str(folder/'pins.json'), '--approval', str(folder/'approval.json'),
            '--pricing', str(folder/'pricing.json'), '--contract', str(folder/'contract.json'),
            '--attempt-directory', str(attempts/attempt_id),
            '--source-config', str(config_path), '--source-config-sha256', config_digest]
    env = {**os.environ, 'FACTORY_OPENAI_API_KEY': key}
    try:
        stdout = ops.run_attempt(args, env)
    finally:
        env.clear()
        key = None
    try:
        outcome = json.loads(stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        outcome = {'status': 'UNKNOWN_OUTPUT'}
    summary = {'attempt_id': attempt_id, 'factory_commit': head, 'outcome': outcome,
               **summarize(attempts/attempt_id)}
    path = results/f'{attempt_id}.json'
    path.write_text(json.dumps(summary, indent=2, sort_keys=True), encoding='utf-8')
    extra = (f" (plus up to US${summary['uncertain_max_usd']} for failed calls; check OpenAI usage)"
             if Decimal(summary['uncertain_max_usd']) else '')
    out(f"Result: {outcome.get('status')}  total cost US${summary['total_cost_usd']}{extra}")
    reason = (outcome.get('result') or {}).get('reason') or outcome.get('reason')
    if reason:
        out(f"  reason: {str(reason)[:160]}")
    for stage, entry in summary['stages'].items():
        detail = entry.get('verdict') or entry.get('decision_type') or entry.get('failure_code') or ''
        out(f"  {stage}: {entry['state']} {detail} US${entry.get('cost_usd') or '0'}")
        for finding in entry.get('findings', []):
            out(f"    - {finding[:300]}")
        if entry.get('decision_type') == 'escalate' and entry.get('summary'):
            out(f"    reason: {entry['summary'][:300]}")
    out(f'Full summary: {path}  (no secrets; safe to share). Do not rerun; a new attempt needs a new approval.')
    return summary


CONTINUE_AFTER = {'REJECTED', 'STOPPED'}  # Definite, non-approved outcomes only.
# A complete provider response that ran out of output tokens: the outcome is known
# (no proposal), only its exact charge is not, so it is counted at its full stage cap.
DEFINITE_FAILURES = {'output_token_limit'}


def definite_failure(summary):
    failed = [e for e in summary['stages'].values() if e['state'] == 'FAILED']
    return (summary['outcome'].get('status') == 'NEEDS_RECONCILIATION' and bool(failed)
            and all(e.get('failure_code') in DEFINITE_FAILURES for e in failed))


def run_batch(*, max_attempts, max_total_usd, publish_approved, ops, out=print, **options):
    """Owner-bounded sequence of attempts; stops at approval, a limit or any uncertainty."""
    if type(max_attempts) is not int or not 1 <= max_attempts <= 5:
        raise ValueError('between 1 and 5 attempts required')
    budget = Decimal(str(max_total_usd))
    task_spec = json.loads(prepare_module.task_path(options.get('task', 'bonus-library-pagination')).read_bytes())
    per_attempt = prepare_module.attempt_cap(task_spec, options['repair_rounds'])
    if not budget.is_finite() or not per_attempt <= budget <= Decimal('20'):
        raise ValueError(f'total budget must cover at least one attempt cap (US${per_attempt}) and be at most US$20')
    if not ops.verify_integrity():
        raise ValueError('Factory files do not match MANIFEST.sha256; nothing was run')
    key = load_key(ops)
    out(f'Key loaded (not shown). Batch: up to {max_attempts} attempt(s), US${budget} total, '
        f'publish approved: {"yes" if publish_approved else "no"}.')
    spent, records, status = Decimal(0), [], 'LIMIT_REACHED'
    try:
        for number in range(1, max_attempts + 1):
            if spent + per_attempt > budget:
                status = 'BUDGET_REACHED'
                break
            out(f'--- Attempt {number} of {max_attempts} (spent so far US${spent}) ---')
            summary = run(ops=ops, out=out, key=key, attempt_id=None, **options)
            # Failed calls count at their cap so the batch limit stays a hard ceiling.
            spent += Decimal(summary['total_cost_usd']) + Decimal(summary['uncertain_max_usd'])
            outcome = summary['outcome'].get('status')
            definite = definite_failure(summary)
            uncertain = not definite and any(entry['state'] == 'FAILED' for entry in summary['stages'].values())
            record = {'attempt_id': summary['attempt_id'], 'status': outcome,
                      'cost_usd': summary['total_cost_usd']}
            records.append(record)
            if outcome == 'TICK_COMPLETED':
                status = 'APPROVED'
                if publish_approved:
                    record['publication'] = ops.publish(summary['attempt_id'])
                    status = 'APPROVED_AND_PUBLISHED'
                break
            if (outcome not in CONTINUE_AFTER and not definite) or uncertain:
                status = 'STOPPED_FOR_RECONCILIATION'
                break
    finally:
        key = None
    batch = {'status': status, 'attempts': records, 'spent_usd': str(spent),
             'max_attempts': max_attempts, 'max_total_usd': str(budget)}
    results = Path(options['runner_root'])/'dev-results'
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    path = results/f'batch-{stamp}.json'
    path.write_text(json.dumps(batch, indent=2, sort_keys=True), encoding='utf-8')
    out(f'Batch finished: {status}; spent US${spent}. Summary: {path}')
    for record in records:
        link = record.get('publication', {}).get('url', '')
        out(f"  {record['attempt_id']}: {record['status']} US${record['cost_usd']} {link}")
    return batch


def main(argv=None, ops=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--owner-authorized', action='store_true')
    parser.add_argument('--runner-root', default=r'C:\FactoryRunner')
    parser.add_argument('--attempt-id')
    parser.add_argument('--repair-rounds', type=int, choices=(0, 1, 2), default=2)
    parser.add_argument('--input-price', required=True)
    parser.add_argument('--output-price', required=True)
    parser.add_argument('--pricing-source')
    # Built by scripts/build_bonus_check_image.py: Node plus the pinned npm dependencies.
    parser.add_argument('--image', default='factory-bonus-checks:ef88df95bc3f')
    parser.add_argument('--manifest')  # Default: the task contract's pinned manifest.
    parser.add_argument('--task', default='bonus-library-pagination')
    parser.add_argument('--hours', type=int, default=12)
    parser.add_argument('--max-attempts', type=int, default=1)
    parser.add_argument('--max-total-usd')
    parser.add_argument('--publish-approved', action='store_true')
    parser.add_argument('--no-self-update', action='store_true')
    args = parser.parse_args(argv)
    if not args.owner_authorized:
        parser.error('explicit owner authorization required')
    source = args.pricing_source or f"openai-pricing-{datetime.now(timezone.utc):%Y-%m-%d}-owner-checked"
    options = dict(runner_root=args.runner_root, repair_rounds=args.repair_rounds,
        input_price=args.input_price, output_price=args.output_price, pricing_source=source,
        image=args.image, manifest=args.manifest, hours=args.hours, task=args.task)
    batch_mode = args.max_attempts > 1 or args.max_total_usd is not None or args.publish_approved
    if batch_mode and (args.attempt_id is not None or args.max_total_usd is None):
        parser.error('a batch needs --max-total-usd and picks attempt ids itself')
    if ops is None:
        ops = HostOps()
        ops.runner_root = args.runner_root
    if not args.no_self_update and os.environ.get('FACTORY_SELF_UPDATED') != '1':
        state = ops.self_update()
        if state == 'updated':
            print('Factory updated to the latest owner-merged version; restarting once.')
            return ops.restart(sys.argv[1:] if argv is None else list(argv))
        if state == 'diverged':
            raise ValueError('Factory checkout differs from the owner-merged main; nothing was run')
        if state == 'offline':
            print('Could not check for Factory updates; continuing with the verified local version.')
    if batch_mode:
        batch = run_batch(max_attempts=args.max_attempts, max_total_usd=args.max_total_usd,
                          publish_approved=args.publish_approved, ops=ops, **options)
        update_report(args.runner_root)
        return 0 if batch['status'].startswith('APPROVED') else 1
    summary = run(attempt_id=args.attempt_id, ops=ops, **options)
    update_report(args.runner_root)
    return 0 if summary['outcome'].get('status') == 'TICK_COMPLETED' else 1


def update_report(runner_root, out=print):
    """Refresh the learning report and cost dashboard; never affects the attempt result."""
    try:
        spec = importlib.util.spec_from_file_location('factory_report', ROOT/'scripts'/'factory_report.py')
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        module.write_report(runner_root, out=out)
    except Exception as error:
        out(f'Factory report not updated: {type(error).__name__}')


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except SystemExit:
        raise
    except Exception as error:
        print(f'STOPPED before or during the attempt: {type(error).__name__}: {str(error)[:300]}')
        raise SystemExit(1)
