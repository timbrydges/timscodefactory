"""Owner-run publication of one reviewer-approved attempt as a Bonus Library branch.

Verifies the attempt artifact, its recorded digest, the APPROVE verdict and the
bound review packet, then writes exactly the approved file contents onto a fresh
clone at the pinned target commit, commits them on a new factory/<attempt> branch
and pushes that branch only. It never pushes to an existing branch, force-pushes,
merges, deploys or calls a model. The owner opens the pull request from the
printed link. Git uses the owner's own credentials on this computer.
"""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'src'))
from factory_state.scope import canonical
from factory_runtime.worker import digest

ATTEMPT = re.compile(r'[a-z0-9][a-z0-9-]{0,62}')
REPOSITORY = 'timbrydges/bonus-library'


def _path(path):
    pure = PurePosixPath(path)
    if (type(path) is not str or not path or '\\' in path or ':' in path or pure.is_absolute()
            or any(part in ('', '.', '..', '.git') for part in path.split('/'))):
        raise ValueError('approved change has an unsafe path')
    return path


def verify_artifact(raw, *, expected_artifact_digest=None):
    """Return the approved packet after checking every binding; raise otherwise."""
    if expected_artifact_digest is not None and digest(raw) != expected_artifact_digest:
        raise ValueError('attempt artifact differs from the recorded run result')
    artifact = json.loads(raw)
    result, decision = artifact.get('result', {}), artifact.get('review_decision', {})
    packet = dict(artifact.get('review_packet') or {})
    review_digest = packet.pop('review_input_digest', None)
    if (artifact.get('kind') != 'development_attempt_v1'
            or result.get('status') != 'REVIEW_ACCEPTED' or decision.get('verdict') != 'APPROVE'
            or artifact.get('release_authorized') is not False):
        raise ValueError('attempt was not approved by the reviewer')
    if (review_digest != digest(canonical(packet)) or decision.get('review_input_digest') != review_digest
            or result.get('review_input_digest') != review_digest
            or result.get('review_decision_digest') != digest(canonical(decision))):
        raise ValueError('review packet or decision does not match its digests')
    proposal = artifact.get('proposal')
    if packet.get('candidate_decision_digest') != digest(canonical(proposal)):
        raise ValueError('approved packet does not bind the final proposal')
    if (packet.get('repository') != REPOSITORY
            or not re.fullmatch(r'[0-9a-f]{40}', str(packet.get('target_commit')))):
        raise ValueError('approved packet names an unexpected repository or commit')
    changes = packet.get('changes')
    if type(changes) is not list or not 1 <= len(changes) <= 50:
        raise ValueError('approved packet has no bounded changes')
    seen = set()
    for change in changes:
        path = _path(change.get('path'))
        if (path in seen or type(change.get('after')) is not str
                or change.get('before') is not None and type(change['before']) is not str):
            raise ValueError('approved change is malformed')
        seen.add(path)
    packet['review_input_digest'] = review_digest
    return packet


class Git:
    def __init__(self, directory):
        self.directory = directory

    def __call__(self, *args, capture=False):
        return subprocess.run(['git', '-C', str(self.directory), '-c', 'core.hooksPath=' + str(Path(self.directory)/'.no-hooks'),
                               '-c', 'core.autocrlf=false', *args], check=True, text=True,
                              capture_output=capture, timeout=300).stdout


def publish(*, attempt_dir, attempt_id, results_file=None, workdir, git_factory=Git, out=print):
    if not ATTEMPT.fullmatch(attempt_id):
        raise ValueError('exact attempt id required')
    raw = (Path(attempt_dir)/'attempt.json').read_bytes()
    expected = None
    if results_file is not None and Path(results_file).is_file():
        summary = json.loads(Path(results_file).read_text(encoding='utf-8'))
        expected = summary.get('outcome', {}).get('result', {}).get('artifact_digest')
        if summary.get('outcome', {}).get('status') != 'TICK_COMPLETED':
            raise ValueError('recorded run did not complete with an approval')
    packet = verify_artifact(raw, expected_artifact_digest=expected)
    branch = f'factory/{attempt_id}'
    clone = Path(workdir)/'bonus-library'
    git = git_factory(Path(workdir))
    git('clone', '--quiet', '--no-checkout', f'https://github.com/{REPOSITORY}.git', str(clone))
    git = git_factory(clone)
    if git('ls-remote', '--heads', 'origin', branch, capture=True).strip():
        raise ValueError(f'branch {branch} already exists; nothing was pushed')
    git('checkout', '--quiet', '-b', branch, packet['target_commit'])
    if git('rev-parse', 'HEAD', capture=True).strip() != packet['target_commit']:
        raise ValueError('clone is not at the approved target commit')
    for change in packet['changes']:
        target = clone/change['path']
        current = target.read_bytes().decode('utf-8') if target.is_file() else None
        if current != change['before']:
            raise ValueError(f"{change['path']} differs from what the reviewer saw; nothing was pushed")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(change['after'].encode('utf-8'))
        git('add', '--', change['path'])
    message = (f"{packet['specification'].get('objective', 'Factory change')}\n\n"
               f"Factory attempt {attempt_id}; reviewer verdict APPROVE.\n"
               f"Artifact: {digest(raw)}\nReview input: {packet['review_input_digest']}\n"
               f"Not merged or deployed by the Factory.")
    git('commit', '--quiet', '-m', message)
    git('push', '--quiet', 'origin', f'HEAD:refs/heads/{branch}')
    url = f'https://github.com/{REPOSITORY}/compare/{packet["target_commit"][:12]}...{branch}?expand=1'
    out(f'Pushed branch {branch} with {len(packet["changes"])} approved file(s).')
    out(f'Open the pull request here (review it, then decide whether to merge): {url}')
    return {'status': 'PUSHED', 'branch': branch, 'url': url, 'artifact_digest': digest(raw)}


def main(argv=None, git_factory=Git):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--owner-authorized', action='store_true')
    parser.add_argument('--attempt-id', required=True)
    parser.add_argument('--runner-root', default=r'C:\FactoryRunner')
    args = parser.parse_args(argv)
    if not args.owner_authorized:
        parser.error('explicit owner authorization required')
    root = Path(args.runner_root)
    with tempfile.TemporaryDirectory(prefix='factory-publish-') as workdir:
        publish(attempt_dir=root/'dev-attempts'/args.attempt_id, attempt_id=args.attempt_id,
                results_file=root/'dev-results'/f'{args.attempt_id}.json', workdir=workdir,
                git_factory=git_factory)
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except SystemExit:
        raise
    except Exception as error:
        print(f'STOPPED; nothing further was done: {type(error).__name__}: {str(error)[:300]}')
        raise SystemExit(1)
