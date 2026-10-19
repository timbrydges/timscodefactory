"""Offline entrypoint: pin source and sandbox without credentials or execution."""
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from factory_runtime.docker_sandbox import DockerSandboxPolicy
from factory_runtime.repository_snapshot import read_repository_snapshot
from factory_runtime.worker import digest


def inspect(repository_path, contract_path, image_ref):
    raw = Path(contract_path).read_bytes()
    if len(raw) > 65536:
        raise ValueError('contract exceeds limit')
    spec = json.loads(raw)
    if any(spec.get(k) is not False for k in ('execution_authorized',
            'spending_authorized', 'signing_authorized', 'release_authorized')):
        raise ValueError('inert contract required')
    snapshot = read_repository_snapshot(repository_path,
        repository=spec['repository'], commit=spec['target_commit'])
    policy = DockerSandboxPolicy(image_ref=image_ref)
    return {'status': 'OFFLINE_PREFLIGHT_ONLY', 'contract_digest': digest(raw),
        'repository': snapshot.repository, 'target_commit': snapshot.commit,
        'source_file_count': len(snapshot.files), 'image_ref': image_ref,
        'environment_digest': policy.environment_digest,
        'credential_source': 'broker-injected FACTORY_OPENAI_API_KEY or exact AWSCURRENT secret',
        'credential_read': False, 'image_presence_verified': False,
        'enabled': False, 'live_ready': False,
        'remaining': ['trusted approval binding and executable live composition',
                      'credential issuer rotation and revocation qualification',
                      'fresh pricing and local image verification']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repository-path', required=True, type=Path)
    parser.add_argument('--contract', required=True, type=Path)
    parser.add_argument('--image-ref', required=True)
    args = parser.parse_args()
    print(json.dumps(inspect(args.repository_path, args.contract, args.image_ref), sort_keys=True))


if __name__ == '__main__':
    main()
