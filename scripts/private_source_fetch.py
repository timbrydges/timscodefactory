"""Owner-run single private-source fetch. Disabled unless --fetch-once is given.

Prints only status metadata: never a token, JWT, key path contents or file data.
Each --attempt-name can be used once; a stopped attempt is never retried.
"""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'src'))
from factory_runtime.private_source import SourceBinding, snapshot_manifest_digest
from factory_runtime import private_source_composition as composition


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fetch-once', action='store_true')
    parser.add_argument('--owner-authorized', action='store_true')
    parser.add_argument('--config', type=Path)
    parser.add_argument('--config-sha256')
    parser.add_argument('--commit')
    parser.add_argument('--manifest')
    parser.add_argument('--attempt-name')
    args = parser.parse_args(argv)
    if not args.fetch_once:
        print(json.dumps({'status': 'DISABLED', 'source_requests': 0}))
        return 0
    if (not args.owner_authorized or None in (args.config, args.config_sha256, args.commit,
                                              args.manifest, args.attempt_name)):
        parser.error('owner authorization, pinned configuration, commit, manifest and attempt name required')
    config = composition.read_private_source_configuration(
        args.config, args.config_sha256, owner_authorized=True)
    binding = SourceBinding(config.repository, config.repository_id, args.commit, args.manifest)
    snapshot = composition.acquire_private_source(
        config, binding, args.attempt_name, clock=lambda: datetime.now(timezone.utc),
        enabled=True, owner_authorized=True)
    print(json.dumps({'status': 'VERIFIED', 'repository': snapshot.repository,
                      'commit': snapshot.commit, 'files': len(snapshot.files),
                      'bytes': sum(len(f.content) for f in snapshot.files),
                      'manifest': snapshot_manifest_digest(snapshot),
                      'receipt': str(config.attempt_parent/args.attempt_name/'source-fetch.json')}))
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except SystemExit:
        raise
    except BaseException as error:
        # Type only: messages could carry paths or remote text. Inspect the receipt.
        print(json.dumps({'status': 'STOPPED', 'error_type': type(error).__name__,
                          'retry': 'never; inspect receipt and report to owner'}))
        raise SystemExit(1)
