"""Operator-only local identity admission. No HTTP, token requests or execution."""
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'src'))
from factory_runtime.github_identity_bootstrap import open_ledger, read_configuration


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--owner-authorized', action='store_true')
    parser.add_argument('--action', choices=('initialize-paused', 'pause', 'resume'))
    parser.add_argument('--identity-config', type=Path)
    parser.add_argument('--identity-config-sha256')
    args = parser.parse_args(argv)
    if args.action is None:
        print(json.dumps({'status':'DISABLED', 'identity_requests':0}))
        return 0
    if not args.owner_authorized or args.identity_config is None or args.identity_config_sha256 is None:
        parser.error('operator authorization and hash-pinned identity configuration required')
    config = read_configuration(args.identity_config, args.identity_config_sha256,
                                owner_authorized=True)
    ledger = open_ledger(config, initialize=args.action == 'initialize-paused')
    if args.action in ('pause', 'resume'):
        ledger.pause(args.action == 'pause')
    print(json.dumps({'status':args.action.upper().replace('-', '_'), 'identity_requests':0}))
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        print(json.dumps({'status':'STOPPED', 'error_type':type(error).__name__}))
        raise SystemExit(1)
