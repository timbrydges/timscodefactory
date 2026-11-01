"""Operator-only local polling host. Disabled by default; installs no OS timer."""
import argparse
import asyncio
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
from functools import partial

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from development_attempt import execute
from factory_runtime.development_schedule import DevelopmentSchedule
from factory_runtime.development_schedule_host import ScheduledPacketHost, poll_schedule
from factory_runtime.github_identity_bootstrap import binding_from_configuration


def main(argv=None, *, credential_binding=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--enable',action='store_true')
    parser.add_argument('--owner-authorized',action='store_true')
    parser.add_argument('--action',choices=('initialize','admit','pause','resume','run'))
    parser.add_argument('--host-directory',type=Path)
    parser.add_argument('--repository-path',type=Path)
    parser.add_argument('--source-config',type=Path)
    parser.add_argument('--source-config-sha256')
    parser.add_argument('--packet',type=Path)
    parser.add_argument('--due-at')
    parser.add_argument('--max-ticks',type=int,default=1)
    parser.add_argument('--interval-seconds',type=int,default=60)
    parser.add_argument('--identity-config',type=Path)
    parser.add_argument('--identity-config-sha256')
    args=parser.parse_args(argv)
    if not args.enable:
        print(json.dumps({'status':'DISABLED','ticks':0}))
        return 0
    if not args.owner_authorized or args.host_directory is None or args.action is None:
        parser.error('explicit operator authorization, action and host directory required')
    base=args.host_directory
    if args.action=='initialize':
        base.mkdir(exist_ok=False)
        (base/'packets').mkdir()
        (base/'attempts').mkdir()
        DevelopmentSchedule(base/'schedule.db')
        print(json.dumps({'status':'INITIALIZED_PAUSED'}))
        return 0
    if not base.is_dir() or base.is_symlink() or not (base/'schedule.db').is_file():
        parser.error('initialized regular host directory required')
    schedule=DevelopmentSchedule(base/'schedule.db')
    if args.action in {'pause','resume'}:
        schedule.pause(args.action=='pause')
        print(json.dumps({'status':'PAUSED' if args.action=='pause' else 'RESUMED'}))
        return 0
    if ((args.repository_path is None) == (args.source_config is None)
            or (args.source_config is None) != (args.source_config_sha256 is None)):
        parser.error('exactly one operator source: --repository-path or a hash-pinned --source-config')
    if args.action == 'run' and (args.identity_config is not None or args.identity_config_sha256 is not None):
        if credential_binding is not None or args.identity_config is None or args.identity_config_sha256 is None:
            parser.error('one complete operator identity binding required')
        credential_binding = binding_from_configuration(args.identity_config, args.identity_config_sha256,
            clock=lambda:datetime.now(timezone.utc), owner_authorized=True, enabled=True)
    host=ScheduledPacketHost(packet_directory=base/'packets',
        attempt_directory=base/'attempts',repository_path=args.repository_path,
        source_config=args.source_config,source_config_sha256=args.source_config_sha256,
        execute=partial(execute, credential_binding=credential_binding),owner_authorized=True)
    if args.action=='admit':
        if args.packet is None or args.due_at is None:
            parser.error('exact packet and due time required')
        with args.packet.open('rb') as handle:
            raw=handle.read(262145)
        host.admit(schedule,raw,due_at=datetime.fromisoformat(args.due_at))
        print(json.dumps({'status':'ADMITTED_NO_DISPATCH'}))
        return 0
    result=asyncio.run(poll_schedule(schedule,host,clock=lambda:datetime.now(timezone.utc),
        enabled=True,max_ticks=args.max_ticks,interval_seconds=args.interval_seconds))
    print(json.dumps(result,sort_keys=True))
    return 1 if any(result.get('outcomes',{}).get(k,0) for k in ('NEEDS_RECONCILIATION','REJECTED','EXPIRED')) else 0


if __name__=='__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        print(json.dumps({'status':'STOPPED','error_type':type(error).__name__}))
        raise SystemExit(1)
