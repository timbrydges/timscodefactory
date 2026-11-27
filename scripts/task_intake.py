"""Draft a task from an idea, or approve a drafted task. No network, no model calls.

  python scripts/task_intake.py draft --idea idea.json
      Writes factory/intake/<task_id>.json as PENDING_APPROVAL and prints the
      exact approval phrase. Review the generated contract and acceptance tests.
  python scripts/task_intake.py approve --task-id <task_id> --phrase "<phrase>" --owner-authorized
      Only the owner's exact phrase moves it to APPROVED and writes
      factory/projects/<task_id>/task.json, which the build loop can then prepare.
"""
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from factory_runtime import task_intake  # noqa: E402

INTAKE = ROOT / 'factory' / 'intake'
PROJECTS = ROOT / 'factory' / 'projects'


def draft(idea_path, intake=INTAKE):
    record = task_intake.draft(json.loads(Path(idea_path).read_bytes()))
    Path(intake).mkdir(exist_ok=True)
    path = Path(intake) / f"{record['task']['task_id']}.json"
    with path.open('x') as handle:
        handle.write(json.dumps(record, indent=2, sort_keys=True) + '\n')
    return {'status': record['status'], 'intake': str(path),
            'approval_phrase': task_intake.approval_phrase(record)}


def approve(task_id, phrase, intake=INTAKE, projects=PROJECTS):
    if not task_intake.TASK_ID.fullmatch(task_id):
        raise ValueError('task id required')
    path = Path(intake) / f'{task_id}.json'
    record = task_intake.approve(json.loads(path.read_bytes()), phrase=phrase)
    folder = task_intake.write_approved(record, projects)
    path.write_text(json.dumps(record, indent=2, sort_keys=True) + '\n')
    return {'status': record['status'], 'task': str(folder / 'task.json')}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest='command', required=True)
    d = sub.add_parser('draft'); d.add_argument('--idea', required=True)
    a = sub.add_parser('approve')
    a.add_argument('--task-id', required=True); a.add_argument('--phrase', required=True)
    a.add_argument('--owner-authorized', action='store_true')
    args = parser.parse_args(argv)
    if args.command == 'draft':
        print(json.dumps(draft(args.idea)))
    else:
        if not args.owner_authorized:
            parser.error('explicit owner authorization required')
        print(json.dumps(approve(args.task_id, args.phrase)))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
