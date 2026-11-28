"""Unattended build-loop runner: readiness checks and one gated scheduled run.

  python scripts/unattended_runner.py check [--runner-root DIR]
      Read-only. Reports every readiness item and the exact owner action for each
      one that is missing. Never reads a key's value, never calls a model.

  python scripts/unattended_runner.py run [--runner-root DIR]
      What a timer (Task Scheduler, cron, a container schedule) invokes. Does
      nothing unless the owner's activation record exists, is unexpired and
      names the task; then runs one non-interactive batch through
      run_owner_attempt.py within the record's daily budget. Keys come from the
      environment or, when the record says so, from AWS Secrets Manager; there
      is never a prompt. A lock file stops overlapping runs and a ledger keeps
      the daily total. Re-running is safe: a run that would exceed the day's
      budget, or one already in progress, exits without spending.

The activation record (``unattended-activation.json`` in the runner root) is
written only by the owner. Example:

  {"kind": "factory_unattended_activation_v1", "approved_by": "tim_brydges",
   "expires_at": "2026-12-05T00:00:00+00:00", "tasks": ["bonus-library-reading-time"],
   "max_usd_per_day": "4.00", "max_attempts_per_run": 3, "publish_approved": true,
   "input_price": "1.00", "output_price": "5.00",
   "reviewer_input_price": "4.00", "reviewer_output_price": "20.00",
   "key_source": "environment"}

It authorizes spending only up to its own limits and never merges or releases.
"""
import argparse
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))

ACTIVATION = 'unattended-activation.json'
LEDGER = 'unattended-ledger.json'
LOCK = 'unattended.lock'
OWNER = 'tim_brydges'
FIELDS = {'kind', 'approved_by', 'expires_at', 'tasks', 'max_usd_per_day', 'max_attempts_per_run',
          'publish_approved', 'input_price', 'output_price', 'key_source'}
OPTIONAL = {'reviewer_input_price', 'reviewer_output_price', 'qa_input_price', 'qa_output_price'}
KEY_SOURCES = {'environment', 'aws-secrets-manager'}
SECRETS = {'FACTORY_OPENAI_API_KEY': 'tims-software-factory/provider/openai/acceptance',
           'FACTORY_ANTHROPIC_API_KEY': 'tims-software-factory/provider/anthropic/review',
           'FACTORY_GOOGLE_API_KEY': 'tims-software-factory/provider/google/qa'}
TASK = re.compile(r'bonus-library-[a-z0-9-]{1,60}')


def _money(value, low, high):
    try:
        amount = Decimal(value)
    except (InvalidOperation, TypeError):
        raise ValueError('decimal amount required') from None
    if not amount.is_finite() or not low < amount <= high:
        raise ValueError('amount outside its bounds')
    return amount


def read_activation(root, now):
    path = Path(root) / ACTIVATION
    if not path.is_file():
        return None
    record = json.loads(path.read_bytes())
    if type(record) is not dict or not FIELDS <= set(record) <= FIELDS | OPTIONAL:
        raise ValueError('activation record has unexpected fields')
    if record['kind'] != 'factory_unattended_activation_v1' or record['approved_by'] != OWNER:
        raise ValueError('activation must be the owner\'s record')
    expires = datetime.fromisoformat(record['expires_at'])
    if expires.tzinfo is None or not now < expires:
        raise ValueError('activation record has expired')
    if (expires - now).days > 31:
        raise ValueError('activation may last at most 31 days')
    tasks = record['tasks']
    if type(tasks) is not list or not 1 <= len(tasks) <= 20 or any(type(t) is not str or not TASK.fullmatch(t) for t in tasks):
        raise ValueError('activation must name one to twenty tasks')
    _money(record['max_usd_per_day'], Decimal(0), Decimal(20))
    if type(record['max_attempts_per_run']) is not int or not 1 <= record['max_attempts_per_run'] <= 5:
        raise ValueError('one to five attempts per run')
    if type(record['publish_approved']) is not bool or record['key_source'] not in KEY_SOURCES:
        raise ValueError('publish flag and a known key source required')
    for key in ('input_price', 'output_price', 'reviewer_input_price', 'reviewer_output_price',
                'qa_input_price', 'qa_output_price'):
        if key in record:
            _money(record[key], Decimal(0), Decimal(1000))
    return record


def spent_today(root, now):
    path = Path(root) / LEDGER
    ledger = json.loads(path.read_text()) if path.is_file() else {}
    return Decimal(ledger.get(now.date().isoformat(), '0')), ledger


def record_spend(root, now, amount):
    total, ledger = spent_today(root, now)
    ledger[now.date().isoformat()] = str(total + Decimal(amount))
    temporary = Path(root) / (LEDGER + '.tmp')
    temporary.write_text(json.dumps(ledger, indent=2, sort_keys=True))
    os.replace(temporary, Path(root) / LEDGER)


def keys_from_secrets_manager(names, client=None):
    """Read each exact secret's current value into memory only; never logged or written."""
    if client is None:
        import boto3
        from factory_runtime.provider_credentials import secrets_manager_client
        client = secrets_manager_client(boto3.Session())
    keys = {}
    for variable in names:
        value = client.get_secret_value(SecretId=SECRETS[variable], VersionStage='AWSCURRENT').get('SecretString')
        if type(value) is not str or len(value.strip()) < 16:
            raise ValueError(f'secret for {variable} is missing or malformed')
        keys[variable] = value.strip()
    return keys


def _spec(task):
    path = ROOT / 'factory' / 'projects' / task / 'task.json'
    return json.loads(path.read_bytes()) if path.is_file() else {}


def needs_reviewer(task):
    return 'reviewer_model' in _spec(task)


def required_keys(tasks):
    specs = [_spec(t) for t in tasks]
    return ['FACTORY_OPENAI_API_KEY',
            *(['FACTORY_ANTHROPIC_API_KEY'] if any('reviewer_model' in s for s in specs) else []),
            *(['FACTORY_GOOGLE_API_KEY'] if any('qa_model' in s for s in specs) else [])]


def check(root, *, env=None, now=None, which=shutil.which, run=subprocess.run):
    """Read-only readiness report; each blocked item names the owner action."""
    env = os.environ if env is None else env
    now = now or datetime.now(timezone.utc)
    root = Path(root)
    items = []
    def item(name, ok, action=''):
        items.append({'item': name, 'ready': bool(ok), **({} if ok else {'owner_action': action})})
    item('runner root exists', root.is_dir(), f'create {root} or set FACTORY_RUNNER_ROOT')
    item('private source config', (root / 'bonus-source-fetch.json').is_file(),
         'copy bonus-source-fetch.json into the runner root')
    item('docker available', which('docker') is not None, 'install Docker on the unattended host')
    dirty = run(['git', '-C', str(ROOT), 'status', '--porcelain'], capture_output=True, text=True).stdout
    item('clean Factory checkout', not dirty.strip(), 'reset local changes in the Factory checkout')
    try:
        activation = read_activation(root, now)
        problem = None
    except (ValueError, KeyError, TypeError) as error:
        activation, problem = None, str(error)
    item('owner activation record', activation is not None,
         problem or f'write {ACTIVATION} in the runner root (see this script\'s help); it is the switch')
    tasks = activation['tasks'] if activation else []
    for task in tasks:
        item(f'task {task} exists', (ROOT / 'factory' / 'projects' / task / 'task.json').is_file(),
             'approve the task with scripts/task_intake.py first')
    source = activation['key_source'] if activation else 'environment'
    for variable in required_keys(tasks):
        if source == 'environment':
            item(f'{variable} available without a prompt', bool(env.get(variable, '').strip()),
                 f'set {variable} for the scheduled task, or use key_source aws-secrets-manager')
        else:
            # Presence is verified at run time; this check reads no secret.
            items.append({'item': f'{variable} from AWS secret {SECRETS[variable]}', 'ready': True,
                          'note': f'create {SECRETS[variable]} and grant the host read access'})
    ready = all(i['ready'] for i in items)
    return {'status': 'READY' if ready else 'BLOCKED', 'items': items, 'model_calls': 0, 'secrets_read': 0}


def run_once(root, *, env=None, now=None, invoke=None, client=None, out=print):
    """One scheduled run under the owner's activation record; safe to repeat."""
    env = dict(os.environ if env is None else env)
    now = now or datetime.now(timezone.utc)
    root = Path(root)
    activation = read_activation(root, now)
    if activation is None:
        return {'status': 'DISABLED', 'reason': f'no {ACTIVATION}; nothing was run', 'model_calls': 0}
    lock = root / LOCK
    try:
        handle = lock.open('x')
    except FileExistsError:
        return {'status': 'ALREADY_RUNNING', 'reason': f'{LOCK} exists; remove it only after checking no run is active'}
    try:
        handle.write(now.isoformat()); handle.close()
        spent, _ = spent_today(root, now)
        remaining = Decimal(activation['max_usd_per_day']) - spent
        sys.path.insert(0, str(ROOT / 'scripts'))
        import prepare_development_attempt as prepare
        results = []
        for task in activation['tasks']:
            spec = json.loads(prepare.task_path(task).read_bytes())
            cap = prepare.attempt_cap(spec, 2)
            if remaining < cap:
                results.append({'task': task, 'status': 'BUDGET_REACHED'})
                break
            keys = required_keys([task])
            if activation['key_source'] == 'aws-secrets-manager':
                env.update(keys_from_secrets_manager(keys, client))
            missing = [k for k in keys if not env.get(k, '').strip()]
            if missing:
                results.append({'task': task, 'status': 'BLOCKED', 'reason': f'{missing[0]} is not available'})
                break
            budget = min(remaining, cap * activation['max_attempts_per_run'])
            args = ['--owner-authorized', '--non-interactive', '--runner-root', str(root), '--task', task,
                    '--input-price', activation['input_price'], '--output-price', activation['output_price'],
                    '--max-attempts', str(activation['max_attempts_per_run']), '--max-total-usd', str(budget)]
            if 'reviewer_model' in spec:
                args += ['--reviewer-input-price', activation['reviewer_input_price'],
                         '--reviewer-output-price', activation['reviewer_output_price']]
            if 'qa_model' in spec:
                args += ['--qa-input-price', activation['qa_input_price'],
                         '--qa-output-price', activation['qa_output_price']]
            if activation['publish_approved']:
                args.append('--publish-approved')
            batch = (invoke or _invoke)(args, env)
            cost = Decimal(batch.get('spent_usd', str(budget)))  # Unknown outcome counts at its limit.
            record_spend(root, now, cost)
            remaining -= cost
            results.append({'task': task, 'status': batch.get('status', 'UNKNOWN'), 'spent_usd': str(cost)})
            if not str(batch.get('status', '')).startswith('APPROVED'):
                break  # Stop the run on any non-approved outcome; the owner reviews it.
        return {'status': 'RAN', 'results': results, 'spent_today_usd': str(spent_today(root, now)[0])}
    finally:
        env.clear()
        lock.unlink(missing_ok=True)


def _invoke(args, env):
    """Run one non-interactive batch and read its batch summary."""
    root = Path(args[args.index('--runner-root') + 1])
    before = set((root / 'dev-results').glob('batch-*.json')) if (root / 'dev-results').is_dir() else set()
    subprocess.run([sys.executable, str(ROOT / 'scripts' / 'run_owner_attempt.py'), *args],
                   env=env, timeout=4 * 3600)
    after = sorted(set((root / 'dev-results').glob('batch-*.json')) - before)
    return json.loads(after[-1].read_text()) if after else {'status': 'UNKNOWN_OUTPUT'}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('command', choices=('check', 'run'))
    parser.add_argument('--runner-root', default=os.environ.get('FACTORY_RUNNER_ROOT', r'C:\FactoryRunner'))
    args = parser.parse_args(argv)
    result = check(args.runner_root) if args.command == 'check' else run_once(args.runner_root)
    print(json.dumps(result, indent=2))
    return 0 if result['status'] in ('READY', 'RAN', 'DISABLED') else 1


if __name__ == '__main__':
    raise SystemExit(main())
