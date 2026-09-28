"""Apply only the three reviewed disabled EventBridge Scheduler resources."""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

try:
    from .prepare_role_deployment import ACCOUNT, REGION, ROOT, aws
    from .verify_disabled_autonomy_schedule import NAME, TARGET, ROLE, INPUT, main as verify_schedule
except ImportError:
    from prepare_role_deployment import ACCOUNT, REGION, ROOT, aws
    from verify_disabled_autonomy_schedule import NAME, TARGET, ROLE, INPUT, main as verify_schedule


DIR = ROOT / 'infra/aws'
BUCKET = f'tims-software-factory-tfstate-{ACCOUNT}-{REGION}'
EXPECTED = {
    'aws_iam_role.autonomy_scheduler[0]',
    'aws_iam_role_policy.autonomy_scheduler_invoke[0]',
    'aws_scheduler_schedule.autonomy_acceptance[0]',
}
SCHEDULE = 'aws_scheduler_schedule.autonomy_acceptance[0]'
SCHEDULE_ONLY = {SCHEDULE}
ROLE_ADDRESS = 'aws_iam_role.autonomy_scheduler[0]'
ROLE_AND_SCHEDULE = {ROLE_ADDRESS, SCHEDULE}
GROUP_SOURCE = f'arn:aws:scheduler:{REGION}:{ACCOUNT}:schedule-group/default'
OLD_SCHEDULE_SOURCE = f'arn:aws:scheduler:{REGION}:{ACCOUNT}:schedule/default/{NAME}'


def trust_matches(document, source_arn):
    if isinstance(document, str):
        document = json.loads(document)
    if not isinstance(document, dict) or document.get('Version') != '2012-10-17':
        return False
    statements = document.get('Statement')
    statement = statements[0] if isinstance(statements, list) and len(statements) == 1 else statements
    return (isinstance(statement, dict) and
            statement.get('Action') in ('sts:AssumeRole', ['sts:AssumeRole']) and
            {k: v for k, v in statement.items() if k != 'Action'} == {
                'Effect': 'Allow',
                'Principal': {'Service': 'scheduler.amazonaws.com'},
                'Condition': {'StringEquals': {'aws:SourceAccount': ACCOUNT},
                              'ArnEquals': {'aws:SourceArn': source_arn}},
            })


def source():
    """Terraform creates its local provider lock file during init."""
    status = subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT,
                                     text=True).splitlines()
    if any(line != '?? infra/aws/.terraform.lock.hcl' for line in status):
        raise RuntimeError('clean checkout required, apart from Terraform provider lock')
    return subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT,
                                   text=True).strip()


def terraform(*args, json_output=False):
    result = subprocess.run(['terraform', '-chdir=' + str(DIR), *args],
                            capture_output=True, text=True, timeout=900,
                            env={**os.environ, 'AWS_MAX_ATTEMPTS': '1'})
    if result.returncode:
        raise RuntimeError('terraform ' + args[0] + ' failed: ' + result.stderr.strip())
    return json.loads(result.stdout) if json_output else result.stdout


def terraform_vars():
    state = terraform('state', 'list')
    variables = ['-var=aws_region=' + REGION,
                 '-var=deploy_disabled_autonomy_schedule=true']
    if 'aws_iam_openid_connect_provider.github[0]' not in state.splitlines():
        oidc = f'arn:aws:iam::{ACCOUNT}:oidc-provider/token.actions.githubusercontent.com'
        provider = aws('iam', 'get-open-id-connect-provider',
                       '--open-id-connect-provider-arn', oidc)
        if provider.get('Url') != 'token.actions.githubusercontent.com' or \
                'sts.amazonaws.com' not in provider.get('ClientIDList', []):
            raise RuntimeError('existing GitHub OIDC provider differs')
        variables.append('-var=existing_github_oidc_provider_arn=' + oidc)
    return variables


def assert_controller():
    stack = aws('cloudformation', 'describe-stacks',
                '--stack-name', 'tims-factory-autonomy-controller-disabled')['Stacks'][0]
    if stack.get('StackStatus') != 'CREATE_COMPLETE':
        raise RuntimeError('disabled controller target has not completed deployment')
    outputs = {x['OutputKey']: x['OutputValue'] for x in stack['Outputs']}
    version = outputs.get('ControllerVersionArn', '')
    if (outputs.get('AcceptanceAliasArn') != TARGET or
            not version.startswith(TARGET.removesuffix(':acceptance') + ':') or
            not version.rsplit(':', 1)[1].isdigit()):
        raise RuntimeError('controller alias or version differs')
    alias = aws('lambda', 'get-alias', '--function-name', TARGET.removesuffix(':acceptance'),
                '--name', 'acceptance')
    config = aws('lambda', 'get-function-configuration', '--function-name', version)
    if (alias.get('AliasArn') != TARGET or
            alias.get('FunctionVersion') != version.rsplit(':', 1)[1] or
            alias.get('RoutingConfig', {}).get('AdditionalVersionWeights') or
            config.get('Environment', {}).get('Variables') !=
                {'FACTORY_AUTONOMY_CONTROLLER_ENABLED': 'false'} or
            config.get('Role') != f'arn:aws:iam::{ACCOUNT}:role/tims-software-factory-autonomy-controller-disabled'):
        raise RuntimeError('controller is not the exact disabled alias')


def validate_plan(plan):
    changes = [r for r in plan.get('resource_changes', [])
               if r.get('mode', 'managed') == 'managed' and r['change']['actions'] != ['no-op']]
    addresses = {r['address'] for r in changes}
    if (len(changes) != len(addresses) or
            addresses not in (EXPECTED, SCHEDULE_ONLY, ROLE_AND_SCHEDULE) or
            any(r['change']['actions'] != (['update'] if r['address'] == ROLE_ADDRESS and
                 addresses == ROLE_AND_SCHEDULE else ['create']) for r in changes)):
        raise RuntimeError('Terraform plan must create only the disabled schedule resources')
    if ROLE_ADDRESS in addresses:
        role_change = next(r['change'] for r in changes if r['address'] == ROLE_ADDRESS)
        after, before = role_change.get('after', {}), role_change.get('before', {})
        if (role_change.get('replace_paths') or
                not trust_matches(after.get('assume_role_policy'), GROUP_SOURCE) or
                (addresses == ROLE_AND_SCHEDULE and (
                    {k: v for k, v in after.items() if k != 'assume_role_policy'} !=
                    {k: v for k, v in before.items() if k != 'assume_role_policy'} or
                    not trust_matches(before.get('assume_role_policy'), OLD_SCHEDULE_SOURCE)))):
            raise RuntimeError('scheduler role plan must change only exact group trust in place')
    schedule = next(r['change']['after'] for r in changes
                    if r['address'] == SCHEDULE)
    windows = schedule.get('flexible_time_window', [])
    targets = schedule.get('target', [])
    if len(windows) != 1 or len(targets) != 1:
        raise RuntimeError('planned schedule requires one disabled window and target')
    window, target = windows[0], targets[0]
    retries = target.get('retry_policy', [])
    if len(retries) != 1:
        raise RuntimeError('planned schedule requires one no-retry policy')
    retry = retries[0]
    if (schedule.get('name') != NAME or schedule.get('state') != 'DISABLED' or
            schedule.get('schedule_expression') != 'rate(15 minutes)' or
            schedule.get('schedule_expression_timezone') != 'UTC' or
            window.get('mode') != 'OFF' or
            window.get('maximum_window_in_minutes') not in (None, 0) or
            target.get('arn') != TARGET or
            json.loads(target.get('input', 'null')) != INPUT or
            retry.get('maximum_retry_attempts') != 0 or
            retry.get('maximum_event_age_in_seconds') != 60):
        raise RuntimeError('planned schedule does not match disabled acceptance binding')
    return addresses


def assert_existing_iam(allow_schedule_in_state=False, source_arn=GROUP_SOURCE):
    existing = set(terraform('state', 'list').splitlines())
    if not (EXPECTED - SCHEDULE_ONLY).issubset(existing) or \
            (SCHEDULE in existing and not allow_schedule_in_state):
        raise RuntimeError('existing scheduler IAM is not the expected Terraform state')
    assert_scheduler_iam(source_arn)


def checked_plan(path, status, allow_schedule_in_state=False):
    metadata = json.loads(Path(str(path) + '.json').read_text(encoding='utf-8'))
    raw = Path(path).read_bytes()
    if (metadata.get('status') != status or metadata.get('source_commit') != source() or
            metadata.get('plan_sha256') != hashlib.sha256(raw).hexdigest() or
            metadata.get('resources') not in (sorted(EXPECTED), sorted(SCHEDULE_ONLY),
                                              sorted(ROLE_AND_SCHEDULE)) or
            metadata.get('model_calls_authorized') != 0 or
            aws('sts', 'get-caller-identity').get('Account') != ACCOUNT):
        raise RuntimeError('disabled schedule plan/source/account changed')
    planned = validate_plan(terraform('show', '-json', str(Path(path).resolve()), json_output=True))
    if metadata['resources'] != sorted(planned):
        raise RuntimeError('disabled schedule plan resources changed')
    if planned in (SCHEDULE_ONLY, ROLE_AND_SCHEDULE):
        assert_existing_iam(allow_schedule_in_state,
                            GROUP_SOURCE if allow_schedule_in_state or planned == SCHEDULE_ONLY
                            else OLD_SCHEDULE_SOURCE)
    assert_controller()
    return metadata


def prepare(path):
    commit = source()
    if aws('sts', 'get-caller-identity').get('Account') != ACCOUNT:
        raise RuntimeError('wrong AWS account')
    assert_controller()
    terraform('init', '-reconfigure', '-backend-config=bucket=' + BUCKET,
              '-backend-config=key=timscodefactory/terraform.tfstate',
              '-backend-config=region=' + REGION, '-backend-config=encrypt=true',
              '-backend-config=use_lockfile=true')
    terraform('validate')
    variables = terraform_vars()
    path = Path(path).resolve()
    terraform('plan', '-input=false', '-out=' + str(path), *variables)
    planned = validate_plan(terraform('show', '-json', str(path), json_output=True))
    if planned in (SCHEDULE_ONLY, ROLE_AND_SCHEDULE):
        assert_existing_iam(source_arn=GROUP_SOURCE if planned == SCHEDULE_ONLY
                            else OLD_SCHEDULE_SOURCE)
    metadata = {'status': 'PREPARED_NOT_EXECUTED', 'source_commit': commit,
                'plan_sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
                'resources': sorted(planned), 'model_calls_authorized': 0}
    Path(str(path) + '.json').write_text(json.dumps(metadata, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(metadata))


def execute(path):
    metadata = checked_plan(path, 'PREPARED_NOT_EXECUTED')
    terraform('apply', '-input=false', '-auto-approve', str(Path(path).resolve()))
    metadata['status'] = 'DEPLOYED_PENDING_CANARY'
    Path(str(path) + '.json').write_text(json.dumps(metadata, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'status': metadata['status'], 'source_commit': metadata['source_commit']}))


def reconcile(path):
    metadata = checked_plan(path, 'PREPARED_NOT_EXECUTED', allow_schedule_in_state=True)
    # An interrupted Terraform apply must be inspected, never applied again.
    state = set(terraform('state', 'list').splitlines())
    if not EXPECTED.issubset(state):
        raise RuntimeError('disabled schedule resources are not all in Terraform state')
    verify_schedule()
    metadata['status'] = 'DEPLOYED_PENDING_CANARY'
    Path(str(path) + '.json').write_text(json.dumps(metadata, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'status': metadata['status'], 'reconciled': True}))


def verify(path):
    metadata = json.loads(Path(str(path) + '.json').read_text(encoding='utf-8'))
    if (metadata.get('status') != 'DEPLOYED_PENDING_CANARY' or
            metadata.get('source_commit') != source() or
            metadata.get('resources') not in (sorted(EXPECTED), sorted(SCHEDULE_ONLY),
                                              sorted(ROLE_AND_SCHEDULE)) or
            metadata.get('model_calls_authorized') != 0 or
            metadata.get('plan_sha256') != hashlib.sha256(Path(path).read_bytes()).hexdigest() or
            aws('sts', 'get-caller-identity').get('Account') != ACCOUNT):
        raise RuntimeError('schedule verification differs from prepared account/source')
    assert_controller()
    verify_schedule()
    if not EXPECTED.issubset(set(terraform('state', 'list').splitlines())):
        raise RuntimeError('verified schedule resources are not all in Terraform state')
    assert_scheduler_iam()
    print(json.dumps({'status': 'DISABLED_ACCEPTANCE_SCHEDULE_VERIFIED',
                      'schedule': NAME, 'state': 'DISABLED',
                      'source_commit': metadata['source_commit'], 'model_calls': 0}))


def assert_scheduler_iam(source_arn=GROUP_SOURCE):
    policy = aws('iam', 'get-role-policy', '--role-name', ROLE.rsplit('/', 1)[1],
                 '--policy-name', 'tims-software-factory-autonomy-scheduler-invoke')
    statements = policy['PolicyDocument']['Statement']
    statement = statements[0] if isinstance(statements, list) and len(statements) == 1 else {}
    if (statement.get('Sid') != 'InvokeExactAcceptanceControllerAlias' or
            statement.get('Effect') != 'Allow' or
            statement.get('Action') not in ('lambda:InvokeFunction', ['lambda:InvokeFunction']) or
            statement.get('Resource') not in (TARGET, [TARGET]) or
            set(statement) != {'Sid', 'Effect', 'Action', 'Resource'}):
        raise RuntimeError('scheduler role has unexpected invoke rights')
    role = aws('iam', 'get-role', '--role-name', ROLE.rsplit('/', 1)[1])['Role']
    if role.get('Arn') != ROLE or not trust_matches(
            role.get('AssumeRolePolicyDocument'), source_arn):
        raise RuntimeError('scheduler role trust differs from exact schedule')
    attached = aws('iam', 'list-attached-role-policies', '--role-name', ROLE.rsplit('/', 1)[1])
    inline = aws('iam', 'list-role-policies', '--role-name', ROLE.rsplit('/', 1)[1])
    if attached.get('AttachedPolicies') != [] or inline.get('PolicyNames') != [
            'tims-software-factory-autonomy-scheduler-invoke']:
        raise RuntimeError('scheduler role has additional policies')


if __name__ == '__main__':
    if len(sys.argv) != 3 or sys.argv[1] not in {'prepare', 'execute', 'reconcile', 'verify'}:
        raise SystemExit('use prepare PLAN | execute PLAN | reconcile PLAN | verify PLAN')
    {'prepare': prepare, 'execute': execute, 'reconcile': reconcile,
     'verify': verify}[sys.argv[1]](sys.argv[2])
