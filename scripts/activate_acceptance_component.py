"""Publish one guarded commissioning component; never invoke or enable a schedule.

The owner-approved commissioning window, two live signatures and an unused
budget are checked before each mutation. Broker, Builder, controller order is
enforced through immutable version/configuration pins. Uncertain execution is
read-only reconciled, never retried.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

from prepare_role_deployment import ACCOUNT, BUCKET, REGION, ROOT, aws, source
from prepare_acceptance_activation_bundle import build_activation_bundle
from stage_disabled_acceptance_config import COMPONENTS, assert_schedule, save, snapshot
from verify_acceptance_staging_scope import verify_live_scope
from factory_runtime.autonomy_contract import COMMISSIONING_GATES, COMMISSIONING_ID

VERSIONS = {'broker': 'BrokerVersion', 'builder': 'BuilderVersion', 'controller': 'ControllerVersion'}
PREFIXES = {'broker': 'factory-acceptance-broker-packages', 'builder': 'factory-role-packages',
            'controller': 'factory-autonomy-controller-packages'}


def sha(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def render(component, bundle, binding):
    if (component not in COMPONENTS or bundle.get('activation_id') != COMMISSIONING_ID or
            bundle.get('contract_blockers') != sorted(COMMISSIONING_GATES) or
            bundle.get('status') != 'PREPARED_DISABLED_NOT_DEPLOYED' or
            binding['activation_id'] != COMMISSIONING_ID):
        raise RuntimeError('only the exact owner-authorized commissioning exception may activate')
    baseline = json.loads((ROOT / COMPONENTS[component][1]).read_text())
    proposed = copy.deepcopy(baseline)
    resources = proposed['Resources']
    logical, flag = COMPONENTS[component][2], COMPONENTS[component][4]
    env = resources[logical]['Properties']['Environment']['Variables']
    updates = dict(bundle['environment_updates'][component])
    if updates.get(flag) != 'false':
        raise RuntimeError('activation must start from disabled preparation')
    updates[flag] = 'true'
    env.update(updates)
    # A changed Description forces an immutable version replacement, including
    # configuration-only changes. The Ref establishes function update ordering.
    resources[VERSIONS[component]]['Properties']['Description'] = 'commissioning-' + sha(updates)
    if component == 'builder':
        statements = resources['BuilderRole']['Properties']['Policies'][1]['Fn::If'][1]['PolicyDocument']['Statement']
        statement = next(s for s in statements if s['Sid'] == 'InvokePinnedCredentialFreeBroker')
        statement['Resource'] = binding['broker_version_arn']
    if component == 'controller':
        resources['ControllerRole']['Properties']['Policies'].append({
            'PolicyName': 'bounded-commissioning', 'PolicyDocument': bundle['controller_policy']})
        resources['AcceptanceNoRetries'] = {'Type': 'AWS::Lambda::EventInvokeConfig',
            'DependsOn': ['AcceptanceAlias'], 'Properties': {
                'FunctionName': {'Ref': 'ControllerFunction'}, 'Qualifier': 'acceptance',
                'MaximumRetryAttempts': 0, 'MaximumEventAgeInSeconds': 60}}
    return baseline, proposed


def normalize(value):
    if isinstance(value, list):
        items = [normalize(v) for v in value]
        if all(isinstance(v, str) for v in items):
            items.sort()
        return items[0] if len(items) == 1 else items
    if isinstance(value, dict):
        return {k: normalize(v) for k, v in value.items()}
    return value


def resolve(value, template, params):
    if isinstance(value, list):
        return [resolve(item, template, params) for item in value]
    if not isinstance(value, dict):
        return value
    if set(value) == {'Ref'}:
        ref = value['Ref']
        if ref == 'AWS::NoValue':
            return None
        if ref in params:
            return params[ref]
        return template['Resources'][ref]['Properties']['TableName']
    if set(value) == {'Fn::If'}:
        condition, yes, no = value['Fn::If']
        left, right = template['Conditions'][condition]['Fn::Equals']
        return resolve(yes if resolve(left, template, params) == right else no, template, params)
    if set(value) == {'Fn::GetAtt'}:
        resource, attribute = value['Fn::GetAtt']
        if resource != 'RoleExecutions' or attribute != 'Arn':
            raise RuntimeError('unsupported IAM reference')
        return f'arn:aws:dynamodb:{REGION}:{ACCOUNT}:table:' + template['Resources'][resource]['Properties']['TableName']
    return {key: resolve(item, template, params) for key, item in value.items()}


def verify_iam(component, template, params):
    logical = COMPONENTS[component][2]
    role_key = template['Resources'][logical]['Properties']['Role']['Fn::GetAtt'][0]
    role = template['Resources'][role_key]['Properties']
    name = role['RoleName']
    actual = aws('iam', 'get-role', '--role-name', name)['Role']
    if normalize(actual['AssumeRolePolicyDocument']) != normalize(role['AssumeRolePolicyDocument']) or actual.get('PermissionsBoundary'):
        raise RuntimeError('component role trust or permissions boundary drifted')
    policies = [p for p in resolve(role.get('Policies', []), template, params) if p is not None]
    if sorted(aws('iam', 'list-role-policies', '--role-name', name)['PolicyNames']) != sorted(p['PolicyName'] for p in policies):
        raise RuntimeError('component inline policy set drifted')
    for policy in policies:
        if normalize(aws('iam', 'get-role-policy', '--role-name', name, '--policy-name', policy['PolicyName'])['PolicyDocument']) != normalize(policy['PolicyDocument']):
            raise RuntimeError('component inline policy document drifted')
    expected = resolve(role.get('ManagedPolicyArns', []), template, params) or []
    attached = aws('iam', 'list-attached-role-policies', '--role-name', name)['AttachedPolicies']
    if sorted(p['PolicyArn'] for p in attached) != sorted(expected):
        raise RuntimeError('component managed policies drifted')
    if component == 'broker':
        from prepare_acceptance_broker_iam import _assert_policy_documents
        _assert_policy_documents()
    if component == 'builder':
        # Preserve and verify the checked-in budget policy, never expand it.
        policy_arn = f'arn:aws:iam::{ACCOUNT}:policy/tims-software-factory-acceptance-budget-builder'
        metadata = aws('iam', 'get-policy', '--policy-arn', policy_arn)['Policy']
        document = aws('iam', 'get-policy-version', '--policy-arn', policy_arn,
                       '--version-id', metadata['DefaultVersionId'])['PolicyVersion']['Document']
        expected_document = {'Version': '2012-10-17', 'Statement': [{
            'Sid': 'ReserveAndReconcileAcceptanceAttempts', 'Effect': 'Allow',
            'Action': ['dynamodb:GetItem', 'dynamodb:PutItem', 'dynamodb:UpdateItem'],
            'Resource': f'arn:aws:dynamodb:{REGION}:{ACCOUNT}:table/tims-factory-acceptance-budget',
            'Condition': {'ForAllValues:StringLike': {'dynamodb:LeadingKeys': ['ACTIVATION#*']}}}]}
        if normalize(document) != normalize(expected_document):
            raise RuntimeError('Builder budget policy drifted')


def artifact(component, params, commit):
    code = base64.b64decode(params['CodeSha256'], validate=True)
    if (len(code) != 32 or params['ArtifactBucket'] != BUCKET or
            params['ArtifactKey'] != f'{PREFIXES[component]}/{commit}/{code.hex()}.zip' or
            not params.get('ArtifactVersion') or params['ArtifactVersion'] == 'null'):
        raise RuntimeError('component is not the exact immutable source artifact')


def published(component, template, before, *, version=None, check_alias=True):
    stack = aws('cloudformation', 'describe-stacks', '--stack-name', COMPONENTS[component][0])['Stacks'][0]
    params = {p['ParameterKey']: p['ParameterValue'] for p in stack['Parameters']}
    actual = aws('cloudformation', 'get-template', '--stack-name', COMPONENTS[component][0])['TemplateBody']
    if isinstance(actual, str):
        actual = json.loads(actual)
    if stack['StackStatus'] != 'UPDATE_COMPLETE' or actual != template or params != before['parameters']:
        raise RuntimeError('published stack differs from exact activation plan')
    outputs = {p['OutputKey']: p['OutputValue'] for p in stack['Outputs']}
    arn = outputs[VERSIONS[component] + 'Arn']
    prefix = f'arn:aws:lambda:{REGION}:{ACCOUNT}:function:{COMPONENTS[component][3]}:'
    if (not arn.startswith(prefix) or not arn[len(prefix):].isdigit() or int(arn[len(prefix):]) < 1 or
            (version is not None and arn != version)):
        raise RuntimeError('published component version pin differs')
    config = aws('lambda', 'get-function-configuration', '--function-name', arn)
    properties = template['Resources'][COMPONENTS[component][2]]['Properties']
    env = resolve(properties['Environment']['Variables'], template, params)
    if (config['CodeSha256'] != params['CodeSha256'] or config['Role'] != before['role'] or
            config['Handler'] != properties['Handler'] or config['Timeout'] != properties['Timeout'] or
            config['Environment']['Variables'] != env or config.get('State') != 'Active' or
            sum(len(k.encode()) + len(v.encode()) for k, v in env.items()) > 4096):
        raise RuntimeError('published component configuration differs')
    verify_iam(component, template, params)
    alias = aws('lambda', 'get-alias', '--function-name', COMPONENTS['controller'][3], '--name', 'acceptance')
    if component == 'controller':
        if (alias['FunctionVersion'] != arn.rsplit(':', 1)[-1] or
                alias.get('RoutingConfig', {}).get('AdditionalVersionWeights')):
            raise RuntimeError('controller alias is not the exact new version')
        config = aws('lambda', 'get-function-event-invoke-config',
            '--function-name', COMPONENTS['controller'][3], '--qualifier', 'acceptance')
        if (config.get('MaximumRetryAttempts') != 0 or config.get('MaximumEventAgeInSeconds') != 60 or
                any(config.get('DestinationConfig', {}).get(key) for key in ('OnSuccess', 'OnFailure'))):
            raise RuntimeError('controller asynchronous delivery is not bounded with zero retries')
    elif check_alias and alias != before['alias']:
        raise RuntimeError('controller alias changed before its activation stage')
    return arn


def validate_changes(component, changes):
    expected = {COMPONENTS[component][2]: {'Environment', 'Role'},
                VERSIONS[component]: {'Description', 'FunctionName'}}
    if component == 'builder':
        expected.update(BuilderRole={'Policies'}, ControllerInvoke={'PolicyDocument'})
    if component == 'controller':
        expected.update(ControllerRole={'Policies'}, AcceptanceAlias={'FunctionVersion'}, AcceptanceNoRetries=set())
    if len(changes) != len(expected) or {c['ResourceChange']['LogicalResourceId'] for c in changes} != set(expected):
        raise RuntimeError('activation change set exceeds exact component boundary')
    for entry in changes:
        change = entry['ResourceChange']; name = change['LogicalResourceId']
        if name == 'AcceptanceNoRetries':
            if change['Action'] != 'Add' or change['ResourceType'] != 'AWS::Lambda::EventInvokeConfig':
                raise RuntimeError('controller must add its exact no-retry configuration')
            continue
        replacement = 'True' if name == VERSIONS[component] else 'False'
        if (change['Action'] != 'Modify' or change.get('Replacement') != replacement or
                change.get('Scope') != ['Properties'] or not change.get('Details') or
                any(d['Target'].get('Attribute') != 'Properties' or
                    d['Target'].get('Name') not in expected[name] for d in change['Details'])):
            raise RuntimeError('activation change set contains an unexpected property or replacement')


def checked(plan, *, live):
    if source() != plan['source_commit'] or aws('sts', 'get-caller-identity')['Account'] != ACCOUNT:
        raise RuntimeError('activation source or account changed')
    now = datetime.now(timezone.utc) if live else datetime.fromisoformat(plan['prepared_at'])
    raw = base64.b64decode(plan['job_base64'], validate=True)
    bundle = build_activation_bundle(plan['binding'], raw, now=now)
    baseline, proposed = render(plan['component'], bundle, plan['binding'])
    if bundle != plan['bundle'] or sha(proposed) != plan['template_sha256']:
        raise RuntimeError('activation material changed')
    artifact(plan['component'], plan['before']['parameters'], plan['source_commit'])
    assert_schedule()
    if live:
        verify_live_scope(plan['binding'], raw, now=now)
        for component in ('broker', 'builder'):
            if component == plan['component']:
                break
            # The completed predecessor journal binds the immutable configuration
            # and exact IAM, not merely a syntactically valid version ARN.
            previous = json.loads(Path(plan['predecessors'][component]).read_text())
            if previous['status'] != 'COMPONENT_PUBLISHED_SCHEDULE_DISABLED':
                raise RuntimeError('predecessor is not verified')
            _, proposed_previous = checked(previous, live=False)
            for key in ('activation_id', 'source_commit', 'contract_digest', 'starts_at', 'expires_at', 'job_version_id', 'provider_secret_arn'):
                if previous['binding'][key] != plan['binding'][key]:
                    raise RuntimeError('predecessor scope differs')
            if previous['job_base64'] != plan['job_base64']:
                raise RuntimeError('predecessor job differs')
            if previous['before']['code_sha256'] != plan['before']['code_sha256']:
                raise RuntimeError('components do not share the same package bytes')
            if component == 'builder' and previous['binding']['broker_version_arn'] != plan['binding']['broker_version_arn']:
                raise RuntimeError('Builder is pinned to another broker version')
            published(component, proposed_previous, previous['before'], version=plan['binding'][component + '_version_arn'])
    return baseline, proposed


def change_checked(plan, status):
    change = aws('cloudformation', 'describe-change-set', '--change-set-name', plan['change_set_arn'])
    validate_changes(plan['component'], change['Changes'])
    template = aws('cloudformation', 'get-template', '--change-set-name', plan['change_set_arn'])['TemplateBody']
    if isinstance(template, str):
        template = json.loads(template)
    if (change['Status'] != 'CREATE_COMPLETE' or change['ExecutionStatus'] != status or
            change['StackId'] != plan['before']['stack_id'] or change['Changes'] != plan['changes'] or
            {p['ParameterKey']: p['ParameterValue'] for p in change['Parameters']} != plan['before']['parameters'] or
            sha(template) != plan['template_sha256']):
        raise RuntimeError('activation change set differs from reviewed plan')


def prepare(component, binding_path, job_path, predecessors_path, path):
    now = datetime.now(timezone.utc)
    binding = json.loads(Path(binding_path).read_text()); raw = Path(job_path).read_bytes()
    bundle = build_activation_bundle(binding, raw, now=now)
    baseline, proposed = render(component, bundle, binding)
    before = snapshot(component, baseline)
    verify_iam(component, baseline, before['parameters'])
    predecessors = json.loads(Path(predecessors_path).read_text())
    required = {'broker': set(), 'builder': {'broker'}, 'controller': {'broker', 'builder'}}[component]
    if set(predecessors) != required:
        raise RuntimeError('activation requires exact predecessor journals')
    plan = {'status': 'PREPARING', 'source_commit': source(), 'prepared_at': now.isoformat(),
        'component': component, 'binding': binding, 'bundle': bundle, 'before': before,
        'predecessors': predecessors, 'job_base64': base64.b64encode(raw).decode(),
        'template_sha256': sha(proposed)}
    checked(plan, live=True)
    save(path, plan, exclusive=True)
    template_path = Path(path).with_suffix('.template.json'); save(template_path, proposed, exclusive=True)
    created = aws('cloudformation', 'create-change-set', '--stack-name', COMPONENTS[component][0],
        '--change-set-name', 'commissioning-' + uuid.uuid4().hex, '--change-set-type', 'UPDATE',
        '--template-body', 'file://' + str(template_path.resolve()), '--capabilities', 'CAPABILITY_NAMED_IAM',
        '--parameters', json.dumps([{'ParameterKey': key, 'UsePreviousValue': True} for key in before['parameters']]))
    plan['change_set_arn'] = created['Id']; save(path, plan)
    aws('cloudformation', 'wait', 'change-set-create-complete', '--change-set-name', created['Id'])
    plan['changes'] = aws('cloudformation', 'describe-change-set', '--change-set-name', created['Id'])['Changes']
    validate_changes(component, plan['changes'])
    plan['status'] = 'PREPARED_NOT_EXECUTED'; save(path, plan)
    print(json.dumps({'status': plan['status'], 'component': component, 'changes': plan['changes']}))


def execute(path):
    plan = json.loads(Path(path).read_text())
    if plan['status'] != 'PREPARED_NOT_EXECUTED':
        raise RuntimeError('activation execution is single-attempt; reconcile instead')
    baseline, _ = checked(plan, live=True)
    if snapshot(plan['component'], baseline) != plan['before']:
        raise RuntimeError('component changed after preparation')
    verify_iam(plan['component'], baseline, plan['before']['parameters'])
    change_checked(plan, 'AVAILABLE')
    plan['status'] = 'ATTEMPTED_RECONCILE_REQUIRED'; save(path, plan)
    aws('cloudformation', 'execute-change-set', '--change-set-name', plan['change_set_arn'])
    aws('cloudformation', 'wait', 'stack-update-complete', '--stack-name', COMPONENTS[plan['component']][0])
    verify(path)


def verify(path):
    plan = json.loads(Path(path).read_text())
    if plan['status'] not in {'ATTEMPTED_RECONCILE_REQUIRED', 'COMPONENT_PUBLISHED_SCHEDULE_DISABLED'}:
        raise RuntimeError('activation has not been attempted')
    _, proposed = checked(plan, live=False)
    change_checked(plan, 'EXECUTE_COMPLETE')
    arn = published(plan['component'], proposed, plan['before'])
    plan.update(status='COMPONENT_PUBLISHED_SCHEDULE_DISABLED', version_arn=arn)
    save(path, plan)
    print(json.dumps({'status': plan['status'], 'version_arn': arn, 'model_calls_by_tool': 0}))


if __name__ == '__main__':
    if len(sys.argv) == 7 and sys.argv[1] == 'prepare':
        prepare(*sys.argv[2:])
    elif len(sys.argv) == 3 and sys.argv[1] in {'execute', 'verify', 'reconcile'}:
        (execute if sys.argv[1] == 'execute' else verify)(sys.argv[2])
    else:
        raise SystemExit('use prepare COMPONENT BINDING JOB PREDECESSORS PLAN | execute PLAN | verify PLAN | reconcile PLAN')
