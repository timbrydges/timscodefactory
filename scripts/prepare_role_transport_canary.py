"""Prepare, execute and verify the durable model-free role transport update."""
import base64
import hashlib
import json
import re
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

try:
    from .prepare_role_deployment import ACCOUNT, BUCKET, REGION, ROLES, ROOT, aws, source
except ImportError:
    from prepare_role_deployment import ACCOUNT, BUCKET, REGION, ROLES, ROOT, aws, source


def validate_changes(changes):
    expected = {'ControllerInvoke'} | {role.title()+suffix for role in ROLES
        for suffix in ('Function', 'Version')}
    found = {change['ResourceChange']['LogicalResourceId'] for change in changes}
    if found != expected:
        raise RuntimeError(f'unexpected transport update resources: {sorted(found)}')
    for change in changes:
        item = change['ResourceChange']; logical = item['LogicalResourceId']
        if item['Action'] != 'Modify':
            raise RuntimeError('transport update must modify existing resources only')
        replacement = item.get('Replacement')
        if logical.endswith('Version'):
            if replacement != 'True':
                raise RuntimeError('published Lambda versions must be replaced')
        elif replacement != 'False':
            raise RuntimeError('functions and controller policy must update in place')


def prepare(package, plan_path):
    commit = source()
    if aws('sts', 'get-caller-identity')['Account'] != ACCOUNT:
        raise RuntimeError('wrong AWS account')
    stack = aws('cloudformation', 'describe-stacks', '--stack-name', 'tims-factory-roles')['Stacks'][0]
    if stack['StackStatus'] != 'CREATE_COMPLETE':
        raise RuntimeError('role stack must be at its verified initial deployment')
    old_outputs = {x['OutputKey']: x['OutputValue'] for x in stack['Outputs']}
    package = Path(package).resolve(); manifest = json.loads(package.with_suffix('.json').read_text())
    if manifest['source_commit'] != commit or manifest['sha256'] != hashlib.sha256(package.read_bytes()).hexdigest():
        raise RuntimeError('package differs from exact clean checkout')
    key = f'factory-role-packages/{commit}/{manifest["sha256"]}.zip'
    upload = aws('s3api', 'put-object', '--bucket', BUCKET, '--key', key, '--body', str(package),
        '--checksum-algorithm', 'SHA256', '--checksum-sha256', manifest['code_sha256'])
    version = upload.get('VersionId')
    if not version or version == 'null':
        raise RuntimeError('versioned artifact storage required')
    parameters = [{'ParameterKey': k, 'ParameterValue': v} for k,v in {
        'ArtifactBucket': BUCKET, 'ArtifactKey': key, 'ArtifactVersion': version,
        'CodeSha256': manifest['code_sha256']}.items()]
    template = ROOT/'infra/roles/functions.cloudformation.json'
    aws('cloudformation', 'validate-template', '--template-body', 'file://'+str(template))
    name = 'transport-'+commit[:12]+'-'+uuid.uuid4().hex[:8]
    created = aws('cloudformation', 'create-change-set', '--stack-name', 'tims-factory-roles',
        '--change-set-name', name, '--change-set-type', 'UPDATE',
        '--template-body', 'file://'+str(template), '--parameters', json.dumps(parameters),
        '--capabilities', 'CAPABILITY_NAMED_IAM')
    arn = created['Id']
    aws('cloudformation', 'wait', 'change-set-create-complete', '--change-set-name', arn)
    described = aws('cloudformation', 'describe-change-set', '--change-set-name', arn)
    validate_changes(described['Changes'])
    plan = {'source_commit': commit, 'artifact': manifest, 'change_set_arn': arn,
        'template_sha256': hashlib.sha256(template.read_bytes()).hexdigest(),
        'changes': described['Changes'], 'previous_versions': old_outputs,
        'status': 'PREPARED_NOT_EXECUTED', 'model_calls_authorized': 0}
    Path(plan_path).write_text(json.dumps(plan, indent=2)+'\n')
    print(json.dumps(plan, indent=2))


def execute(plan_path):
    plan_path = Path(plan_path).resolve(); plan = json.loads(plan_path.read_text())
    if plan['source_commit'] != source() or aws('sts', 'get-caller-identity')['Account'] != ACCOUNT:
        raise RuntimeError('deployment account/source changed')
    template = ROOT/'infra/roles/functions.cloudformation.json'
    if hashlib.sha256(template.read_bytes()).hexdigest() != plan['template_sha256']:
        raise RuntimeError('reviewed template changed')
    described = aws('cloudformation', 'describe-change-set', '--change-set-name', plan['change_set_arn'])
    validate_changes(described['Changes'])
    if described['Changes'] != plan['changes'] or described['ExecutionStatus'] != 'AVAILABLE':
        raise RuntimeError('reviewed change set changed or cannot execute')
    aws('cloudformation', 'execute-change-set', '--change-set-name', plan['change_set_arn'])
    aws('cloudformation', 'wait', 'stack-update-complete', '--stack-name', 'tims-factory-roles')
    plan['status'] = 'DEPLOYED_PENDING_TRANSPORT_PROOFS'
    plan_path.write_text(json.dumps(plan, indent=2)+'\n')
    print(json.dumps({'status': plan['status'], 'source_commit': plan['source_commit']}))


def invoke(arn, event, target):
    response = aws('lambda', 'invoke', '--function-name', arn, '--invocation-type', 'RequestResponse',
        '--cli-binary-format', 'raw-in-base64-out', '--payload', json.dumps(event), str(target))
    if response.get('FunctionError') or response.get('ExecutedVersion') != arn.rsplit(':',1)[1]:
        raise RuntimeError(f'role invocation failed; inspect {target}')
    return json.loads(target.read_text())


def verify(plan_path):
    sys.path.insert(0, str(ROOT/'src'))
    from factory_state.kms_signer import SIGNERS
    from factory_state.scope import SignedScopeStore, canonical
    from factory_state.signers import load_trusted_signers
    plan_path = Path(plan_path).resolve(); plan = json.loads(plan_path.read_text())
    if (not re.fullmatch(r'[a-f0-9]{40}', plan.get('source_commit', '')) or
            aws('sts', 'get-caller-identity')['Account'] != ACCOUNT):
        raise RuntimeError('verification account or deployed source binding invalid')
    stack = aws('cloudformation', 'describe-stacks', '--stack-name', 'tims-factory-roles')['Stacks'][0]
    if stack['StackStatus'] != 'UPDATE_COMPLETE':
        raise RuntimeError('role transport stack update not complete')
    outputs = {x['OutputKey']: x['OutputValue'] for x in stack['Outputs']}
    versions = {outputs[role.title()+'VersionArn'] for role in ROLES}
    if versions & set(plan['previous_versions'].values()) or len(versions) != 3:
        raise RuntimeError('transport update did not publish three fresh versions')
    policy = aws('iam', 'get-role-policy', '--role-name', 'tims-software-factory-github-controller',
        '--policy-name', 'factory-isolated-role-versions')['PolicyDocument']
    resources = policy['Statement'][0]['Resource']
    if set(resources if isinstance(resources, list) else [resources]) != versions:
        raise RuntimeError('controller invocation policy is not pinned to fresh versions')
    trusted = load_trusted_signers(ROOT/'factory/profiles/scope-signers.json', now=datetime.now(timezone.utc))
    verifier = SignedScopeStore('unused', None, trusted)
    proofs = []
    for role in ROLES:
        arn = outputs[role.title()+'VersionArn']
        configuration = aws('lambda', 'get-function-configuration', '--function-name', arn)
        if (configuration['CodeSha256'] != plan['artifact']['code_sha256'] or
                configuration['Role'] != f'arn:aws:iam::{ACCOUNT}:role/tims-factory-executor-{role}' or
                configuration['Environment']['Variables'].get('EXECUTION_TABLE') != 'tims-factory-role-executions'):
            raise RuntimeError('deployed transport function differs from plan')
        identity_nonce = uuid.uuid4().hex
        identity = invoke(arn, {'kind':'identity_probe','source_commit':plan['source_commit'],
            'nonce':identity_nonce}, plan_path.parent/f'transport-identity-{role}.json')
        identity_now = datetime.now(timezone.utc)
        verifier._verify(identity['payload'], base64.b64decode(identity['signature_base64'], validate=True),
            SIGNERS[role], identity_now)
        nonce = uuid.uuid4().hex; raw = f'{role}:model-free-transport:{plan["source_commit"]}'.encode()
        event = {'kind':'transport_canary','source_commit':plan['source_commit'],'nonce':nonce,
            'input_base64':base64.b64encode(raw).decode()}
        target = plan_path.parent/f'transport-{role}.json'
        first = invoke(arn, event, target); second = invoke(arn, event, target)
        transport_now = datetime.now(timezone.utc)
        if first != second or first.get('model_calls') != 0 or first.get('operational_execution_enabled') is not False:
            raise RuntimeError('transport replay or model-free boundary failed')
        payload = first['payload']; expected = {'kind':'transport_result','producer_identity':SIGNERS[role],
            'source_commit':plan['source_commit'],'nonce':nonce,
            'input_digest':'sha256:'+hashlib.sha256(raw).hexdigest(),
            'output_digest':'sha256:'+hashlib.sha256(base64.b64decode(first['output_base64'], validate=True)).hexdigest(),
            'purpose':'lambda-transport-canary-only'}
        if set(payload) != set(expected)|{'issued_at','expires_at'} or any(payload[k] != v for k,v in expected.items()):
            raise RuntimeError('signed transport binding mismatch')
        verifier._verify(payload, base64.b64decode(first['signature_base64'], validate=True),
            SIGNERS[role], transport_now)
        key = {'PK':{'S':f'ROLE#{SIGNERS[role]}#FACTORY#tims-software-factory#TASK#cloud-role-canary-{nonce}'},
               'SK':{'S':'EXECUTION#transport-canary'}}
        record = aws('dynamodb', 'get-item', '--table-name', 'tims-factory-role-executions',
            '--key', json.dumps(key), '--consistent-read').get('Item', {})
        if (record.get('status') != {'S':'COMPLETE'} or record.get('model_calls') != {'N':'0'} or
                record.get('response') != {'S':canonical(first).decode()}):
            raise RuntimeError('durable transport evidence mismatch')
        proofs.append({'role':role,'function_arn':arn,'identity':SIGNERS[role],
            'transport_payload':payload,'signature_base64':first['signature_base64'],
            'replay_returned_identical_result':True,'durable_record_status':'COMPLETE','model_calls':0})
    evidence = {'source_commit':plan['source_commit'],'status':'THREE_ROLE_TRANSPORTS_VERIFIED',
        'model_calls':0,'operational_execution_enabled':False,'autonomous_scheduling_enabled':False,
        'proofs':proofs}
    plan_path.with_name('role-transport-evidence.json').write_text(json.dumps(evidence,indent=2)+'\n')
    print(json.dumps(evidence,indent=2))


if __name__ == '__main__':
    if sys.argv[1] == 'prepare': prepare(sys.argv[2], sys.argv[3])
    elif sys.argv[1] == 'execute': execute(sys.argv[2])
    elif sys.argv[1] == 'verify': verify(sys.argv[2])
    else: raise SystemExit('Use prepare PACKAGE PLAN, execute PLAN, or verify PLAN')
