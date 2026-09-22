"""Prepare reviewed Factory role change sets in owner-authenticated CloudShell.

Preparation uploads the bounded ZIP but does not execute either change set.
Execution is a separate explicit command against the locally retained plan.
"""
import base64
import hashlib
import json
import os
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ACCOUNT = '666730517561'
REGION = 'ca-central-1'
BUCKET = 'tims-software-factory-666730517561-ca-central-1'
ROLES = ('planner', 'builder', 'inspector')


def aws(*args):
    env = {**os.environ, 'AWS_MAX_ATTEMPTS': '1', 'AWS_PAGER': ''}
    result = subprocess.run(['aws', *args, '--region', REGION, '--output', 'json', '--no-cli-pager'],
        capture_output=True, text=True, env=env, timeout=900)
    if result.returncode:
        raise RuntimeError(f'AWS {args[0]} {args[1]} failed: {result.stderr.strip()}')
    return json.loads(result.stdout) if result.stdout.strip() else {}


def source():
    if subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT, text=True).strip():
        raise RuntimeError('clean checkout required')
    return subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()


def validate_changes(stack, changes):
    if stack == 'tims-factory-roles':
        expected = {'RoleExecutions', 'ControllerInvoke'} | {r.title()+suffix for r in ROLES
            for suffix in ('Logs', 'Role', 'Function', 'Version')}
        if {x['ResourceChange']['LogicalResourceId'] for x in changes} != expected:
            raise RuntimeError('unexpected role resource set')
        if any(x['ResourceChange']['Action'] != 'Add' for x in changes):
            raise RuntimeError('role deployment must contain additions only')
    else:
        expected = {r.title()+'Role' for r in ROLES}
        if {x['ResourceChange']['LogicalResourceId'] for x in changes} != expected:
            raise RuntimeError('signing update must touch exactly three non-owner roles')
        if any(x['ResourceChange']['Action'] != 'Modify' or x['ResourceChange'].get('Replacement') != 'False'
               for x in changes):
            raise RuntimeError('signing update must not replace any resource')


def prepare(package, plan_path):
    commit = source()
    if aws('sts', 'get-caller-identity')['Account'] != ACCOUNT:
        raise RuntimeError('wrong AWS account')
    package = Path(package).resolve(); manifest = json.loads(package.with_suffix('.json').read_text())
    if manifest['source_commit'] != commit or manifest['sha256'] != hashlib.sha256(package.read_bytes()).hexdigest():
        raise RuntimeError('package differs from exact clean checkout')
    key = f'factory-role-packages/{commit}/{manifest["sha256"]}.zip'
    upload = aws('s3api', 'put-object', '--bucket', BUCKET, '--key', key, '--body', str(package),
                 '--checksum-algorithm', 'SHA256', '--checksum-sha256', manifest['code_sha256'])
    version = upload.get('VersionId')
    if not version or version == 'null':
        raise RuntimeError('versioned artifact storage required')
    params = [{'ParameterKey': k, 'ParameterValue': v} for k,v in {
        'ArtifactBucket': BUCKET, 'ArtifactKey': key, 'ArtifactVersion': version,
        'CodeSha256': manifest['code_sha256']}.items()]
    plans = []
    for stack, kind, relative, parameters in (
        ('tims-factory-roles', 'CREATE', 'infra/roles/functions.cloudformation.json', params),
        ('tims-factory-signing', 'UPDATE', 'infra/signing/keys.cloudformation.json',
         [{'ParameterKey': 'EnableRoleExecutionTrust', 'ParameterValue': 'true'}])):
        template = ROOT/relative
        aws('cloudformation', 'validate-template', '--template-body', 'file://'+str(template))
        name = 'roles-'+commit[:12]+'-'+uuid.uuid4().hex[:8]
        created = aws('cloudformation', 'create-change-set', '--stack-name', stack,
            '--change-set-name', name, '--change-set-type', kind,
            '--template-body', 'file://'+str(template), '--parameters', json.dumps(parameters),
            '--capabilities', 'CAPABILITY_NAMED_IAM')
        arn = created['Id']
        aws('cloudformation', 'wait', 'change-set-create-complete', '--change-set-name', arn)
        described = aws('cloudformation', 'describe-change-set', '--change-set-name', arn)
        validate_changes(stack, described['Changes'])
        plans.append({'stack': stack, 'type': kind, 'change_set_arn': arn,
            'template': relative, 'template_sha256': hashlib.sha256(template.read_bytes()).hexdigest(),
            'changes': described['Changes']})
    plan = {'source_commit': commit, 'artifact': manifest, 'plans': plans,
            'status': 'PREPARED_NOT_EXECUTED', 'model_calls_authorized': 0}
    Path(plan_path).write_text(json.dumps(plan, indent=2)+'\n')
    print(json.dumps(plan, indent=2))


def execute(plan_path):
    plan_path = Path(plan_path).resolve(); plan = json.loads(plan_path.read_text())
    if plan['source_commit'] != source() or aws('sts', 'get-caller-identity')['Account'] != ACCOUNT:
        raise RuntimeError('deployment account/source changed')
    for entry in plan['plans']:
        if hashlib.sha256((ROOT/entry['template']).read_bytes()).hexdigest() != entry['template_sha256']:
            raise RuntimeError('reviewed template changed')
        described = aws('cloudformation', 'describe-change-set', '--change-set-name', entry['change_set_arn'])
        validate_changes(entry['stack'], described['Changes'])
        if described['Changes'] != entry['changes']:
            raise RuntimeError('reviewed change set changed')
        if described['ExecutionStatus'] == 'AVAILABLE':
            aws('cloudformation', 'execute-change-set', '--change-set-name', entry['change_set_arn'])
        elif described['ExecutionStatus'] not in {'EXECUTE_IN_PROGRESS', 'EXECUTE_COMPLETE'}:
            raise RuntimeError('change set cannot execute; reconcile stack state')
        waiter = 'stack-create-complete' if entry['type'] == 'CREATE' else 'stack-update-complete'
        aws('cloudformation', 'wait', waiter, '--stack-name', entry['stack'])
    plan['status'] = 'DEPLOYED_PENDING_PROBES'; plan_path.write_text(json.dumps(plan, indent=2)+'\n')
    print(json.dumps({'status': plan['status'], 'source_commit': plan['source_commit']}))


def verify(plan_path):
    sys.path.insert(0, str(ROOT/'src'))
    from factory_state.scope import SignedScopeStore
    from factory_state.signers import load_trusted_signers
    from factory_state.kms_signer import SIGNERS
    plan_path = Path(plan_path).resolve(); plan = json.loads(plan_path.read_text())
    if plan['source_commit'] != source() or aws('sts', 'get-caller-identity')['Account'] != ACCOUNT:
        raise RuntimeError('verification account/source changed')
    result = aws('cloudformation', 'describe-stacks', '--stack-name', 'tims-factory-roles')['Stacks'][0]
    if result['StackStatus'] != 'CREATE_COMPLETE':
        raise RuntimeError('role stack not complete')
    outputs = {x['OutputKey']: x['OutputValue'] for x in result['Outputs']}
    proofs = []
    for role in ROLES:
        nonce = uuid.uuid4().hex
        event = {'kind': 'identity_probe', 'source_commit': plan['source_commit'], 'nonce': nonce}
        target = plan_path.parent/f'role-probe-{role}.json'
        arn = outputs[role.title()+'VersionArn']
        configuration = aws('lambda', 'get-function-configuration', '--function-name', arn)
        if (configuration['CodeSha256'] != plan['artifact']['code_sha256'] or
                configuration['Role'] != f'arn:aws:iam::{ACCOUNT}:role/tims-factory-executor-{role}'):
            raise RuntimeError('deployed function code or execution role differs from plan')
        response = aws('lambda', 'invoke', '--function-name', arn, '--invocation-type', 'RequestResponse',
            '--cli-binary-format', 'raw-in-base64-out', '--payload', json.dumps(event), str(target))
        if response.get('FunctionError') or response.get('ExecutedVersion') != arn.rsplit(':',1)[1]:
            raise RuntimeError(f'{role} deployment probe failed; inspect {target}')
        proof = json.loads(target.read_text()); now = datetime.now(timezone.utc)
        payload = proof['payload']
        expected = {'kind':'identity_challenge','identity':SIGNERS[role], 'source_commit':plan['source_commit'],
                    'nonce':nonce, 'purpose':'lambda-deployment-verification-only'}
        if set(payload) != set(expected)|{'issued_at','expires_at'} or any(payload[k] != v for k,v in expected.items()):
            raise RuntimeError('probe binding mismatch')
        SignedScopeStore('unused', None, load_trusted_signers(ROOT/'factory/profiles/scope-signers.json', now=now))._verify(
            payload, base64.b64decode(proof['signature_base64'], validate=True), SIGNERS[role], now)
        if proof['model_calls'] != 0 or proof['operational_execution_enabled'] is not False:
            raise RuntimeError('probe exceeded deployment scope')
        proofs.append({'role':role, 'function_arn':arn, 'proof':proof})
    evidence = {'source_commit':plan['source_commit'], 'status':'THREE_LAMBDA_IDENTITIES_VERIFIED',
                'model_calls':0, 'autonomous_execution_enabled':False, 'proofs':proofs}
    plan_path.with_name('role-deployment-evidence.json').write_text(json.dumps(evidence, indent=2)+'\n')
    print(json.dumps(evidence, indent=2))


if __name__ == '__main__':
    if sys.argv[1] == 'prepare': prepare(sys.argv[2], sys.argv[3])
    elif sys.argv[1] == 'execute': execute(sys.argv[2])
    elif sys.argv[1] == 'verify': verify(sys.argv[2])
    else: raise SystemExit('Use prepare PACKAGE PLAN, execute PLAN, or verify PLAN')
