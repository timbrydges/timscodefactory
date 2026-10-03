"""Offline additive Security deployment plan; no cloud writes or execution authority."""
import argparse
import base64
import copy
import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from factory_state.model import StateError
from factory_state.scope import canonical

BUCKET = 'tims-software-factory-666730517561-ca-central-1'
STACK_PREFIX = 'arn:aws:cloudformation:ca-central-1:666730517561:stack/tims-factory-review-bootstrap/'
HANDLER = 'factory_runtime.security_validation_attestation.handler'


def digest(value):
    return 'sha256:' + hashlib.sha256(canonical(value)).hexdigest()


def prepare(current, package, *, object_version):
    if (not isinstance(package, dict) or
            set(package) != {'source_commit','sha256','code_sha256','zip_bytes'} or
            not isinstance(package['source_commit'], str) or not re.fullmatch('[0-9a-f]{40}', package['source_commit']) or
            not isinstance(package['sha256'], str) or not re.fullmatch('[0-9a-f]{64}', package['sha256']) or
            package['code_sha256'] != base64.b64encode(bytes.fromhex(package['sha256'])).decode() or
            type(package['zip_bytes']) is not int or not 0 < package['zip_bytes'] <= 50*1024*1024 or
            not isinstance(object_version, str) or object_version == 'null' or
            not re.fullmatch('[A-Za-z0-9._+/-]{1,1024}', object_version)):
        raise StateError('Security deployment requires an exact immutable package')
    if (not isinstance(current, dict) or 'Transform' in current or
            not isinstance(current.get('Resources'), dict) or not isinstance(current.get('Outputs'), dict)):
        raise StateError('Security deployment requires a plain current stack template')
    resources = current['Resources']
    function = resources.get('SecurityFunction', {})
    props = function.get('Properties', {})
    if (function.get('Type') != 'AWS::Lambda::Function' or
            props.get('FunctionName') != 'tims-factory-review-security' or props.get('Runtime') != 'python3.12' or
            props.get('Architectures') != ['x86_64'] or props.get('MemorySize') != 128 or
            props.get('Role') != {'Fn::GetAtt':['SecurityRole','Arn']} or
            props.get('Environment', {}).get('Variables', {}).get('FACTORY_REVIEW_ROLE') != 'security' or
            props.get('Environment', {}).get('Variables', {}).get('FACTORY_REVIEW_KEY_ARN') != {'Fn::GetAtt':['SecurityKey','Arn']} or
            props.get('Environment', {}).get('Variables', {}).get('FACTORY_OPERATIONAL_EXECUTION_ENABLED') != 'false' or
            not all(k in resources for k in ('SecurityVersion','SecurityRole','SecurityKey','QaFunction','QaVersion'))):
        raise StateError('Security deployment baseline identity or disabled controls differ')
    logical = 'SecurityValidationVersion' + package['sha256'][:16]
    output = logical + 'Arn'
    already_published = any(
        resource.get('Type') == 'AWS::Lambda::Version' and
        resource.get('Properties', {}).get('FunctionName') in ({'Ref':'SecurityFunction'}, 'tims-factory-review-security') and
        resource.get('Properties', {}).get('CodeSha256') == package['code_sha256']
        for resource in resources.values())
    if already_published or logical in resources or output in current['Outputs']:
        raise StateError('Security package version already planned or deployed; verify instead of replaying')
    template = copy.deepcopy(current)
    template['Resources']['SecurityFunction']['Properties'].update(
        Handler=HANDLER, Timeout=60, Code={'S3Bucket':BUCKET,
            'S3Key':f"security-validation/{package['source_commit']}/{package['sha256']}.zip",
            'S3ObjectVersion':object_version})
    disabled = template['Resources']['SecurityFunction']['Properties']
    disabled['Environment']['Variables']['FACTORY_SECURITY_ATTESTATION_ENABLED']='false'
    disabled['Environment']['Variables']['FACTORY_SECURITY_VALIDATION_ENABLED']='false'
    disabled['ReservedConcurrentExecutions']=0
    template['Resources'][logical] = {'Type':'AWS::Lambda::Version',
        'DeletionPolicy':'Retain','UpdateReplacePolicy':'Retain', 'Properties':{
            'FunctionName':{'Ref':'SecurityFunction'}, 'CodeSha256':package['code_sha256'],
            'Description':'Disabled Security validation '+package['source_commit']}}
    template['Outputs'][output] = {'Value':{'Ref':logical}}
    return {'status':'PREPARED_NOT_EXECUTED','source_commit':package['source_commit'],
        'base_template_digest':digest(current), 'template_digest':digest(template),
        'version_logical_id':logical,'version_output':output,'template':template,
        'package':copy.deepcopy(package),'model_calls_authorized':0,'execution_authorized':False,
        'gate_authority':False}


def validate_changes(plan, current, proposed, change_set, *, stack_id, current_parameters):
    """Require actual change-set template AND summary, never trust its title."""
    try:
        version = plan['template']['Resources']['SecurityFunction']['Properties']['Code']['S3ObjectVersion']
        expected = prepare(current, plan['package'], object_version=version)
        if canonical(plan) != canonical(expected) or canonical(proposed) != canonical(expected['template']):
            raise StateError('Security deployment plan or change-set template changed')
        if (not isinstance(stack_id, str) or not stack_id.startswith(STACK_PREFIX) or
                not stack_id[len(STACK_PREFIX):] or change_set.get('StackId') != stack_id or
                change_set.get('Status') != 'CREATE_COMPLETE' or
                change_set.get('ExecutionStatus') != 'AVAILABLE' or change_set.get('NextToken')):
            raise StateError('Security change set is incomplete, unavailable or targets another stack')
        parameters = change_set.get('Parameters', [])
        if (not isinstance(parameters,list) or len(parameters)!=len(current_parameters) or
                {p.get('ParameterKey') for p in parameters}!=set(current_parameters) or
                any(p.get('ParameterValue')!=current_parameters[p['ParameterKey']] for p in parameters)):
            raise StateError('Security deployment must preserve resolved stack parameter values')
        changes = change_set.get('Changes')
        if not isinstance(changes, list) or len(changes) != 2:
            raise StateError('Security deployment must contain exactly two resource changes')
        seen = set()
        for change in changes:
            rc = change['ResourceChange']; name = rc['LogicalResourceId']
            if change.get('Type') != 'Resource' or name in seen:
                raise StateError('Security change set contains duplicate or non-resource changes')
            seen.add(name)
            if name == plan['version_logical_id']:
                if rc.get('Action') != 'Add' or rc.get('ResourceType') != 'AWS::Lambda::Version':
                    raise StateError('Security version must be additive')
            elif name == 'SecurityFunction':
                if (rc.get('Action') != 'Modify' or rc.get('ResourceType') != 'AWS::Lambda::Function' or
                        rc.get('Replacement') != 'False' or rc.get('Scope') != ['Properties']):
                    raise StateError('Security function replacement or non-property change prohibited')
                details = rc.get('Details')
                if not isinstance(details, list) or not details:
                    raise StateError('Security function change details missing')
                for detail in details:
                    target = detail['Target']
                    if (target.get('Attribute') != 'Properties' or target.get('Name') not in ('Code','Handler','Timeout','Environment','ReservedConcurrentExecutions') or
                            target.get('RequiresRecreation') != 'Never'):
                        raise StateError('Security deployment changes a protected property')
            else:
                raise StateError('Security deployment changes a protected resource')
        if seen != {'SecurityFunction',plan['version_logical_id']}:
            raise StateError('Security deployment missing required changes')
    except (KeyError, TypeError, AttributeError, ValueError):
        raise StateError('Security change-set evidence malformed') from None
    return {'status':'SECURITY_CHANGE_SET_VALIDATED_NOT_EXECUTED',
            'template_digest':plan['template_digest'],'gate_authority':False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('current_template', type=Path)
    parser.add_argument('package_manifest', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--object-version', required=True)
    args = parser.parse_args()
    plan = prepare(json.loads(args.current_template.read_bytes()),
        json.loads(args.package_manifest.read_bytes()), object_version=args.object_version)
    with args.output.open('x', encoding='utf-8') as output:
        output.write(json.dumps(plan, indent=2)+'\n')
    print('PREPARED_NOT_EXECUTED: existing resources and parameters must be preserved')
