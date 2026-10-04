"""Validate only two disabled reviewer updates; never executes a change set."""
import base64
import copy
import json
from pathlib import Path
import re
from prepare_pilot002_runtime import ACCOUNT,REGION,STACK,StateError

SOURCE='d9c75eb8b59c3c6bda508557224fd92354f8d34c'
BUCKET='tims-software-factory-666730517561-ca-central-1'
ROOT=Path(__file__).resolve().parents[1]
REVIEWERS=('InspectorFunction','QaFunction')


def baseline():
    return json.loads((ROOT/'factory/evidence/pilot-002-builder-live-preview.json').read_bytes())['rollback_template']


def render(current,package,code):
    if current!=baseline():raise StateError('Exact disabled baseline required')
    sha=package.get('sha256','')
    if (package.get('source_commit')!=SOURCE or package.get('execution_enabled') is not False or
            type(package.get('model_calls')) is not int or package['model_calls']!=0 or
            package.get('handler')!='factory_runtime.pilot002_runtime_probe.handler' or
            'activation_sha256' in package or not re.fullmatch('[0-9a-f]{64}',sha) or
            package.get('code_sha256')!=base64.b64encode(bytes.fromhex(sha)).decode()):
        raise StateError('Unreviewed disabled package')
    if (set(code)!={'S3Bucket','S3Key','S3ObjectVersion'} or code['S3Bucket']!=BUCKET or
            code['S3Key']!='pilot-002/runtime/'+SOURCE+'/'+sha+'.zip' or
            not isinstance(code['S3ObjectVersion'],str) or not 0<len(code['S3ObjectVersion'])<=1024 or
            code['S3ObjectVersion']=='null'):raise StateError('Immutable artifact required')
    result=copy.deepcopy(current)
    for name in REVIEWERS:
        props=result['Resources'][name]['Properties']
        props.update(Code=copy.deepcopy(code),Handler='factory_runtime.pilot002_entrypoint.handler',Timeout=180,
            Description='Pilot 002 reviewer staged entrypoint; disabled, no activation material')
        props['Tags']=[{'Key':'SourceCommit','Value':SOURCE},{'Key':'Purpose','Value':'disabled-reviewer-entrypoint'}]
    return result


def validate(template,changes,package,code):
    if (template!=render(baseline(),package,code) or changes.get('Status')!='CREATE_COMPLETE' or
            changes.get('ExecutionStatus')!='AVAILABLE' or changes.get('NextToken') or changes.get('Parameters') or
            not str(changes.get('StackId','')).startswith(f'arn:aws:cloudformation:{REGION}:{ACCOUNT}:stack/{STACK}/')):
        raise StateError('Incomplete or changed preview')
    items=changes.get('Changes',[])
    if len(items)!=2 or {v.get('ResourceChange',{}).get('LogicalResourceId') for v in items}!=set(REVIEWERS):
        raise StateError('Only the two reviewers may change')
    for item in items:
        change=item.get('ResourceChange',{})
        if (item.get('Type')!='Resource' or change.get('ResourceType')!='AWS::Lambda::Function' or
                change.get('Action')!='Modify' or change.get('Replacement')!='False'):
            raise StateError('Unexpected resource operation')
    return {'status':'REVIEWER_STAGE_VALIDATED_NOT_EXECUTED','source_commit':SOURCE,
        'changed_functions':['inspector','qa'],'execution_enabled':False,'reserved_concurrency':0,
        'activation_material_present':False,'provider_calls':0,'iam_changes':0}
