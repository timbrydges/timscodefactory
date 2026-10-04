"""Render/validate the exact Inspector-only shared-capacity preview; never execute."""
import base64
import copy
import json
from pathlib import Path
from factory_state.model import StateError

ROOT=Path(__file__).resolve().parents[1]
SOURCE='d9c75eb8b59c3c6bda508557224fd92354f8d34c'
ACTIVATION='c19193c7fce6204f7f2e80746dc7a5e847b05bc426248e4b32478d2a6585c9d2'
PLAN='sha256:dd8d6e4149871cc47d0247552db790b8d8d9b40b200d5702dc30f02af1baba8c'
STACK='arn:aws:cloudformation:ca-central-1:666730517561:stack/tims-factory-pilot-002-runtime-disabled/62f6a321-bf6c-11f1-93d5-0ee0206d8b5f'
BUCKET='tims-software-factory-666730517561-ca-central-1'


def baseline():
    return json.loads((ROOT/'factory/evidence/pilot-002-reviewer-stage-preview.json').read_bytes())['template']


def render(current,package,code):
    if current!=baseline():raise StateError('Disabled baseline drift')
    if (package.get('source_commit')!=SOURCE or package.get('activation_sha256')!=ACTIVATION or
            package.get('role')!='inspector' or package.get('activation_authorized') is not False or
            package.get('signed_allowance_included') is not False or package.get('model_calls')!=0 or
            package.get('code_sha256')!=base64.b64encode(bytes.fromhex(package['sha256'])).decode()):
        raise StateError('Exact Inspector activation package required')
    if (set(code)!={'S3Bucket','S3Key','S3ObjectVersion'} or code['S3Bucket']!=BUCKET or
            code['S3Key']!='pilot-002/runtime/'+SOURCE+'/'+package['sha256']+'.zip' or
            not isinstance(code['S3ObjectVersion'],str) or not code['S3ObjectVersion'] or code['S3ObjectVersion']=='null'):
        raise StateError('Immutable package required')
    target=copy.deepcopy(current);f=target['Resources']['InspectorFunction']['Properties']
    f.update(Code=copy.deepcopy(code),Description='Pilot 002 exact Inspector request; one permanent attempt, no retry')
    f['Environment']['Variables']['FACTORY_PILOT002_EXECUTION_ENABLED']='true'
    f['Environment']['Variables']['FACTORY_PILOT002_ACTIVATION_SHA256']=ACTIVATION
    del f['ReservedConcurrentExecutions']
    return target


def validate(template,changes,package,code):
    if (template!=render(baseline(),package,code) or changes.get('Status')!='CREATE_COMPLETE' or
            changes.get('ExecutionStatus')!='AVAILABLE' or changes.get('NextToken') or
            changes.get('Parameters') or changes.get('StackId')!=STACK):raise StateError('Inspector preview differs')
    items=changes.get('Changes',[])
    if len(items)!=1:raise StateError('Only Inspector may change')
    item=items[0];r=item.get('ResourceChange',{})
    if (item.get('Type')!='Resource' or r.get('LogicalResourceId')!='InspectorFunction' or
            r.get('ResourceType')!='AWS::Lambda::Function' or r.get('Action')!='Modify' or r.get('Replacement')!='False'):
        raise StateError('Unexpected Inspector resource change')
    return {'status':'INSPECTOR_PREVIEW_NOT_EXECUTED','maximum_provider_calls':1,'retries':0,
        'reserved_micro_usd':250000,'reserved_lambda_concurrency':None,'iam_changes':0,'model_calls':0}
