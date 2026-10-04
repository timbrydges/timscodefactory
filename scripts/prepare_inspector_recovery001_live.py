"""Offline live-preview validator. No AWS clients, deployment, signing or invocation."""
import copy
import json
import re
from pathlib import Path

import prepare_inspector_recovery001_disabled as disabled
from build_inspector_recovery001_activation_package import validate_material
from build_inspector_recovery001_package import MATERIAL
from factory_runtime.inspector_recovery001 import TABLE,PK
from factory_runtime.inspector_recovery001_authorization import REQUEST_DIGEST
from factory_state.model import StateError
from factory_state.scope import canonical

ROOT=Path(__file__).resolve().parents[1]
STACK='arn:aws:cloudformation:ca-central-1:666730517561:stack/tims-factory-inspector-recovery-001-disabled/940599c0-bfef-11f1-8245-06ffeb34c079'
PROFILE='arn:aws:bedrock:ca-central-1:666730517561:inference-profile/global.anthropic.claude-sonnet-4-5-20250929-v1:0'
MODEL='anthropic.claude-sonnet-4-5-20250929-v1:0'


def baseline():
    proof=json.loads((ROOT/'factory/evidence/inspector-recovery-001-disabled-deployed.json').read_bytes())
    if proof['stack_id']!=STACK or proof['status']!='DEPLOYED_VERIFIED_DISABLED':raise StateError('Recovery baseline evidence differs')
    return disabled.render(proof['package'],proof['code'])


def access():
    # Same proven Inspector model restrictions; only the separate recovery key is writable.
    return {'Type':'AWS::IAM::Policy','Properties':{'PolicyName':'recovery001-own-attempt-and-inspector',
        'Roles':[disabled.ROLE],'PolicyDocument':{'Version':'2012-10-17','Statement':[
            {'Sid':'OwnRecoveryAttemptOnly','Effect':'Allow','Action':['dynamodb:PutItem','dynamodb:UpdateItem'],
             'Resource':'arn:aws:dynamodb:ca-central-1:666730517561:table/'+TABLE,
             'Condition':{'ForAllValues:StringEquals':{'dynamodb:LeadingKeys':[PK]},'Null':{'dynamodb:LeadingKeys':'false'}}},
            {'Sid':'ExactInspectorProfile','Effect':'Allow','Action':'bedrock:InvokeModel','Resource':PROFILE,
             'Condition':{'StringEquals':{'aws:RequestedRegion':'ca-central-1'}}},
            {'Sid':'RegionalModelViaProfile','Effect':'Allow','Action':'bedrock:InvokeModel',
             'Resource':'arn:aws:bedrock:ca-central-1::foundation-model/'+MODEL,
             'Condition':{'StringEquals':{'aws:RequestedRegion':'ca-central-1','bedrock:InferenceProfileArn':PROFILE}}},
            {'Sid':'GlobalModelViaProfile','Effect':'Allow','Action':'bedrock:InvokeModel',
             'Resource':'arn:aws:bedrock:::foundation-model/'+MODEL,
             'Condition':{'StringEquals':{'aws:RequestedRegion':'unspecified','bedrock:InferenceProfileArn':PROFILE}}}]}}}


def render(current,package,code,*,activation,now,shared_capacity_approved=False):
    if current!=baseline():raise StateError('Recovery disabled baseline drift')
    if shared_capacity_approved is not True:raise StateError('Exact shared-capacity approval required')
    extra={'activation_sha256','request_digest','material_expires_at','maximum_cost_micro_usd','activation_authorized'}
    if (type(package) is not dict or not extra<=set(package) or package.get('activation_included') is not True or
            package.get('activation_authorized') is not False or package.get('request_digest')!=REQUEST_DIGEST or
            type(package.get('activation_sha256')) is not str or not re.fullmatch('[0-9a-f]{64}',package['activation_sha256']) or
            type(package.get('material_expires_at')) is not int or type(package.get('maximum_cost_micro_usd')) is not int):
        raise StateError('Validated recovery activation package required')
    inert={k:v for k,v in package.items() if k not in extra};inert['activation_included']=False
    disabled.render(inert,code)  # Exact metadata schema, code hash, size, handler and immutable object.
    files={name:(ROOT/name).read_bytes() for name in MATERIAL}
    files['BUILD.json']=canonical({'source_commit':package['source_commit']})
    material=validate_material(files,activation,now)
    if material!={k:package[k] for k in extra}:raise StateError('Activation package bindings differ')
    if material['material_expires_at']-now.timestamp()<600:raise StateError('Insufficient activation time remaining')
    target=copy.deepcopy(current)
    target['Resources']['RecoveryAccess']=access()
    function=target['Resources']['RecoveryFunction']
    function['DependsOn']=['RecoveryLogs','RecoveryAccess']
    properties=function['Properties'];properties['Code']=copy.deepcopy(code)
    properties['Environment']['Variables']={'FACTORY_INSPECTOR_RECOVERY001_ENABLED':'true',
        'FACTORY_INSPECTOR_RECOVERY001_ACTIVATION_SHA256':package['activation_sha256']}
    del properties['ReservedConcurrentExecutions']
    return target


def validate(template,changes,package,code,*,activation,now,shared_capacity_approved=False):
    expected=render(baseline(),package,code,activation=activation,now=now,shared_capacity_approved=shared_capacity_approved)
    if (template!=expected or changes.get('Status')!='CREATE_COMPLETE' or changes.get('ExecutionStatus')!='AVAILABLE' or
            changes.get('NextToken') or changes.get('Parameters') or changes.get('StackId')!=STACK):
        raise StateError('Recovery live preview differs or is incomplete')
    rows=changes.get('Changes',[])
    if len(rows)!=2:raise StateError('Only recovery access and function may change')
    seen=set()
    for row in rows:
        resource=row.get('ResourceChange',{});name=resource.get('LogicalResourceId')
        if row.get('Type')!='Resource' or name in seen:raise StateError('Unexpected recovery change')
        seen.add(name)
        if name=='RecoveryAccess':
            if resource.get('Action')!='Add' or resource.get('ResourceType')!='AWS::IAM::Policy':raise StateError('Recovery access must be new')
        elif name=='RecoveryFunction':
            if (resource.get('Action')!='Modify' or resource.get('ResourceType')!='AWS::Lambda::Function' or
                    resource.get('Replacement')!='False'):raise StateError('Recovery function replacement forbidden')
        else:raise StateError('Unrelated resource change forbidden')
    return {'status':'RECOVERY_LIVE_PREVIEW_NOT_EXECUTED','maximum_provider_calls':1,'retries':0,
        'reserved_micro_usd':250000,'reserved_lambda_concurrency':None,'recovery_access_policy_additions':1,
        'original_attempt_access':False,'model_calls':0}
