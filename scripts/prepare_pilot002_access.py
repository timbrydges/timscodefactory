"""Prepare three exact runtime policies while preserving disabled Lambda resources."""
import copy
import hashlib
import json
from pathlib import Path
import sys

from prepare_pilot002_runtime import ACCOUNT, REGION, STACK, ROLES, render as foundation
from factory_state.model import StateError

ROOT=Path(__file__).resolve().parents[1]
BASELINE_SHA='abce76e0db170fa2296dbec6c60fdbfd0287058b410e827717b446777f236dac'
SECRETS={
    'builder':f'arn:aws:secretsmanager:{REGION}:{ACCOUNT}:secret:tims-software-factory/provider/openai/acceptance-WE57Tw',
    'qa':f'arn:aws:secretsmanager:{REGION}:{ACCOUNT}:secret:tims-software-factory/provider/google/qa-rYGeOE'}
MODEL='anthropic.claude-sonnet-4-5-20250929-v1:0'
PROFILE=f'arn:aws:bedrock:{REGION}:{ACCOUNT}:inference-profile/global.{MODEL}'
TABLE=f'arn:aws:dynamodb:{REGION}:{ACCOUNT}:table/tims-factory-pilot-002-attempts'
BUILDER_KEY=f'arn:aws:kms:{REGION}:{ACCOUNT}:key/134908eb-251f-443a-bfa0-f83d8f04c36c'
BUILDER_VERSION='ebb6cc21-2df9-4b06-8f55-2b0661f27f69'


def baseline():
    proof=json.loads((ROOT/'factory/evidence/pilot-002-disabled-runtime-preview.json').read_bytes())
    template=foundation(source_commit=proof['source_commit'],code=proof['code'])
    if hashlib.sha256(json.dumps(template,sort_keys=True).encode()).hexdigest()!=BASELINE_SHA:
        raise StateError('Pilot 002 reviewed foundation changed')
    return template


def policy(role):
    if role not in ROLES:raise StateError('Pilot 002 role invalid')
    statements=[{'Sid':'OwnPermanentAttemptOnly','Effect':'Allow','Action':['dynamodb:PutItem','dynamodb:UpdateItem'],
        'Resource':TABLE,'Condition':{'ForAllValues:StringEquals':{
            'dynamodb:LeadingKeys':[f'PILOT#002#TASK#safe-workspace-fingerprint-001#ROLE#{role}']},
            'Null':{'dynamodb:LeadingKeys':'false'}}}]
    if role in SECRETS:
        statements.append({'Sid':'ExactExistingProviderSecret','Effect':'Allow',
            'Action':'secretsmanager:GetSecretValue','Resource':SECRETS[role]})
        if role=='builder':
            statements.append({'Sid':'DecryptExactBuilderVersionThroughSecretsManager','Effect':'Allow',
                'Action':'kms:Decrypt','Resource':BUILDER_KEY,'Condition':{'StringEquals':{
                    'kms:ViaService':f'secretsmanager.{REGION}.amazonaws.com',
                    'kms:EncryptionContext:SecretARN':SECRETS[role],
                    'kms:EncryptionContext:SecretVersionId':BUILDER_VERSION}}})
    else:
        for sid,resource,region,profile_condition in (
            ('ExactInspectorProfile',PROFILE,REGION,False),
            ('RegionalModelViaProfile',f'arn:aws:bedrock:{REGION}::foundation-model/{MODEL}',REGION,True),
            ('GlobalModelViaProfile',f'arn:aws:bedrock:::foundation-model/{MODEL}','unspecified',True)):
            conditions={'aws:RequestedRegion':region}
            if profile_condition:conditions['bedrock:InferenceProfileArn']=PROFILE
            statements.append({'Sid':sid,'Effect':'Allow','Action':'bedrock:InvokeModel',
                'Resource':resource,'Condition':{'StringEquals':conditions}})
    return {'Version':'2012-10-17','Statement':statements}


def render(current):
    if current!=baseline():raise StateError('Pilot 002 current foundation differs; reconcile before access changes')
    template=copy.deepcopy(current)
    template['Description']='Pilot 002 disabled runtime with scoped provider and permanent-attempt policies; no activation.'
    for role in ROLES:
        template['Resources'][role.title()+'Access']={'Type':'AWS::IAM::Policy','Properties':{
            'PolicyName':'pilot002-own-attempt-and-provider',
            'Roles':['tims-factory-pilot-002-'+role+'-disabled'],'PolicyDocument':policy(role)}}
    return template


def validate_changes(template, change_set):
    if (template!=render(baseline()) or change_set.get('Status')!='CREATE_COMPLETE' or
            change_set.get('ExecutionStatus')!='AVAILABLE' or change_set.get('NextToken') or
            change_set.get('Parameters') or not str(change_set.get('StackId','')).startswith(
                f'arn:aws:cloudformation:{REGION}:{ACCOUNT}:stack/{STACK}/')):
        raise StateError('Pilot 002 access preview differs or is incomplete')
    changes=change_set.get('Changes',[]);names=[x.get('ResourceChange',{}).get('LogicalResourceId') for x in changes]
    if len(names)!=3 or set(names)!={role.title()+'Access' for role in ROLES}:
        raise StateError('Pilot 002 access preview must add exactly three policies')
    for item in changes:
        change=item['ResourceChange']
        if item.get('Type')!='Resource' or change.get('Action')!='Add' or change.get('ResourceType')!='AWS::IAM::Policy':
            raise StateError('Pilot 002 access preview cannot modify existing resources')
    return {'status':'ACCESS_PREVIEW_VALIDATED_NOT_EXECUTED','new_policies':3,'existing_resources_changed':0,
        'execution_enabled':False,'reserved_concurrency':0,'provider_calls':0}


if __name__=='__main__':
    current=json.loads(Path(sys.argv[1]).read_bytes())
    with Path(sys.argv[2]).open('x',encoding='utf-8') as stream:json.dump(render(current),stream,indent=2)
    print('ACCESS_PREPARED_NOT_AUTHORIZED: three policies; all functions remain disabled')
