"""Offline exact-task bootstrap templates. Never grants IAM or invokes Lambda."""
import copy
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from factory_runtime import pilot002_bootstrap as boot
from factory_state.model import StateError
from prepare_security_gate_access import LOG_POLICY, ROLE, TABLE


def prepare(current, *, commit, code, starts_at, expires_at, nonce):
    boot.facts(ROOT)
    if (not isinstance(commit,str) or not re.fullmatch('[0-9a-f]{40}',commit) or
        type(starts_at) is not int or type(expires_at) is not int or not 0<expires_at-starts_at<=3600 or
        not isinstance(nonce,str) or not re.fullmatch('[0-9a-f]{32}',nonce) or
        not isinstance(code,dict) or set(code)!={'S3Bucket','S3Key','S3ObjectVersion'} or
        any(not isinstance(v,str) or not v for v in code.values())):
        raise StateError('Bootstrap requires exact source, immutable S3 object version and bounded window')
    try:
        role=current['Resources']['ControllerRole']['Properties']
        fn=current['Resources']['ControllerFunction']['Properties']
        env=fn['Environment']['Variables']
        if ('Transform' in current or role['RoleName']!=ROLE or role['Policies']!=[LOG_POLICY] or
            role.get('ManagedPolicyArns') or fn['FunctionName']!='tims-software-factory-autonomy-controller' or
            fn['Role']!={'Fn::GetAtt':['ControllerRole','Arn']} or
            fn['Handler']!='factory_runtime.security_gate_runtime.controller_handler' or
            fn.get('ReservedConcurrentExecutions')!=0 or
            any(env.get(k,'false')!='false' for k in ('FACTORY_SECURITY_GATE_ENABLED','FACTORY_QA_GATE_ENABLED',boot.ENABLED)) or
            env.get('FACTORY_AUTONOMY_CONTROLLER_ENABLED')!='false' or
            role['AssumeRolePolicyDocument']!={'Version':'2012-10-17','Statement':[{
                'Effect':'Allow','Principal':{'Service':'lambda.amazonaws.com'},'Action':'sts:AssumeRole'}]}):
            raise StateError('Bootstrap baseline must be the disabled logging-only Security controller')
    except (KeyError,TypeError):
        raise StateError('Bootstrap baseline malformed') from None
    config={'approved':True,'owner_identity':'tim_brydges','operation':'pilot-002-bootstrap',
        'source_commit':commit,'task_id':boot.TASK,'contract_sha256':boot.PINNED[boot.CONTRACT],
        'not_before':starts_at,'expires_at':expires_at,'nonce':nonce}
    disabled=copy.deepcopy(current)
    props=disabled['Resources']['ControllerFunction']['Properties']
    props['Code']=copy.deepcopy(code); props['Handler']='factory_runtime.pilot002_bootstrap.handler'
    props['Environment']['Variables'].update({boot.ENABLED:'false',boot.CONFIG:json.dumps(config,sort_keys=True)})
    active=copy.deepcopy(disabled)
    active['Resources']['ControllerFunction']['Properties']['Environment']['Variables'][boot.ENABLED]='true'
    active['Resources']['ControllerFunction']['Properties']['ReservedConcurrentExecutions']=1
    iso=lambda value:datetime.fromtimestamp(value,timezone.utc).isoformat()
    policy={'PolicyName':'pilot-002-bootstrap-temporary','PolicyDocument':{'Version':'2012-10-17','Statement':[{
        'Effect':'Allow','Action':['dynamodb:GetItem','dynamodb:PutItem'],'Resource':TABLE,
        'Condition':{'ForAllValues:StringEquals':{'dynamodb:LeadingKeys':[boot.PARTITION]},
            'Null':{'dynamodb:LeadingKeys':'false'},
            'DateGreaterThanEquals':{'aws:CurrentTime':iso(starts_at)},
            'DateLessThan':{'aws:CurrentTime':iso(expires_at)}}}]}}
    active['Resources']['ControllerRole']['Properties']['Policies'].append(policy)
    return {'status':'PREPARED_NOT_AUTHORIZED','source_commit':commit,'config':config,
        'baseline_sha256':hashlib.sha256(json.dumps(current,sort_keys=True).encode()).hexdigest(),
        'disabled_template':disabled,'active_template':active,'restore_template':disabled,
        'rollback_template':copy.deepcopy(current),'temporary_policy':policy,
        'event':{'kind':'bootstrap_pilot_002','source_commit':commit,'task_id':boot.TASK,'nonce':nonce},
        'expected_items':boot.items(config),'maximum_invocations':1,'model_calls':0,
        'production_release_authorized':False,
        'requires':'Owner approval and exact change-set review before permission grant or activation'}


def validate_changes(plan, current, proposed, change_set, *, parameters, phase):
    config=plan['config']
    rebuilt=prepare(plan['rollback_template'],commit=plan['source_commit'],
        code=plan['disabled_template']['Resources']['ControllerFunction']['Properties']['Code'],
        starts_at=config['not_before'],expires_at=config['expires_at'],nonce=config['nonce'])
    if json.dumps(plan,sort_keys=True)!=json.dumps(rebuilt,sort_keys=True):
        raise StateError('Bootstrap proposal drifted')
    phases={'deploy':('rollback_template','disabled_template'),
            'activate':('disabled_template','active_template'),'restore':('active_template','restore_template')}
    if phase not in phases:raise StateError('Unknown bootstrap deployment phase')
    before,after=(plan[k] for k in phases[phase])
    if current!=before or proposed!=after:raise StateError('Bootstrap actual templates differ')
    prefix='arn:aws:cloudformation:ca-central-1:666730517561:stack/tims-factory-autonomy-controller-disabled/'
    if (change_set.get('Status')!='CREATE_COMPLETE' or change_set.get('ExecutionStatus')!='AVAILABLE' or
        change_set.get('NextToken') or not str(change_set.get('StackId','')).startswith(prefix)):
        raise StateError('Bootstrap change set incomplete or wrong stack')
    actual=change_set.get('Parameters',[])
    if len(actual)!=len(parameters) or {p['ParameterKey']:p.get('ParameterValue') for p in actual}!=parameters:
        raise StateError('Bootstrap must preserve stack parameters')
    allowed={'ControllerFunction':('AWS::Lambda::Function',{'Code','Handler','Environment'})} if phase=='deploy' else {
        'ControllerRole':('AWS::IAM::Role',{'Policies'}),
        'ControllerFunction':('AWS::Lambda::Function',{'Environment','ReservedConcurrentExecutions','Role'})}
    changes=change_set.get('Changes',[]); seen=set()
    for entry in changes:
        resource=entry.get('ResourceChange',{}); name=resource.get('LogicalResourceId')
        if name not in allowed or name in seen:raise StateError('Bootstrap changes unexpected resources')
        seen.add(name); kind,props=allowed[name]
        if (entry.get('Type')!='Resource' or resource.get('Action')!='Modify' or
            resource.get('ResourceType')!=kind or resource.get('Replacement')!='False' or
            resource.get('Scope')!=['Properties'] or not resource.get('Details') or
            any(d.get('Target',{}).get('Attribute')!='Properties' or
                d['Target'].get('Name') not in props or d['Target'].get('RequiresRecreation')!='Never'
                for d in resource['Details'])):
            raise StateError('Bootstrap change exceeds reviewed properties')
    if seen!=set(allowed):raise StateError('Bootstrap expected changes missing')
    return {'status':'VALIDATED_NOT_EXECUTED','phase':phase}


if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input',type=Path); parser.add_argument('output',type=Path)
    args=parser.parse_args(); options=json.loads(args.input.read_text())
    current=options.pop('current_template')
    plan=prepare(current,**options)
    with args.output.open('x',encoding='utf-8') as stream: json.dump(plan,stream,indent=2)
    print('PREPARED_NOT_AUTHORIZED: no AWS calls, permission grants or task writes')
