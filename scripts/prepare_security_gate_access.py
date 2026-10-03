"""Offline temporary task-partition permission proposal; never applies IAM."""
import argparse
import copy
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from factory_state.model import StateError
from factory_state.scope import canonical

ROLE='tims-software-factory-autonomy-controller-disabled'
TABLE='arn:aws:dynamodb:ca-central-1:666730517561:table/tims-software-factory-state'
PARTITION='FACTORY#tims-software-factory#TASK#deterministic-text-fingerprint'
POLICY='security-gate-001-temporary-state-access'
TRUST_END=datetime(2026,10,4,13,27,36,tzinfo=timezone.utc)
LOG_POLICY={'PolicyName':'canary-logs-only','PolicyDocument':{'Version':'2012-10-17','Statement':[{
    'Effect':'Allow','Action':['logs:CreateLogStream','logs:PutLogEvents'],
    'Resource':'arn:aws:logs:ca-central-1:666730517561:log-group:/aws/lambda/tims-software-factory-autonomy-controller:*'}]}}


def digest(value): return 'sha256:'+hashlib.sha256(canonical(value)).hexdigest()


def prepare(current, *, starts_at, expires_at):
    if (starts_at.tzinfo is None or starts_at.utcoffset() is None or
            expires_at.tzinfo is None or expires_at.utcoffset() is None or
            not 0 < (expires_at-starts_at).total_seconds() <= 3600 or expires_at>TRUST_END):
        raise StateError('Security access requires at most one hour within existing key enrollment')
    try:
        role=current['Resources']['ControllerRole']
        props=role['Properties']
        function=current['Resources']['ControllerFunction']['Properties']
        if ('Transform' in current or role['Type']!='AWS::IAM::Role' or
                props['RoleName']!=ROLE or props.get('ManagedPolicyArns') or
                props['Policies']!=[LOG_POLICY] or
                props['AssumeRolePolicyDocument']!={'Version':'2012-10-17','Statement':[{
                    'Effect':'Allow','Principal':{'Service':'lambda.amazonaws.com'},'Action':'sts:AssumeRole'}]} or
                function['FunctionName']!='tims-software-factory-autonomy-controller' or
                function['Handler']!='factory_runtime.security_gate_runtime.controller_handler' or
                function['Role']!={'Fn::GetAtt':['ControllerRole','Arn']} or
                function['Environment']['Variables'].get('FACTORY_AUTONOMY_CONTROLLER_ENABLED')!='false' or
                function['Environment']['Variables'].get('FACTORY_SECURITY_GATE_ENABLED')!='false' or
                function.get('ReservedConcurrentExecutions')!=0):
            raise StateError('Security access baseline is not the blocked logging-only controller')
    except (KeyError,TypeError):
        raise StateError('Security access template baseline malformed') from None
    policy={'PolicyName':POLICY,'PolicyDocument':{'Version':'2012-10-17','Statement':[{
        'Effect':'Allow','Action':['dynamodb:GetItem','dynamodb:PutItem','dynamodb:UpdateItem'],
        'Resource':TABLE,'Condition':{
            'ForAllValues:StringEquals':{'dynamodb:LeadingKeys':[PARTITION]},
            'Null':{'dynamodb:LeadingKeys':'false'},
            'DateGreaterThanEquals':{'aws:CurrentTime':starts_at.astimezone(timezone.utc).isoformat()},
            'DateLessThan':{'aws:CurrentTime':expires_at.astimezone(timezone.utc).isoformat()}}}]}}
    proposed=copy.deepcopy(current)
    proposed['Resources']['ControllerRole']['Properties']['Policies'].append(policy)
    return {'status':'PREPARED_NOT_AUTHORIZED','role_name':ROLE,
        'starts_at':starts_at.isoformat(),'expires_at':expires_at.isoformat(),
        'before_digest':digest(current),'after_digest':digest(proposed),
        'policy':policy,'template':proposed,'restore_template':copy.deepcopy(current),
        'scope':'Only this task partition; no delete, scan, model, secret, KMS or Lambda invocation permissions',
        'requires':'Explicit owner approval before granting temporary state access; remove it after the bounded operation'}


def validate_changes(plan, current, proposed, changes, *, current_parameters, reverse=False):
    expected=prepare(plan['restore_template'],starts_at=datetime.fromisoformat(plan['starts_at']),
                     expires_at=datetime.fromisoformat(plan['expires_at']))
    before,after=(expected['template'],expected['restore_template']) if reverse else (expected['restore_template'],expected['template'])
    if canonical(plan)!=canonical(expected) or canonical(current)!=canonical(before) or canonical(proposed)!=canonical(after):
        raise StateError('Security access proposal or actual template drifted')
    if (changes.get('Status')!='CREATE_COMPLETE' or changes.get('ExecutionStatus')!='AVAILABLE' or
            changes.get('NextToken') or not isinstance(changes.get('StackId'),str) or
            not changes['StackId'].startswith('arn:aws:cloudformation:ca-central-1:666730517561:stack/tims-factory-autonomy-controller-disabled/')):
        raise StateError('Security access change set is incomplete or targets another stack')
    parameters=changes.get('Parameters',[])
    if (len(parameters)!=len(current_parameters) or
            {p.get('ParameterKey') for p in parameters}!=set(current_parameters) or
            any(p.get('ParameterValue')!=current_parameters[p['ParameterKey']] for p in parameters)):
        raise StateError('Security access must preserve all deployed parameter values')
    entries=changes.get('Changes',[]); seen=set()
    if not 1<=len(entries)<=2:
        raise StateError('Security access changes unexpected resources')
    for change in entries:
        rc=change.get('ResourceChange',{}); name=rc.get('LogicalResourceId')
        allowed={'ControllerRole':('AWS::IAM::Role','Policies'),
                 'ControllerFunction':('AWS::Lambda::Function','Role')}
        if name not in allowed or name in seen:
            raise StateError('Security access changes unexpected or duplicate resource')
        seen.add(name); kind,prop=allowed[name]
        if (change.get('Type')!='Resource' or rc.get('Action')!='Modify' or
                rc.get('ResourceType')!=kind or rc.get('Replacement')!='False' or
                rc.get('Scope')!=['Properties'] or not rc.get('Details') or
                any(d.get('Target',{}).get('Attribute')!='Properties' or
                    d['Target'].get('Name')!=prop or d['Target'].get('RequiresRecreation')!='Never' for d in rc['Details'])):
            raise StateError('Security access change exceeds exact inline-policy boundary')
    if 'ControllerRole' not in seen:
        raise StateError('Security access role change missing')
    return {'status':'VALIDATED_NOT_EXECUTED','reverse':reverse,'after_digest':digest(after)}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('current_template',type=Path); parser.add_argument('output',type=Path)
    parser.add_argument('--starts-at',required=True); parser.add_argument('--expires-at',required=True)
    args=parser.parse_args()
    proposal=prepare(json.loads(args.current_template.read_bytes()),starts_at=datetime.fromisoformat(args.starts_at),expires_at=datetime.fromisoformat(args.expires_at))
    with args.output.open('x',encoding='utf-8') as output:
        json.dump(proposal,output,indent=2); output.write('\n')
    print('PREPARED_NOT_AUTHORIZED: no IAM, state, signing or provider call')
