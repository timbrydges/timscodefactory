"""Offline table-only proposal; no AWS clients, IAM grants or deployment."""
import json
import sys
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from factory_runtime.qa_recovery002 import TABLE
from factory_state.model import StateError

STACK = 'tims-factory-qa-recovery-002-attempts'


def render():
    return {'AWSTemplateFormatVersion':'2010-09-09',
        'Description':'Separate permanent QA recovery hold. No live authority or runtime access.',
        'Resources':{'RecoveryAttempt':{'Type':'AWS::DynamoDB::Table',
            'DeletionPolicy':'Retain','UpdateReplacePolicy':'Retain','Properties':{
                'TableName':TABLE,'BillingMode':'PAY_PER_REQUEST','DeletionProtectionEnabled':True,
                'AttributeDefinitions':[{'AttributeName':'PK','AttributeType':'S'}],
                'KeySchema':[{'AttributeName':'PK','KeyType':'HASH'}],
                'SSESpecification':{'SSEEnabled':True}}}}}


def validate_changes(template, change_set):
    prefix='arn:aws:cloudformation:ca-central-1:666730517561:stack/'+STACK+'/'
    if (template!=render() or change_set.get('Status')!='CREATE_COMPLETE' or
            change_set.get('ExecutionStatus')!='AVAILABLE' or change_set.get('NextToken') or
            change_set.get('Parameters') or not str(change_set.get('StackId','')).startswith(prefix)):
        raise StateError('Recovery table preview differs or is incomplete')
    changes=change_set.get('Changes',[])
    if len(changes)!=1:
        raise StateError('Recovery preview must add exactly one table')
    row=changes[0];resource=row.get('ResourceChange',{})
    if (row.get('Type')!='Resource' or resource.get('LogicalResourceId')!='RecoveryAttempt' or
            resource.get('ResourceType')!='AWS::DynamoDB::Table' or resource.get('Action')!='Add'):
        raise StateError('Recovery preview must only add its separate table')
    return {'status':'VALIDATED_NOT_EXECUTED','model_calls':0,'iam_grants':0}


if __name__=='__main__':
    with Path(sys.argv[1]).open('x',encoding='utf-8') as stream:
        stream.write(json.dumps(render(),indent=2)+'\n')
    print('PREPARED_NOT_EXECUTED: separate table only; no IAM or model access')
