"""Offline five-resource disabled broker template; no permission is applied."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from factory_runtime.google_qa_boundary import ACTIVATION, FLAG, TABLE

NAME = 'tims-factory-google-qa-broker'
SECRET_ARN = 'arn:aws:secretsmanager:ca-central-1:666730517561:secret:tims-software-factory/provider/google/qa-rYGeOE'
SECRET_VERSION = 'db69f4bf-38c0-43d5-8bbf-ce20d8e07282'


def render():
    return {'AWSTemplateFormatVersion': '2010-09-09',
        'Description': 'Disabled Google QA broker. Pending owner permission approval; no live model path.',
        'Parameters': {'ArtifactBucket': {'Type': 'String', 'AllowedValues': [
            'tims-software-factory-666730517561-ca-central-1']},
            **{p: {'Type': 'String'} for p in ('ArtifactKey', 'ArtifactVersion', 'CodeSha256')}},
        'Resources': {
            'Attempts': {'Type': 'AWS::DynamoDB::Table', 'DeletionPolicy': 'Retain',
                'UpdateReplacePolicy': 'Retain', 'Properties': {'TableName': TABLE,
                    'BillingMode': 'PAY_PER_REQUEST', 'DeletionProtectionEnabled': True,
                    'AttributeDefinitions': [{'AttributeName': n, 'AttributeType': 'S'} for n in ('PK','SK')],
                    'KeySchema': [{'AttributeName':'PK','KeyType':'HASH'}, {'AttributeName':'SK','KeyType':'RANGE'}],
                    'SSESpecification': {'SSEEnabled': True}}},
            'Logs': {'Type': 'AWS::Logs::LogGroup', 'Properties': {
                'LogGroupName': '/aws/lambda/' + NAME, 'RetentionInDays': 14}},
            'Role': {'Type': 'AWS::IAM::Role', 'Properties': {'RoleName': NAME,
                'AssumeRolePolicyDocument': {'Version':'2012-10-17','Statement': [{
                    'Effect':'Allow','Principal':{'Service':'lambda.amazonaws.com'},'Action':'sts:AssumeRole'}]},
                'Policies': [{'PolicyName':'ExactGoogleCredentialAndAttemptOnly', 'PolicyDocument': {
                    'Version':'2012-10-17', 'Statement': [
                        {'Effect':'Allow','Action':['secretsmanager:GetSecretValue'],'Resource':SECRET_ARN,
                         'Condition': {'ForAnyValue:StringEquals': {'secretsmanager:VersionStage':'AWSCURRENT'}}},
                        {'Effect':'Allow','Action':['dynamodb:PutItem','dynamodb:GetItem','dynamodb:UpdateItem'],
                         'Resource': {'Fn::GetAtt':['Attempts','Arn']},
                         'Condition': {'ForAllValues:StringEquals': {'dynamodb:LeadingKeys':['GOOGLE_QA#'+ACTIVATION]}}},
                        {'Effect':'Allow','Action':['logs:CreateLogStream','logs:PutLogEvents'],
                         'Resource':'arn:aws:logs:ca-central-1:666730517561:log-group:/aws/lambda/'+NAME+':*'}]}}]}},
            'Function': {'Type':'AWS::Lambda::Function','DependsOn':['Logs'],'Properties': {
                'FunctionName':NAME,'Runtime':'python3.12','Architectures':['x86_64'],
                'Handler':'factory_runtime.google_qa_boundary.handler','Timeout':120,'MemorySize':128,
                'ReservedConcurrentExecutions':1,'Role':{'Fn::GetAtt':['Role','Arn']},
                'Code': {'S3Bucket':{'Ref':'ArtifactBucket'}, 'S3Key':{'Ref':'ArtifactKey'},
                         'S3ObjectVersion':{'Ref':'ArtifactVersion'}},
                'Environment': {'Variables': {FLAG:'false','FACTORY_GOOGLE_SECRET_ARN':SECRET_ARN,
                    'FACTORY_GOOGLE_SECRET_VERSION':SECRET_VERSION,'FACTORY_GOOGLE_ATTEMPTS_TABLE':TABLE}}}},
            'Version': {'Type':'AWS::Lambda::Version','Properties': {
                'FunctionName':{'Ref':'Function'},'CodeSha256':{'Ref':'CodeSha256'}}}},
        'Outputs': {'VersionArn': {'Value':{'Ref':'Version'}},
                    'RoleArn': {'Value':{'Fn::GetAtt':['Role','Arn']}}}}


if __name__ == '__main__':
    with Path(sys.argv[1]).open('x', encoding='utf-8', newline='\n') as stream:
        stream.write(json.dumps(render(),indent=2)+'\n')
    print('PREPARED_ONLY: five new resources, no deployment or model calls')
