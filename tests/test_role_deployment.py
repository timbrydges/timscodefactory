import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(ROOT/'src'))
from factory_runtime.lambda_role import handle_probe, handle_transport
from factory_state.kms_signer import SIGNERS
from factory_state.scope import SignedScopeStore
from factory_state.model import StateError
from scripts.scope_dispatch_canary import fixture_keys, sign
from scripts.prepare_role_deployment import validate_changes
from scripts.prepare_role_transport_canary import validate_changes as validate_transport_changes
from test_dispatch_ledger import NOW


class RoleDeploymentTests(unittest.TestCase):
    class ConditionalFailure(Exception):
        response = {'Error': {'Code': 'ConditionalCheckFailedException'}}

    class MemoryTable:
        def __init__(self): self.items = {}; self.puts = 0
        @staticmethod
        def key(item): return item['PK']['S'], item['SK']['S']
        def put_item(self, **request):
            key = self.key(request['Item'])
            if key in self.items: raise RoleDeploymentTests.ConditionalFailure()
            self.items[key] = dict(request['Item']); self.puts += 1
        def get_item(self, **request): return {'Item': dict(self.items[self.key(request['Key'])])}
        def update_item(self, **request):
            item = self.items[self.key(request['Key'])]
            values = request['ExpressionAttributeValues']
            if item['status'] != values[':started'] or item['event_digest'] != values[':digest']:
                raise AssertionError('conditional update mismatch')
            item['status'], item['response'] = values[':done'], values[':response']

    def test_execution_roles_cannot_write_controller_state_or_sign_directly(self):
        template = json.loads((ROOT/'infra/roles/functions.cloudformation.json').read_text())
        self.assertEqual(len(template['Resources']), 14)
        for role in ('planner','builder','inspector'):
            resources = template['Resources']; name = role.title()
            statements = resources[name+'Role']['Properties']['Policies'][0]['PolicyDocument']['Statement']
            reads = next(s for s in statements if s['Sid']=='CanaryStateReadAndConditionsOnly')
            writes = next(s for s in statements if s['Sid']=='OwnExecutionRecordsOnly')
            self.assertEqual(set(reads['Action']), {'dynamodb:GetItem','dynamodb:ConditionCheckItem'})
            self.assertEqual(writes['Resource'], {'Fn::GetAtt':['RoleExecutions','Arn']})
            self.assertEqual(writes['Condition']['ForAllValues:StringLike']['dynamodb:LeadingKeys'],
                [f'ROLE#{SIGNERS[role]}#FACTORY#tims-software-factory#TASK#cloud-role-canary-*'])
            self.assertFalse(any(a.startswith(('kms:','bedrock:','iam:')) for s in statements for a in s['Action']))
            props = resources[name+'Function']['Properties']
            self.assertEqual(props['Timeout'],60)
            self.assertNotIn('ReservedConcurrentExecutions',props)
            self.assertEqual(props['Environment']['Variables']['EXECUTION_TABLE'],
                             {'Ref':'RoleExecutions'})
        self.assertFalse(any(v['Type']=='AWS::Lambda::Url' for v in template['Resources'].values()))

    def test_signing_trust_excludes_owner_and_is_exact_role_and_disabled_by_default(self):
        t = json.loads((ROOT/'infra/signing/keys.cloudformation.json').read_text())
        self.assertEqual(t['Parameters']['EnableRoleExecutionTrust']['Default'],'false')
        self.assertEqual(len(t['Resources']['OwnerRole']['Properties']['AssumeRolePolicyDocument']['Statement']),1)
        for role in ('planner','builder','inspector'):
            statement=t['Resources'][role.title()+'Role']['Properties']['AssumeRolePolicyDocument']['Statement'][1]['Fn::If'][1]
            self.assertEqual(statement['Condition']['ArnEquals']['aws:PrincipalArn'],
                             f'arn:aws:iam::666730517561:role/tims-factory-executor-{role}')

    def test_probe_is_fixed_kind_and_cannot_sign_task_or_owner_approval(self):
        with tempfile.TemporaryDirectory() as directory:
            keys, private = fixture_keys(directory, tuple(SIGNERS.values()))
            class Signer:
                identity = SIGNERS['builder']
                def sign(self,payload,*,now): return sign(payload,private[self.identity],directory)
            event={'kind':'identity_probe','source_commit':'a'*40,'nonce':'b'*32}
            with patch('factory_state.scope.shutil.which',return_value=None):
                proof=handle_probe(event,role='builder',commit='a'*40,signer=Signer(),now=NOW)
                verifier=SignedScopeStore('unused',None,keys)
                import base64
                sig=base64.b64decode(proof['signature_base64'])
                verifier._verify(proof['payload'],sig,SIGNERS['builder'],NOW)
                with self.assertRaises(StateError): verifier._verify({**proof['payload'],'nonce':'changed'},sig,SIGNERS['builder'],NOW)
            for changed in ({**event,'kind':'capability'}, {**event,'source_commit':'c'*40}, {**event,'payload':{}}):
                with self.assertRaises(StateError): handle_probe(changed,role='builder',commit='a'*40,signer=Signer(),now=NOW)
            self.assertFalse(proof['operational_execution_enabled'])

    def test_transport_canary_is_signed_durable_and_replay_safe(self):
        with tempfile.TemporaryDirectory() as directory:
            keys, private = fixture_keys(directory, tuple(SIGNERS.values()))
            class Signer:
                identity = SIGNERS['planner']
                def sign(self,payload,*,now): return sign(payload,private[self.identity],directory)
            database = self.MemoryTable()
            import base64
            event={'kind':'transport_canary','source_commit':'a'*40,'nonce':'b'*32,
                   'input_base64':base64.b64encode(b'model-free transport').decode()}
            result=handle_transport(event,role='planner',commit='a'*40,signer=Signer(),now=NOW,
                                    database=database,table='executions')
            replay=handle_transport(event,role='planner',commit='a'*40,signer=Signer(),now=NOW,
                                    database=database,table='executions')
            self.assertEqual(replay,result);self.assertEqual(database.puts,1)
            self.assertEqual(result['model_calls'],0);self.assertFalse(result['operational_execution_enabled'])
            SignedScopeStore('unused',None,keys)._verify(result['payload'],
                base64.b64decode(result['signature_base64']),SIGNERS['planner'],NOW)
            item=next(iter(database.items.values()))
            self.assertEqual(item['status'],{'S':'COMPLETE'})
            with self.assertRaises(StateError):
                handle_transport({**event,'input_base64':base64.b64encode(b'changed').decode()},
                    role='planner',commit='a'*40,signer=Signer(),now=NOW,database=database,table='executions')

    def test_change_set_rejects_key_mutation_and_role_replacement(self):
        changes=[{'ResourceChange':{'LogicalResourceId':r+'Role','Action':'Modify','Replacement':'False'}}
                 for r in ('Planner','Builder','Inspector')]
        validate_changes('tims-factory-signing',changes)
        changes[0]['ResourceChange']['Replacement']='True'
        with self.assertRaises(RuntimeError):validate_changes('tims-factory-signing',changes)
        changes[0]['ResourceChange'].update(LogicalResourceId='OwnerKey',Replacement='False')
        with self.assertRaises(RuntimeError):validate_changes('tims-factory-signing',changes)

    def test_transport_change_set_is_exact_and_replaces_only_versions(self):
        changes=[]
        for role in ('Planner','Builder','Inspector'):
            changes.extend([{'ResourceChange':{'LogicalResourceId':role+'Function','Action':'Modify','Replacement':'False'}},
                            {'ResourceChange':{'LogicalResourceId':role+'Version','Action':'Modify','Replacement':'True'}}])
        changes.append({'ResourceChange':{'LogicalResourceId':'ControllerInvoke','Action':'Modify','Replacement':'False'}})
        validate_transport_changes(changes)
        changes[0]['ResourceChange']['Replacement']='True'
        with self.assertRaises(RuntimeError):validate_transport_changes(changes)
