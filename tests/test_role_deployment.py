import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(ROOT/'src'))
from factory_runtime.lambda_role import (handle_operational_boundary_probe,
                                         handle_probe, handle_transport)
from factory_runtime.live_provider_activation import validate_live_provider_preparation
from factory_state.kms_signer import SIGNERS
from factory_state.scope import SignedScopeStore
from factory_state.model import StateError
from scripts.scope_dispatch_canary import fixture_keys, sign
from scripts.prepare_role_deployment import validate_changes
from scripts.prepare_role_transport_canary import (
    validate_changes as validate_transport_changes, validate_existing_stack,
    verify_operational_boundary)
from scripts.prepare_builder_acceptance_iam import (
    validate_changes as validate_builder_iam_changes,
    validate_deployed_template as validate_builder_deployed_template,
    validate_template as validate_builder_iam_template)
from scripts import prepare_builder_acceptance_iam as builder_iam
from scripts.build_role_package import contract_paths
from test_dispatch_ledger import NOW


class RoleDeploymentTests(unittest.TestCase):
    def test_transport_preparation_accepts_completed_prior_update_only(self):
        parameters = [
            {'ParameterKey': 'EnableBuilderAcceptanceIam', 'ParameterValue': 'true'},
            {'ParameterKey': 'EnableInspectorAcceptanceIam', 'ParameterValue': 'true'},
        ]
        for status in ('CREATE_COMPLETE', 'UPDATE_COMPLETE'):
            validate_existing_stack({'StackStatus': status, 'Parameters': parameters})
        for status in ('UPDATE_IN_PROGRESS', 'UPDATE_ROLLBACK_COMPLETE',
                       'UPDATE_COMPLETE_CLEANUP_IN_PROGRESS'):
            with self.assertRaises(RuntimeError):
                validate_existing_stack({'StackStatus': status, 'Parameters': parameters})

    def test_deployment_verifier_requires_exact_signed_disabled_boundary(self):
        class Verifier:
            def __init__(self): self.calls = []
            def _verify(self, payload, signature, identity, now):
                self.calls.append((payload, signature, identity, now))
        payload = {'kind':'operational_boundary_attestation',
            'producer_identity':SIGNERS['builder'],'source_commit':'a'*40,
            'nonce':'boundary-probe-1234','task_id':'deterministic-text-fingerprint',
            'target_alias':'coding_primary_sol_live','model_id':'gpt-5.6-sol',
            'maximum_cost_usd_per_call':'0.25','maximum_provider_calls':3,
            'maximum_request_bytes':42020,'provider_credentials_in_role':False,
            'operational_execution_enabled':False,
            'purpose':'operational-boundary-deployment-verification-only',
            'issued_at':int(NOW.timestamp()),'expires_at':int(NOW.timestamp())+300}
        proof = {'payload':payload,'signature_base64':'cw==' ,'model_calls':0,
                 'operational_execution_enabled':False}
        verifier = Verifier()
        self.assertEqual(verify_operational_boundary(proof, commit='a'*40,
            nonce='boundary-probe-1234', verifier=verifier, now=NOW), payload)
        self.assertEqual(verifier.calls[0][1:], (b's', SIGNERS['builder'], NOW))
        with self.assertRaises(RuntimeError):
            verify_operational_boundary({**proof, 'model_calls':1}, commit='a'*40,
                nonce='boundary-probe-1234', verifier=verifier, now=NOW)
        with self.assertRaises(RuntimeError):
            verify_operational_boundary({**proof, 'payload':{**payload,
                'model_id':'other-model'}}, commit='a'*40,
                nonce='boundary-probe-1234', verifier=verifier, now=NOW)

    def test_operational_boundary_probe_is_builder_only_signed_and_model_free(self):
        class Signer:
            identity = SIGNERS['builder']
            def sign(self, payload, *, now): return b's' * 64
        event = {'kind':'operational_boundary_probe','source_commit':'a'*40,
                 'nonce':'boundary-probe-1234','task_id':'deterministic-text-fingerprint'}
        proof = handle_operational_boundary_probe(
            event, role='builder', commit='a'*40, signer=Signer(), now=NOW)
        payload = proof['payload']
        self.assertEqual(payload['target_alias'], 'coding_primary_sol_live')
        self.assertEqual(payload['model_id'], 'gpt-5.6-sol')
        self.assertEqual(payload['maximum_cost_usd_per_call'], '0.25')
        self.assertEqual(payload['maximum_provider_calls'], 3)
        self.assertEqual(payload['maximum_request_bytes'], 42020)
        self.assertFalse(payload['provider_credentials_in_role'])
        self.assertFalse(proof['operational_execution_enabled'])
        self.assertEqual(proof['model_calls'], 0)
        with self.assertRaises(StateError):
            handle_operational_boundary_probe(
                event, role='planner', commit='a'*40, signer=Signer(), now=NOW)

    def test_disabled_builder_probe_loads_packaged_contract_and_rejects_activation(self):
        class Signer:
            identity = SIGNERS['builder']
            def sign(self, payload, *, now): return b's' * 64
        event = {'kind':'operational_boundary_probe','source_commit':'a'*40,
                 'nonce':'boundary-probe-1234','task_id':'deterministic-text-fingerprint'}
        paths = contract_paths()
        self.assertIn('factory/autonomy/operating-contract.yaml', paths)
        self.assertTrue({
            'factory/profiles/provider-live-activation.yaml',
            'factory/profiles/provider-models.yaml',
            'factory/evals/provider-qualification.yaml',
            'factory/evals/provider-repair-corpus-v1.json',
        }.issubset(paths))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in paths:
                target = root/name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT/name, target)
            self.assertFalse(validate_live_provider_preparation(root).all_live_targets_disabled)
            proof = handle_operational_boundary_probe(event, role='builder',
                commit='a'*40, signer=Signer(), now=NOW, root=root)
            self.assertFalse(proof['operational_execution_enabled'])
            self.assertEqual(proof['payload']['maximum_provider_calls'], 3)
            contract_path = root/'factory/autonomy/operating-contract.yaml'
            contract = yaml.safe_load(contract_path.read_text())
            contract['activation']['pending_gates'] = []
            contract_path.write_text(yaml.safe_dump(contract))
            with self.assertRaisesRegex(StateError, 'disabled Builder operating contract differs'):
                handle_operational_boundary_probe(event, role='builder',
                    commit='a'*40, signer=Signer(), now=NOW, root=root)

    def test_cloudformation_hard_codes_operational_kill_switch_false(self):
        template = (ROOT/'infra/roles/functions.cloudformation.json').read_text()
        self.assertEqual(
            template.count('"FACTORY_OPERATIONAL_EXECUTION_ENABLED": "false"'), 3)
        self.assertNotIn('"FACTORY_OPERATIONAL_EXECUTION_ENABLED": "true"', template)

    def test_builder_acceptance_iam_is_separate_and_defaults_off(self):
        template = json.loads((ROOT/'infra/roles/functions.cloudformation.json').read_text())
        self.assertEqual(template['Parameters']['EnableBuilderAcceptanceIam']['Default'], 'false')
        resources = template['Resources']
        builder = resources['BuilderRole']['Properties']
        self.assertEqual(len(resources), 14)
        self.assertEqual(len(resources['PlannerRole']['Properties']['Policies']), 1)
        self.assertEqual(len(resources['InspectorRole']['Properties']['Policies']), 2)
        self.assertEqual(template['Parameters']['EnableInspectorAcceptanceIam'],
            {'Type': 'String', 'Default': 'false', 'AllowedValues': ['false', 'true']})
        self.assertEqual(template['Conditions']['InspectorAcceptanceIamEnabled'],
            {'Fn::Equals': [{'Ref': 'EnableInspectorAcceptanceIam'}, 'true']})
        inspector = resources['InspectorRole']['Properties']['Policies'][1]['Fn::If']
        self.assertEqual(inspector[0], 'InspectorAcceptanceIamEnabled')
        self.assertEqual(inspector[2], {'Ref': 'AWS::NoValue'})
        self.assertEqual(inspector[1]['PolicyDocument'], {
            'Version': '2012-10-17', 'Statement': [
                {'Sid': 'ExactInspectorProfile', 'Effect': 'Allow',
                 'Action': 'bedrock:InvokeModel',
                 'Resource': 'arn:aws:bedrock:ca-central-1:666730517561:inference-profile/global.anthropic.claude-sonnet-5-5',
                 'Condition': {'StringEquals': {'aws:RequestedRegion': 'ca-central-1'}}},
                {'Sid': 'ModelOnlyViaInspectorProfile', 'Effect': 'Allow',
                 'Action': 'bedrock:InvokeModel', 'Resource': [
                     'arn:aws:bedrock:ca-central-1::foundation-model/anthropic.claude-sonnet-5-5',
                     'arn:aws:bedrock:::foundation-model/anthropic.claude-sonnet-5-5'],
                 'Condition': {'StringEquals': {'bedrock:InferenceProfileArn':
                     'arn:aws:bedrock:ca-central-1:666730517561:inference-profile/global.anthropic.claude-sonnet-5-5'}}}]})
        self.assertEqual(builder['ManagedPolicyArns']['Fn::If'][0], 'BuilderAcceptanceIamEnabled')
        self.assertEqual(builder['ManagedPolicyArns']['Fn::If'][1],
            ['arn:aws:iam::666730517561:policy/tims-software-factory-acceptance-budget-builder'])
        self.assertEqual(builder['ManagedPolicyArns']['Fn::If'][2], {'Ref':'AWS::NoValue'})
        condition, enabled, disabled = builder['Policies'][1]['Fn::If']
        self.assertEqual(condition, 'BuilderAcceptanceIamEnabled')
        self.assertEqual(disabled, {'Ref':'AWS::NoValue'})
        statements = {s['Sid']: s for s in enabled['PolicyDocument']['Statement']}
        self.assertEqual(set(statements), {'ReadAndGuardExactAcceptanceState',
            'OwnExactAcceptanceExecution', 'InvokePinnedCredentialFreeBroker'})
        self.assertEqual(statements['ReadAndGuardExactAcceptanceState']['Action'],
            ['dynamodb:GetItem', 'dynamodb:ConditionCheckItem'])
        self.assertEqual(statements['OwnExactAcceptanceExecution']['Action'],
            ['dynamodb:GetItem', 'dynamodb:PutItem', 'dynamodb:UpdateItem'])
        self.assertEqual(statements['InvokePinnedCredentialFreeBroker']['Resource'],
            'arn:aws:lambda:ca-central-1:666730517561:function:tims-factory-provider-broker:3')
        self.assertEqual(len(validate_builder_iam_template()), 64)

    def test_builder_iam_plan_accepts_only_observed_role_dependency(self):
        role = {'ResourceChange': {'LogicalResourceId':'BuilderRole',
            'ResourceType':'AWS::IAM::Role', 'Action':'Modify', 'Replacement':'False'}}
        function = {'ResourceChange': {'LogicalResourceId':'BuilderFunction',
            'ResourceType':'AWS::Lambda::Function', 'Action':'Modify', 'Replacement':'False',
            'Scope':['Properties'], 'Details':[{'Target':{'Attribute':'Properties',
                'Name':'Role', 'RequiresRecreation':'Never'}, 'Evaluation':'Dynamic',
                'ChangeSource':'ResourceAttribute', 'CausingEntity':'BuilderRole.Arn'}]}}
        validate_builder_iam_changes([function, role])
        for changed in ([role], [role, role],
                [role, {'ResourceChange':{**function['ResourceChange'], 'Replacement':'True'}}],
                [role, {'ResourceChange':{**function['ResourceChange'], 'Details':[
                    {**function['ResourceChange']['Details'][0], 'CausingEntity':'OtherRole.Arn'}]}}],
                [role, {'ResourceChange':{**function['ResourceChange'], 'Details':[
                    {**function['ResourceChange']['Details'][0], 'Target':{
                        'Attribute':'Properties', 'Name':'Environment',
                        'RequiresRecreation':'Never'}}]}}]):
            with self.assertRaises(RuntimeError):
                validate_builder_iam_changes(changed)

    def test_builder_iam_preflight_rejects_deployed_function_drift(self):
        deployed = json.loads((ROOT/'infra/roles/functions.cloudformation.json').read_text())
        validate_builder_deployed_template(deployed)
        deployed['Resources']['BuilderFunction']['Properties']['Environment']['Variables'][
            'FACTORY_OPERATIONAL_EXECUTION_ENABLED'] = 'true'
        with self.assertRaisesRegex(RuntimeError, 'deployed BuilderFunction differs'):
            validate_builder_deployed_template(deployed)

    def test_builder_iam_execute_rechecks_exact_change_set_before_apply(self):
        detail = {'Target':{'Attribute':'Properties','Name':'Role',
                            'RequiresRecreation':'Never'}, 'Evaluation':'Dynamic',
                  'ChangeSource':'ResourceAttribute','CausingEntity':'BuilderRole.Arn'}
        changes = [{'ResourceChange':{'LogicalResourceId':'BuilderRole',
                    'ResourceType':'AWS::IAM::Role','Action':'Modify','Replacement':'False'}},
                   {'ResourceChange':{'LogicalResourceId':'BuilderFunction',
                    'ResourceType':'AWS::Lambda::Function','Action':'Modify',
                    'Replacement':'False','Scope':['Properties'],'Details':[detail]}}]
        plan = {'status':'PREPARED_NOT_EXECUTED','source_commit':'a'*40,
                'stack_id':'stack-1','change_set_arn':'change-set-1',
                'template_sha256':builder_iam.validate_template(), 'changes':changes,
                'operational_execution_enabled':False,'model_calls_authorized':0}
        stack = {'StackId':'stack-1','StackStatus':'UPDATE_COMPLETE','Parameters':[
            {'ParameterKey':key,'ParameterValue':value} for key,value in {
                'EnableBuilderAcceptanceIam':'false','ArtifactBucket':'bucket',
                'ArtifactKey':'key','ArtifactVersion':'version','CodeSha256':'code'}.items()]}
        change_set = {'StackId':'stack-1','Status':'CREATE_COMPLETE',
                      'ExecutionStatus':'AVAILABLE','Changes':changes,'Parameters':[
            {'ParameterKey':key,'ParameterValue':value} for key,value in {
                'EnableBuilderAcceptanceIam':'true','ArtifactBucket':'bucket',
                'ArtifactKey':'key','ArtifactVersion':'version','CodeSha256':'code'}.items()]}
        calls = []
        def fake_aws(*args):
            calls.append(args[:2])
            if args[:2] == ('sts','get-caller-identity'): return {'Account':builder_iam.ACCOUNT}
            if args[:2] == ('cloudformation','describe-stacks'): return {'Stacks':[stack]}
            if args[:2] == ('cloudformation','get-template'):
                return {'TemplateBody':json.loads(builder_iam.TEMPLATE.read_text())}
            if args[:2] == ('cloudformation','describe-change-set'): return change_set
            return {}
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'plan.json'; path.write_text(json.dumps(plan))
            with patch.object(builder_iam, 'source', return_value='a'*40), \
                    patch.object(builder_iam, 'aws', side_effect=fake_aws):
                changed = json.loads(json.dumps(change_set))
                changed['Changes'][1]['ResourceChange']['Details'][0]['Target']['Name'] = 'Code'
                change_set = changed
                with self.assertRaises(RuntimeError): builder_iam.execute(path)
                self.assertNotIn(('cloudformation','execute-change-set'), calls)
                change_set['Changes'] = changes
                builder_iam.execute(path)
                self.assertIn(('cloudformation','execute-change-set'), calls)
                self.assertEqual(json.loads(path.read_text())['status'],
                                 'DEPLOYED_PENDING_VERIFICATION')

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
