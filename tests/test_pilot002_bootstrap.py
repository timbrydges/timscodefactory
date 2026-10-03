import copy
import json
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import Mock

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'src'),str(ROOT/'scripts')]
from factory_runtime import pilot002_bootstrap as boot
from factory_state.dynamodb import DynamoDBStateStore
from factory_state.model import StateError
from prepare_pilot002_bootstrap import prepare, validate_changes
from prepare_security_gate_access import LOG_POLICY, ROLE


class BootstrapTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        for name in boot.PINNED:
            path=self.root/name; path.parent.mkdir(parents=True,exist_ok=True)
            path.write_bytes((ROOT/name).read_bytes())
        (self.root/'BUILD.json').write_text(json.dumps({'source_commit':'a'*40}))
        self.start=1791039600
        self.config={'approved':True,'owner_identity':'tim_brydges','operation':'pilot-002-bootstrap',
            'source_commit':'a'*40,'task_id':boot.TASK,'contract_sha256':boot.PINNED[boot.CONTRACT],
            'not_before':self.start,'expires_at':self.start+3600,'nonce':'b'*32}
        self.env={boot.ENABLED:'true',boot.CONFIG:json.dumps(self.config),'FACTORY_AUTONOMY_CONTROLLER_ENABLED':'false'}
        self.event={'kind':'bootstrap_pilot_002','source_commit':'a'*40,'task_id':boot.TASK,'nonce':'b'*32}
        self.sts=Mock(); self.sts.get_caller_identity.return_value={'Account':'666730517561',
            'Arn':f'arn:aws:sts::666730517561:assumed-role/{ROLE}/test'}
        self.db=Mock(); self.rows={}
        self.db.get_item.side_effect=lambda **kw: {'Item':copy.deepcopy(self.rows[kw['Key']['SK']['S']])} if kw['Key']['SK']['S'] in self.rows else {}
        def transaction(**kw):
            self.assertLessEqual(len(kw['ClientRequestToken']),36)
            self.assertEqual(len(kw['TransactItems']),3)
            for entry in kw['TransactItems']:
                put=entry['Put']; item=put['Item']
                self.assertEqual(put['TableName'],boot.TABLE)
                self.assertEqual(put['ConditionExpression'],'attribute_not_exists(PK) AND attribute_not_exists(SK)')
                self.assertEqual(item['PK'],{'S':boot.PARTITION})
                self.assertNotIn(item['SK']['S'],self.rows)
            for entry in kw['TransactItems']:
                item=entry['Put']['Item']; self.rows[item['SK']['S']]=copy.deepcopy(item)
        self.db.transact_write_items.side_effect=transaction

    def run_bootstrap(self,clock=None):
        return boot.run(self.event,root=self.root,env=self.env,db=self.db,sts=self.sts,
                        clock=clock or (lambda:datetime.fromtimestamp(self.start+1,timezone.utc)))

    def test_atomic_creation_serializes_for_existing_state_adapter(self):
        result=self.run_bootstrap()
        self.assertEqual(result['status'],'BOOTSTRAPPED_PAUSED_VERIFIED')
        state=DynamoDBStateStore._deserialize_payload(self.rows['STATE']['payload']['S'])
        self.assertEqual((state.task_id,state.state,state.version),(boot.TASK,'PAUSED',0))
        self.assertFalse(state.leases); self.assertFalse(state.consumed_evidence_ids)
        self.assertEqual(self.run_bootstrap()['writes'],0)
        self.db.transact_write_items.assert_called_once()

    def test_existing_state_partial_marker_or_changed_audit_never_overwrites(self):
        expected=boot.items(self.config)
        for row in expected:
            with self.subTest(key=row['SK']):
                self.rows={row['SK']['S']:copy.deepcopy(row)}
                with self.assertRaises(StateError): self.run_bootstrap()
        self.db.transact_write_items.assert_not_called()

    def test_unknown_outcome_is_not_retried(self):
        self.db.transact_write_items.side_effect=TimeoutError('sensitive raw error')
        with self.assertRaisesRegex(StateError,'uncertain'):self.run_bootstrap()
        self.db.transact_write_items.assert_called_once()

    def test_boundary_rejects_disabled_wrong_task_expiry_and_approval_expansion(self):
        cases=[('approved',False),('approved',1),('task_id','deterministic-text-fingerprint'),
               ('expires_at',self.start),('expires_at',self.start+3601),('not_before',True),
               ('source_commit','c'*40),('contract_sha256','0'*64),('extra',True)]
        for key,value in cases:
            with self.subTest(key=key,value=value):
                config={**self.config,key:value}; self.env[boot.CONFIG]=json.dumps(config)
                with self.assertRaises(StateError):self.run_bootstrap()
        self.env[boot.CONFIG]=json.dumps(self.config); self.env[boot.ENABLED]='false'
        with self.assertRaises(StateError):self.run_bootstrap()
        self.db.get_item.assert_not_called(); self.db.transact_write_items.assert_not_called()

    def test_clock_rechecked_before_write(self):
        clock=Mock(side_effect=[datetime.fromtimestamp(self.start+1,timezone.utc),
                              datetime.fromtimestamp(self.start+3600,timezone.utc)])
        with self.assertRaises(StateError):self.run_bootstrap(clock)
        self.db.transact_write_items.assert_not_called()

    def test_wrong_role_or_contract_cannot_write(self):
        self.sts.get_caller_identity.return_value={'Account':'666730517561','Arn':'wrong'}
        with self.assertRaises(StateError):self.run_bootstrap()
        self.db.get_item.assert_not_called()
        (self.root/boot.CONTRACT).write_text('{}')
        with self.assertRaises(StateError):self.run_bootstrap()
        self.db.transact_write_items.assert_not_called()

    def test_permission_plan_only_grants_new_partition_get_and_put(self):
        baseline={'Resources':{'ControllerRole':{'Properties':{'RoleName':ROLE,'Policies':[LOG_POLICY],
            'AssumeRolePolicyDocument':{'Version':'2012-10-17','Statement':[{'Effect':'Allow',
                'Principal':{'Service':'lambda.amazonaws.com'},'Action':'sts:AssumeRole'}]}}},
            'ControllerFunction':{'Properties':{'FunctionName':'tims-software-factory-autonomy-controller',
                'Handler':'factory_runtime.security_gate_runtime.controller_handler',
                'Role':{'Fn::GetAtt':['ControllerRole','Arn']},'ReservedConcurrentExecutions':0,
                'Environment':{'Variables':{'FACTORY_AUTONOMY_CONTROLLER_ENABLED':'false'}}}}}}
        original=copy.deepcopy(baseline)
        args=dict(commit='a'*40,code={'S3Bucket':'bucket','S3Key':'key','S3ObjectVersion':'version'},
                  starts_at=self.start,expires_at=self.start+3600,nonce='b'*32)
        plan=prepare(baseline,**args)
        policy=plan['temporary_policy']['PolicyDocument']['Statement'][0]
        self.assertEqual(policy['Action'],['dynamodb:GetItem','dynamodb:PutItem'])
        self.assertEqual(policy['Condition']['ForAllValues:StringEquals']['dynamodb:LeadingKeys'],[boot.PARTITION])
        self.assertEqual(plan['restore_template']['Resources']['ControllerRole']['Properties']['Policies'],[LOG_POLICY])
        self.assertEqual(plan['restore_template']['Resources']['ControllerFunction']['Properties']['ReservedConcurrentExecutions'],0)
        self.assertEqual(baseline,original)
        baseline['Resources']['ControllerFunction']['Properties']['ReservedConcurrentExecutions']=1
        with self.assertRaises(StateError):prepare(baseline,**args)

    def test_real_baseline_and_changeset_scope(self):
        baseline=json.loads((ROOT/'factory/evidence/pilot-002-controller-baseline-2026-10-03.json').read_bytes())
        plan=prepare(baseline,commit='a'*40,code={'S3Bucket':'bucket','S3Key':'key','S3ObjectVersion':'version'},
                     starts_at=self.start,expires_at=self.start+3600,nonce='b'*32)
        def change(name,kind,props):
            return {'Type':'Resource','ResourceChange':{'LogicalResourceId':name,'ResourceType':kind,
                'Action':'Modify','Replacement':'False','Scope':['Properties'],
                'Details':[{'Target':{'Attribute':'Properties','Name':p,'RequiresRecreation':'Never'}} for p in props]}}
        cs={'Status':'CREATE_COMPLETE','ExecutionStatus':'AVAILABLE',
            'StackId':'arn:aws:cloudformation:ca-central-1:666730517561:stack/tims-factory-autonomy-controller-disabled/id',
            'Parameters':[],'Changes':[change('ControllerFunction','AWS::Lambda::Function',['Code','Handler','Environment'])]}
        validate_changes(plan,baseline,plan['disabled_template'],cs,parameters={},phase='deploy')
        active=copy.deepcopy(cs)
        active['Changes']=[change('ControllerRole','AWS::IAM::Role',['Policies']),
                           change('ControllerFunction','AWS::Lambda::Function',['Role','Environment','ReservedConcurrentExecutions'])]
        validate_changes(plan,plan['disabled_template'],plan['active_template'],active,parameters={},phase='activate')
        validate_changes(plan,plan['active_template'],plan['restore_template'],active,parameters={},phase='restore')
        for bad in [dict(cs,NextToken='more'),dict(cs,StackId='wrong'),dict(cs,Parameters=[{'ParameterKey':'new','ParameterValue':'x'}]),
                    dict(cs,Changes=cs['Changes']+[change('AcceptanceAlias','AWS::Lambda::Alias',['FunctionVersion'])])]:
            with self.subTest(bad=bad):
                with self.assertRaises(StateError):validate_changes(plan,baseline,plan['disabled_template'],bad,parameters={},phase='deploy')
        drift=copy.deepcopy(plan); drift['active_template']['Resources']['ControllerRole']['Properties']['Policies'].append({'bad':True})
        with self.assertRaises(StateError):validate_changes(drift,baseline,plan['disabled_template'],cs,parameters={},phase='deploy')

    def test_shared_capacity_is_explicit_proposal_and_restores_zero(self):
        baseline=json.loads((ROOT/'factory/evidence/pilot-002-controller-baseline-2026-10-03.json').read_bytes())
        args=dict(commit='a'*40,code={'S3Bucket':'bucket','S3Key':'key','S3ObjectVersion':'version'},
                  starts_at=self.start,expires_at=self.start+3600,nonce='b'*32)
        original=prepare(baseline,**args)
        shared=prepare(original['disabled_template'],**args,capacity_mode='shared-account-pool')
        self.assertEqual(shared['status'],'PREPARED_NOT_AUTHORIZED')
        self.assertNotIn('ReservedConcurrentExecutions',shared['active_template']['Resources']['ControllerFunction']['Properties'])
        self.assertEqual(shared['restore_template']['Resources']['ControllerFunction']['Properties']['ReservedConcurrentExecutions'],0)
        self.assertEqual(shared['temporary_policy'],original['temporary_policy'])
        self.assertEqual(shared['expected_items'],original['expected_items'])
        self.assertEqual(shared['maximum_invocations'],1)
        with self.assertRaises(StateError):prepare(baseline,**args,capacity_mode='unlimited')

    def test_racing_bootstrap_transactions_cannot_overwrite(self):
        from concurrent.futures import ThreadPoolExecutor
        from threading import Barrier, Lock
        barrier=Barrier(2); lock=Lock(); commits=[]
        original=self.db.transact_write_items.side_effect
        def racing_write(**kw):
            barrier.wait(timeout=5)
            with lock:
                if self.rows:raise RuntimeError('TransactionCanceled: existing marker/state')
                original(**kw);commits.append(kw)
        self.db.transact_write_items.side_effect=racing_write
        def invoke():
            try:return self.run_bootstrap()['status']
            except StateError:return 'REJECTED'
        with ThreadPoolExecutor(max_workers=2) as pool:
            results=list(pool.map(lambda _:invoke(),range(2)))
        self.assertCountEqual(results,['BOOTSTRAPPED_PAUSED_VERIFIED','REJECTED'])
        self.assertEqual(len(commits),1)
        self.assertEqual(tuple(self.rows[i['SK']['S']] for i in boot.items(self.config)),boot.items(self.config))


if __name__=='__main__':unittest.main()
