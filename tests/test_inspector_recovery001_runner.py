import copy
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock,patch

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'scripts'),str(ROOT/'src')]
import run_inspector_recovery001_once as p
import test_inspector_recovery001_live as fixture


class RecoveryRunnerTests(unittest.TestCase):
    def run_case(self,mode='success',reuse=False):
        fx=fixture.RecoveryLivePreviewTests();fx.setUp()
        plan={'activation':json.loads(fx.raw),'pricing':{},'allowance_payload':{'fixture':True}}
        # Keep actual activation/preview validation; substitute signature verification only.
        blob=b'synthetic package'
        fx.package['zip_bytes']=len(blob)
        proof={'status':'PREPARED_VALIDATED_NOT_EXECUTED','plan_digest':p.signing.digest(plan),
            'stack_id':p.preview.STACK,'shared_capacity_approved':True,
            'change_set_arn':'arn:aws:cloudformation:ca-central-1:666730517561:changeSet/inspector-recovery001-live-fixture/id',
            'package':fx.package,'code':fx.code,'template':fx.template,'rollback_template':p.preview.baseline()}
        base=json.loads((ROOT/'factory/evidence/inspector-recovery-001-disabled-deployed.json').read_bytes())
        state={'active':False,'off':False,'attempt':None};calls=[]
        cf=Mock();lam=Mock();db=Mock();iam=Mock();s3=Mock();sts=Mock();events=Mock();scheduler=Mock()
        def template():return proof['template'] if state['active'] else proof['rollback_template']
        cf.get_template.side_effect=lambda **kw:{'TemplateBody':proof['template'] if 'ChangeSetName' in kw else template()}
        cf.describe_change_set.return_value=fx.changes
        cf.describe_stacks.return_value={'Stacks':[{'StackStatus':'UPDATE_COMPLETE'}]}
        def execute(**kw):
            calls.append('activate');state['active']=True
            if mode=='activation_timeout':raise TimeoutError('private detail')
        cf.execute_change_set.side_effect=execute
        def rollback(**kw):
            calls.append('rollback')
            if mode=='rollback_failure':raise RuntimeError('private detail')
            state['active']=False
        cf.update_stack.side_effect=rollback
        def function(FunctionName):
            if FunctionName!=p.NAME:
                role=FunctionName.rsplit('-',1)[-1]
                return {'FunctionName':FunctionName,'CodeSha256':base['workers'][role]['code_sha256'],
                    'Environment':{'Variables':{'FACTORY_PILOT002_EXECUTION_ENABLED':'false'}}}
            value=copy.deepcopy(template()['Resources']['RecoveryFunction']['Properties'])
            value.update(Role=base['role_arn'],State='Active',LastUpdateStatus='Successful',
                CodeSha256=(proof['package'] if state['active'] else base['package'])['code_sha256'])
            if mode=='wrong_code' and state['active']:value['CodeSha256']='wrong'
            return value
        lam.get_function_configuration.side_effect=function
        lam.get_function_concurrency.side_effect=lambda FunctionName:{} if FunctionName==p.NAME and state['active'] and not state['off'] else {'ReservedConcurrentExecutions':0}
        def off(**kw):calls.append('off');state['off']=True
        lam.put_function_concurrency.side_effect=off
        lam.get_account_settings.return_value={'AccountLimit':{'UnreservedConcurrentExecutions':10}}
        lam.list_event_source_mappings.return_value={'EventSourceMappings':[]}
        lam.list_aliases.return_value={'Aliases':[]};lam.list_function_url_configs.return_value={'FunctionUrlConfigs':[]}
        class Missing(Exception):pass
        lam.exceptions.ResourceNotFoundException=Missing;lam.get_policy.side_effect=Missing
        role=proof['rollback_template']['Resources']['RecoveryRole']['Properties']
        iam.get_role.return_value={'Role':{'AssumeRolePolicyDocument':role['AssumeRolePolicyDocument']}}
        iam.list_attached_role_policies.return_value={'AttachedPolicies':[]}
        def policies():
            result={v['PolicyName']:v['PolicyDocument'] for v in role['Policies']}
            if state['active']:
                value=proof['template']['Resources']['RecoveryAccess']['Properties'];result[value['PolicyName']]=value['PolicyDocument']
            return result
        iam.list_role_policies.side_effect=lambda **kw:{'PolicyNames':list(policies())}
        iam.get_role_policy.side_effect=lambda **kw:{'PolicyDocument':policies()[kw['PolicyName']]}
        old={'builder':{'status':{'S':'COMPLETE'}},'inspector':{'status':{'S':'STARTED'},
            'reservation_status':{'S':'HELD'},'reserved_micro_usd':{'N':'250000'}},'qa':None}
        def item(**kw):
            if kw['TableName']==p.TABLE:return {'Item':{'status':{'S':'STARTED'}}} if mode=='already_used' else {'Item':state['attempt']}
            role_name=kw['Key']['PK']['S'].rsplit('#',1)[-1];return {'Item':old[role_name]}
        db.get_item.side_effect=item
        s3.get_object.return_value={'VersionId':proof['code']['S3ObjectVersion'],'Body':io.BytesIO(blob)}
        sts.get_caller_identity.return_value={'Account':'666730517561'}
        events.list_rule_names_by_target.return_value={'RuleNames':[]}
        scheduler.get_paginator.return_value.paginate.return_value=[]
        def invoke(**kw):
            calls.append('invoke');state['attempt']={'status':{'S':'STARTED'}}
            if mode=='invoke_timeout':raise TimeoutError('private detail')
            result={'status':'INSPECTOR_RECOVERY001_FAILED_NO_RETRY' if mode=='review_failure' else 'INSPECTOR_RECOVERY001_COMPLETED_UNSIGNED',
                'role':'inspector','recovery_scope_digest':'sha256:'+p.SCOPE_SHA256,'gate_authority':False,'production_release_authorized':False}
            raw=b'x'*524289 if mode=='oversized' else json.dumps(result).encode()
            return {'StatusCode':200,'Payload':io.BytesIO(raw)}
        lam.invoke.side_effect=invoke
        clients={'cloudformation':cf,'lambda':lam,'dynamodb':db,'iam':iam,'s3':s3,'sts':sts,'events':events,'scheduler':scheduler}
        session=Mock();session.client.side_effect=lambda service,**kw:clients[service]
        with tempfile.TemporaryDirectory() as directory,patch.object(p.signing,'validate_plan',return_value=plan['allowance_payload']),patch.object(p,'verify'):
            args={'approved_plan_digest':proof['plan_digest'],'approved_preview_digest':p.signing.digest(proof),
                'signing_workflow_run':1,'output':Path(directory),'session':session,'clock':lambda:fx.now,'sleep':lambda _:None}
            if mode=='already_used':
                with self.assertRaises(p.StateError):p.run(plan,proof,{'payload':plan['allowance_payload']},**args)
                cf.execute_change_set.assert_not_called();lam.invoke.assert_not_called();return
            report=p.run(plan,proof,{'payload':plan['allowance_payload']},**args)
            self.assertTrue((Path(directory)/'recovery-execution-marker.json').exists())
            if reuse:
                with self.assertRaises(p.StateError):p.run(plan,proof,{'payload':plan['allowance_payload']},**args)
            self.assertLessEqual(lam.invoke.call_count,1)
            self.assertEqual(cf.execute_change_set.call_count,1)
            self.assertIn('off',calls)
            self.assertLess(calls.index('off'),calls.index('rollback'))
            self.assertNotIn('private detail',json.dumps(report))
            for call in session.client.call_args_list:self.assertEqual(call.kwargs['config'].retries['total_max_attempts'],1)
            return report,calls,state

    def test_once_and_verified_rollback_and_no_repeat(self):
        report,calls,state=self.run_case(reuse=True)
        self.assertEqual(calls.count('invoke'),1);self.assertTrue(report['shutdown_verified'])
        self.assertFalse(state['active']);self.assertEqual(report['shutdown_errors'],[])

    def test_uncertain_activation_disables_without_invoking(self):
        report,calls,_=self.run_case('activation_timeout')
        self.assertNotIn('invoke',calls);self.assertTrue(report['shutdown_verified'])

    def test_uncertain_invocation_does_not_retry(self):
        report,calls,_=self.run_case('invoke_timeout')
        self.assertEqual(calls.count('invoke'),1);self.assertEqual(report['status'],'STOPPED_NO_RETRY');self.assertTrue(report['shutdown_verified'])

    def test_already_consumed_recovery_never_activates(self):self.run_case('already_used')

    def test_wrong_active_code_never_invokes(self):
        report,calls,_=self.run_case('wrong_code')
        self.assertNotIn('invoke',calls);self.assertTrue(report['shutdown_verified'])

    def test_failed_review_and_oversized_response_stop_and_disable(self):
        for mode in ('review_failure','oversized'):
            report,_,_=self.run_case(mode);self.assertEqual(report['status'],'STOPPED_NO_RETRY');self.assertTrue(report['shutdown_verified'])

    def test_rollback_failure_reported_with_concurrency_forced_off(self):
        report,_,state=self.run_case('rollback_failure')
        self.assertFalse(report['shutdown_verified']);self.assertTrue(state['off']);self.assertTrue(report['shutdown_errors'])


if __name__=='__main__':unittest.main()
