import copy
import io
import hashlib
import base64
import json
import sys
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path
from unittest.mock import Mock,patch

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'scripts'),str(ROOT/'src')]
import run_pilot002_qa_once as p
import test_pilot002_qa_live as fixture


class QaRunnerTests(unittest.TestCase):
    def run_case(self,mode='success',reuse=False):
        fx=fixture.QaPreviewTests();fx.setUp()
        plan=fx.plan
        blob=b'synthetic package'
        raw_hash=hashlib.sha256(blob).digest()
        fx.package.update(zip_bytes=len(blob),sha256=raw_hash.hex(),code_sha256=base64.b64encode(raw_hash).decode())
        fx.code['S3Key']='pilot-002/runtime/'+p.signing.QA_SOURCE+'/'+raw_hash.hex()+'.zip'
        proof={'status':'PREPARED_VALIDATED_NOT_EXECUTED','plan_digest':p.signing.digest(plan),
            'stack_id':p.preview.STACK,'shared_capacity_approved':True,
            'change_set_arn':'arn:aws:cloudformation:ca-central-1:666730517561:changeSet/pilot002-qa-live-fixture/id',
            'package':fx.package,'code':fx.code,'template':fx.render(),'rollback_template':p.preview.baseline()}
        proof['shutdown_deadline']=int(fx.now.timestamp())+180
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
            if mode=='protected_attempt_drift':old['inspector']['status']['S']='COMPLETE'
        cf.execute_change_set.side_effect=execute
        def rollback(**kw):
            calls.append('rollback')
            if mode=='rollback_failure':raise RuntimeError('private detail')
            state['active']=False
        cf.update_stack.side_effect=rollback
        def function(FunctionName):
            if FunctionName=='tims-factory-inspector-recovery-001':
                return {'FunctionName':FunctionName,'CodeSha256':base['package']['code_sha256'],
                    'Environment':{'Variables':{'FACTORY_INSPECTOR_RECOVERY001_ENABLED':'false'}}}
            if FunctionName!=p.NAME:
                role=FunctionName.rsplit('-',1)[-1]
                return {'FunctionName':FunctionName,'CodeSha256':base['workers'][role]['code_sha256'],
                    'Environment':{'Variables':{'FACTORY_PILOT002_EXECUTION_ENABLED':'false'}}}
            value=copy.deepcopy(template()['Resources']['QaFunction']['Properties'])
            value.update(Role='arn:aws:iam::666730517561:role/tims-factory-pilot-002-qa-disabled',State='Active',LastUpdateStatus='Successful',
                CodeSha256=(proof['package']['code_sha256'] if state['active'] else base['workers']['qa']['code_sha256']))
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
        role=proof['rollback_template']['Resources']['QaRole']['Properties']
        shutdown_role=p.shutdown.render(int(fx.now.timestamp())+1200,now=fx.now)['Resources']['ShutdownRole']['Properties']
        def role_props(name):return shutdown_role if name==p.shutdown.ROLE else role
        iam.get_role.side_effect=lambda RoleName:{'Role':{'AssumeRolePolicyDocument':role_props(RoleName)['AssumeRolePolicyDocument']}}
        iam.list_attached_role_policies.return_value={'AttachedPolicies':[]}
        def policies(name):
            result={v['PolicyName']:v['PolicyDocument'] for v in role_props(name)['Policies']}
            if name!=p.shutdown.ROLE:
                value=proof['template']['Resources']['QaAccess']['Properties'];result[value['PolicyName']]=value['PolicyDocument']
            return result
        iam.list_role_policies.side_effect=lambda RoleName:{'PolicyNames':list(policies(RoleName))+(['unexpected'] if mode=='iam_drift' else [])}
        iam.get_role_policy.side_effect=lambda RoleName,PolicyName:{'PolicyDocument':policies(RoleName)[PolicyName]}
        old={'builder':{'status':{'S':'COMPLETE'}},'inspector':{'status':{'S':'STARTED'},
            'reservation_status':{'S':'HELD'},'reserved_micro_usd':{'N':'250000'}},'qa':None}
        recovery={'status':{'S':'STARTED'},'reservation_status':{'S':'HELD'},'reserved_micro_usd':{'N':'250000'}}
        def item(**kw):
            if kw['TableName']==p.RECOVERY_TABLE:return {'Item':recovery}
            role_name=kw['Key']['PK']['S'].rsplit('#',1)[-1]
            if role_name=='qa':return {'Item':{'status':{'S':'STARTED'}}} if mode=='already_used' else {'Item':state['attempt']}
            return {'Item':copy.deepcopy(old[role_name])}
        db.get_item.side_effect=item
        s3.get_object.return_value={'VersionId':proof['code']['S3ObjectVersion'],'Body':io.BytesIO(blob)}
        sts.get_caller_identity.return_value={'Account':'666730517561'}
        events.list_rule_names_by_target.return_value={'RuleNames':[]}
        scheduler.get_paginator.return_value.paginate.return_value=[]
        schedule=p.shutdown.properties(proof['shutdown_deadline'],now=fx.now,armed=mode!='shutdown_missing')
        scheduler.get_schedule.side_effect=lambda **kw:dict(schedule)
        def update_schedule(**kw):
            if not 1<=len(kw['ClientToken'])<=64:
                raise ValueError('Scheduler ClientToken must be at most 64 characters')
            if mode=='disarm_failure':raise RuntimeError('private detail')
            schedule.update({k:v for k,v in kw.items() if k!='ClientToken'})
        scheduler.update_schedule.side_effect=update_schedule
        def invoke(**kw):
            calls.append('invoke');state['attempt']={'status':{'S':'STARTED'}}
            if mode=='invoke_timeout':raise TimeoutError('private detail')
            result={'status':'PILOT002_REVIEW_FAILED_NO_RETRY' if mode=='review_failure' else 'PILOT002_COMPLETED_UNSIGNED',
                'role':'qa','gate_authority':False,'production_release_authorized':False,
                'actual_micro_usd':0,'transport_invocations':1,'request_digest':p.signing.REQUESTS['qa'],
                'source_commit':p.signing.QA_SOURCE,'approval_digest':p.signing.digest(plan['allowance_payload']),
                'reservation_status':'HELD','accepted_review':False,'attempt_reusable':False,'failure_stage':'response'}
            if mode=='paid_response':result['actual_micro_usd']=1
            raw=b'x'*524289 if mode=='oversized' else json.dumps(result).encode()
            return {'StatusCode':200,'Payload':io.BytesIO(raw)}
        lam.invoke.side_effect=invoke
        clients={'cloudformation':cf,'lambda':lam,'dynamodb':db,'iam':iam,'s3':s3,'sts':sts,'events':events,'scheduler':scheduler}
        session=Mock();session.client.side_effect=lambda service,**kw:clients[service]
        runtime_args={}
        if mode=='runtime_deadline':runtime_args['shutdown_deadline']=proof.pop('shutdown_deadline')
        if mode=='no_deadline':proof.pop('shutdown_deadline')
        if mode=='conflicting_deadline':runtime_args['shutdown_deadline']=proof['shutdown_deadline']+1
        with tempfile.TemporaryDirectory() as directory,patch.object(p,'verify',side_effect=p.StateError('bad signature') if mode=='bad_signature' else None):
            args={'approved_plan_digest':proof['plan_digest'],'approved_preview_digest':p.signing.digest(proof),
                'signing_workflow_run':1,'output':Path(directory),'session':session,
                'clock':lambda:fx.now+timedelta(seconds=301 if mode=='expired_after_activation' and state['active'] else 0),
                'sleep':lambda _:None,**runtime_args}
            if mode in ('already_used','shutdown_missing','no_deadline','conflicting_deadline','iam_drift','bad_signature'):
                with self.assertRaises(p.StateError):p.run(plan,proof,{'payload':plan['allowance_payload']},**args)
                cf.execute_change_set.assert_not_called();lam.invoke.assert_not_called();return
            report=p.run(plan,proof,{'payload':plan['allowance_payload']},**args)
            self.assertTrue((Path(directory)/'qa-execution-marker.json').exists())
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
        self.assertTrue(report['schedule_disabled'])

    def test_uncertain_activation_disables_without_invoking(self):
        report,calls,_=self.run_case('activation_timeout')
        self.assertNotIn('invoke',calls);self.assertTrue(report['shutdown_verified'])

    def test_uncertain_invocation_does_not_retry(self):
        report,calls,_=self.run_case('invoke_timeout')
        self.assertEqual(calls.count('invoke'),1);self.assertEqual(report['status'],'STOPPED_NO_RETRY');self.assertTrue(report['shutdown_verified'])

    def test_already_consumed_qa_never_activates(self):self.run_case('already_used')

    def test_missing_independent_shutdown_never_activates(self):self.run_case('shutdown_missing')

    def test_runtime_deadline_does_not_change_approved_preview(self):
        report,calls,state=self.run_case('runtime_deadline')
        self.assertTrue(report['shutdown_verified']);self.assertEqual(calls.count('invoke'),1)

    def test_missing_or_conflicting_deadline_never_activates(self):
        for mode in ('no_deadline','conflicting_deadline'):self.run_case(mode)

    def test_wrong_active_code_never_invokes(self):
        report,calls,_=self.run_case('wrong_code')
        self.assertNotIn('invoke',calls);self.assertTrue(report['shutdown_verified'])

    def test_failed_review_and_oversized_response_stop_and_disable(self):
        for mode in ('review_failure','oversized'):
            report,_,_=self.run_case(mode);self.assertEqual(report['status'],'STOPPED_NO_RETRY');self.assertTrue(report['shutdown_verified'])

    def test_rollback_failure_reported_with_concurrency_forced_off(self):
        report,_,state=self.run_case('rollback_failure')
        self.assertFalse(report['shutdown_verified']);self.assertTrue(state['off']);self.assertTrue(report['shutdown_errors'])


    def test_permission_drift_prevents_activation(self):self.run_case('iam_drift')

    def test_invalid_signature_never_activates(self):self.run_case('bad_signature')

    def test_expiry_during_activation_prevents_provider_invocation(self):
        report,calls,_=self.run_case('expired_after_activation')
        self.assertNotIn('invoke',calls)
        self.assertTrue(report['shutdown_verified'])
        self.assertTrue(report['schedule_disabled'])

    def test_protected_attempt_change_stops_and_preserves_shutdown_schedule(self):
        report,calls,state=self.run_case('protected_attempt_drift')
        self.assertNotIn('invoke',calls)
        self.assertFalse(report['shutdown_verified'])
        self.assertFalse(report['schedule_disabled'])
        self.assertTrue(state['off'])

    def test_nonzero_cost_result_is_rejected_and_restored(self):
        report,calls,_=self.run_case('paid_response')
        self.assertEqual(report['status'],'STOPPED_NO_RETRY')
        self.assertTrue(report['shutdown_verified'])
        self.assertEqual(calls.count('invoke'),1)

    def test_disarm_failure_is_reported_without_retry(self):
        report,_,_=self.run_case('disarm_failure')
        self.assertFalse(report['schedule_disabled'])
        self.assertIn('schedule_disarm:RuntimeError',report['shutdown_errors'])


if __name__=='__main__':unittest.main()
