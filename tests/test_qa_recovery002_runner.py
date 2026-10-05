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
import run_qa_recovery002_once as p
import test_qa_recovery002_live as fixture


class RecoveryRunnerTests(unittest.TestCase):
    def run_case(self,mode='success',reuse=False):
        fx=fixture.RecoveryLivePreviewTests();fx.setUp()
        plan={'activation':json.loads(fx.raw),'pricing':{},'allowance_payload':{'fixture':True,'expires_at':int(fx.now.timestamp())+300}}
        # Keep actual activation/preview validation; substitute signature verification only.
        blob=b'synthetic package'
        fx.package['zip_bytes']=len(blob)
        proof={'status':'PREPARED_VALIDATED_NOT_EXECUTED','plan_digest':p.signing.digest(plan),
            'stack_id':p.preview.STACK,'shared_capacity_approved':True,
            'change_set_arn':'arn:aws:cloudformation:ca-central-1:666730517561:changeSet/qa-recovery002-live-fixture/id',
            'package':fx.package,'code':fx.code,'template':fx.template,'rollback_template':p.preview.baseline()}
        proof['shutdown_deadline']=int(fx.now.timestamp())+180
        base=json.loads((ROOT/'factory/evidence/inspector-recovery-001-disabled-deployed.json').read_bytes())
        original=base; base={**p.preview.baseline_proof(),'workers':original['workers']}
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
            if FunctionName=='tims-factory-qa-recovery-001':
                previous=json.loads((ROOT/'factory/evidence/qa-recovery-001-disabled-deployed.json').read_bytes())
                return {'FunctionName':FunctionName,'CodeSha256':'drift' if mode=='previous_qa_worker_drift' else previous['code_sha256'],
                    'Environment':{'Variables':{'FACTORY_QA_RECOVERY001_ENABLED':'false'}}}
            if FunctionName=='tims-factory-inspector-recovery-001':
                return {'FunctionName':FunctionName,'CodeSha256':original['package']['code_sha256'],
                    'Environment':{'Variables':{'FACTORY_INSPECTOR_RECOVERY001_ENABLED':'false'}}}
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
        shutdown_role=p.shutdown.render(int(fx.now.timestamp())+1200,now=fx.now)['Resources']['ShutdownRole']['Properties']
        iam.get_role.side_effect=lambda **kw:{'Role':{'AssumeRolePolicyDocument':(shutdown_role if kw['RoleName']==p.shutdown.ROLE else role)['AssumeRolePolicyDocument']}}
        iam.list_attached_role_policies.return_value={'AttachedPolicies':[]}
        def policies():
            result={v['PolicyName']:v['PolicyDocument'] for v in role['Policies']}
            if state['active']:
                value=proof['template']['Resources']['RecoveryAccess']['Properties'];result[value['PolicyName']]=value['PolicyDocument']
            return result
        shutdown_policy=shutdown_role['Policies'][0]
        iam.list_role_policies.side_effect=lambda **kw:{'PolicyNames':[shutdown_policy['PolicyName']] if kw['RoleName']==p.shutdown.ROLE else list(policies())}
        iam.get_role_policy.side_effect=lambda **kw:{'PolicyDocument':shutdown_policy['PolicyDocument'] if kw['RoleName']==p.shutdown.ROLE else policies()[kw['PolicyName']]}
        old={'builder':{'status':{'S':'COMPLETE'}},'inspector':{'status':{'S':'STARTED'},
            'reservation_status':{'S':'HELD'},'reserved_micro_usd':{'N':'250000'}},'qa':None}
        old['qa']=copy.deepcopy(old['inspector']);old['inspector_recovery']=copy.deepcopy(old['inspector'])
        old['qa_recovery001']=copy.deepcopy(old['inspector'])
        if mode=='previous_qa_reset':old['qa_recovery001']=None
        if mode=='old_qa_reset':old['qa']=None
        if mode=='old_inspector_reset':old['inspector_recovery']=None
        def item(**kw):
            if kw['TableName']==p.PREVIOUS_QA_TABLE:return {'Item':old['qa_recovery001']}
            if kw['TableName']==p.INSPECTOR_TABLE:return {'Item':old['inspector_recovery']}
            if kw['TableName']==p.TABLE:return {'Item':{'status':{'S':'STARTED'}}} if mode=='already_used' else {'Item':state['attempt']}
            role_name=kw['Key']['PK']['S'].rsplit('#',1)[-1];return {'Item':old[role_name]}
        db.get_item.side_effect=item
        s3.get_object.return_value={'VersionId':proof['code']['S3ObjectVersion'],'Body':io.BytesIO(blob)}
        sts.get_caller_identity.return_value={'Account':'666730517561'}
        events.list_rule_names_by_target.return_value={'RuleNames':[]}
        scheduler.get_paginator.return_value.paginate.return_value=[]
        schedule=p.shutdown.properties(proof['shutdown_deadline'],now=fx.now,armed=mode!='shutdown_missing')
        scheduler.get_schedule.side_effect=lambda **kw:copy.deepcopy(schedule)
        def disarm(**kw):
            self.assertLessEqual(len(kw.pop('ClientToken')),64)
            calls.append('disarm');schedule.update(kw)
        scheduler.update_schedule.side_effect=disarm
        def invoke(**kw):
            calls.append('invoke');state['attempt']={'status':{'S':'STARTED'}}
            if mode=='invoke_timeout':raise TimeoutError('private detail')
            result={'status':'QA_RECOVERY002_FAILED_NO_RETRY' if mode=='review_failure' else 'QA_RECOVERY002_COMPLETED_UNSIGNED',
                'role':'qa','recovery_scope_digest':'sha256:'+p.SCOPE_SHA256,'gate_authority':False,'production_release_authorized':False}
            if mode=='review_failure':result.update(accepted_review=False,attempt_reusable=False,failure_stage='response')
            else:result.update(actual_micro_usd=0,transport_invocations=1,request_digest=p.REQUEST_DIGEST,
                source_commit=plan['activation']['source_commit'],approval_digest=p.signing.digest(plan['allowance_payload']),reservation_status='HELD')
            if mode=='wrong_cost':result['actual_micro_usd']=1
            raw=b'x'*524289 if mode=='oversized' else json.dumps(result).encode()
            return {'StatusCode':200,'Payload':io.BytesIO(raw)}
        lam.invoke.side_effect=invoke
        clients={'cloudformation':cf,'lambda':lam,'dynamodb':db,'iam':iam,'s3':s3,'sts':sts,'events':events,'scheduler':scheduler}
        session=Mock();session.client.side_effect=lambda service,**kw:clients[service]
        runtime_args={}
        if mode=='runtime_deadline':runtime_args['shutdown_deadline']=proof.pop('shutdown_deadline')
        if mode=='no_deadline':proof.pop('shutdown_deadline')
        if mode=='conflicting_deadline':runtime_args['shutdown_deadline']=proof['shutdown_deadline']+1
        with tempfile.TemporaryDirectory() as directory,patch.object(p.signing,'validate_plan',return_value=plan['allowance_payload']),patch.object(p,'verify'):
            args={'approved_plan_digest':proof['plan_digest'],'approved_preview_digest':p.signing.digest(proof),
                'signing_workflow_run':1,'output':Path(directory),'session':session,'clock':lambda:fx.now,'sleep':lambda _:None,**runtime_args}
            if mode in ('already_used','shutdown_missing','no_deadline','conflicting_deadline','old_qa_reset','old_inspector_reset','previous_qa_reset','previous_qa_worker_drift'):
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
        self.assertEqual(calls.count('invoke'),1);self.assertTrue(report['shutdown_verified']);self.assertTrue(report['schedule_disabled'])
        self.assertFalse(state['active']);self.assertEqual(report['shutdown_errors'],[])

    def test_uncertain_activation_disables_without_invoking(self):
        report,calls,_=self.run_case('activation_timeout')
        self.assertNotIn('invoke',calls);self.assertTrue(report['shutdown_verified'])

    def test_uncertain_invocation_does_not_retry(self):
        report,calls,_=self.run_case('invoke_timeout')
        self.assertEqual(calls.count('invoke'),1);self.assertEqual(report['status'],'STOPPED_NO_RETRY');self.assertTrue(report['shutdown_verified'])

    def test_already_consumed_recovery_never_activates(self):self.run_case('already_used')

    def test_consumed_original_holds_cannot_be_reset(self):
        for mode in ('old_qa_reset','old_inspector_reset','previous_qa_reset','previous_qa_worker_drift'):self.run_case(mode)

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
        for mode in ('review_failure','oversized','wrong_cost'):
            report,_,_=self.run_case(mode);self.assertEqual(report['status'],'STOPPED_NO_RETRY');self.assertTrue(report['shutdown_verified'])

    def test_rollback_failure_reported_with_concurrency_forced_off(self):
        report,_,state=self.run_case('rollback_failure')
        self.assertFalse(report['shutdown_verified']);self.assertTrue(state['off']);self.assertTrue(report['shutdown_errors']);self.assertFalse(report['schedule_disabled'])


if __name__=='__main__':unittest.main()
