import base64
import contextlib
import copy
import hashlib
import io
import json
from datetime import datetime,timezone
from pathlib import Path
import runpy
import sys
import tempfile
import unittest
from unittest.mock import Mock,patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
import prepare_pilot002_inspector_live as p
import sign_pilot002_reviewer_allowance as signer


class InspectorLiveTests(unittest.TestCase):
    def setUp(self):
        self.proof=json.loads((ROOT/'factory/evidence/pilot-002-inspector-live-preview.json').read_bytes())
        self.plan=json.loads((ROOT/'factory/evidence/pilot-002-inspector-live-review-candidate.json').read_bytes())
        self.now=datetime.fromisoformat(self.plan['prepared_at'])

    def changes(self):
        return {'Status':'CREATE_COMPLETE','ExecutionStatus':'AVAILABLE','StackId':p.STACK,'Changes':self.proof['changes']}

    def test_exact_plan_and_preview_validate_at_recorded_time(self):
        signer.validate_plan(self.plan,root=ROOT,role='inspector',approved_digest=p.PLAN,now=self.now)
        result=p.validate(self.proof['template'],self.changes(),self.proof['package'],self.proof['code'])
        self.assertEqual(result['maximum_provider_calls'],1)
        self.assertEqual(self.plan['pricing']['maximum_cost_micro_usd'],159744)
        for role in ('Builder','Qa'):
            self.assertEqual(self.proof['template']['Resources'][role+'Function'],p.baseline()['Resources'][role+'Function'])

    def test_expanded_preview_replacement_and_wrong_package_fail_closed(self):
        for mutate in (lambda x:x.update(NextToken='more'),lambda x:x['Changes'].append(copy.deepcopy(x['Changes'][0])),
                lambda x:x['Changes'][0]['ResourceChange'].update(Replacement='True')):
            changes=copy.deepcopy(self.changes());mutate(changes)
            with self.assertRaises(Exception):p.validate(self.proof['template'],changes,self.proof['package'],self.proof['code'])
        for field,value in [('activation_sha256','0'*64),('source_commit','0'*40),('signed_allowance_included',True)]:
            package=copy.deepcopy(self.proof['package']);package[field]=value
            with self.assertRaises(Exception):p.render(p.baseline(),package,self.proof['code'])

    def run_fixture(self,mode):
        proof=copy.deepcopy(self.proof);blob=b'offline-package-fixture'
        proof['package'].update(sha256=hashlib.sha256(blob).hexdigest(),code_sha256=base64.b64encode(hashlib.sha256(blob).digest()).decode(),zip_bytes=len(blob))
        proof['code']['S3Key']='pilot-002/runtime/'+p.SOURCE+'/'+proof['package']['sha256']+'.zip'
        proof['template']=p.render(p.baseline(),proof['package'],proof['code'])
        state={'active':False,'forced_off':False,'attempted':False}
        cf=Mock();lam=Mock();db=Mock();sts=Mock();s3=Mock();events=Mock()
        cf.get_template.side_effect=lambda **kw:{'TemplateBody':proof['template'] if 'ChangeSetName' in kw or state['active'] else proof['rollback_template']}
        cf.describe_change_set.return_value=self.changes()
        cf.describe_stacks.return_value={'Stacks':[{'StackStatus':'UPDATE_COMPLETE'}]}
        def execute(**kw):
            state['active']=True
            if mode=='activation_timeout':raise TimeoutError('uncertain activation')
        cf.execute_change_set.side_effect=execute
        cf.update_stack.side_effect=lambda **kw:state.update(active=False)
        def function(FunctionName):
            role=FunctionName.rsplit('-',1)[-1]
            template=proof['template'] if state['active'] else proof['rollback_template']
            f=template['Resources'][role.title()+'Function']['Properties']
            code=('bfxa39U+CrnS05GTMT4DgHIC8KKWVHAxKbvgrcP37M4=' if role=='builder' else
                proof['package']['code_sha256'] if role=='inspector' and state['active'] else 'db7WTGzE+2ZpU064Y8Jt4DP89yDL+tzU/4U0E4OsAO4=')
            return {'FunctionName':FunctionName,'CodeSha256':code,'LastUpdateStatus':'Successful',
                'Handler':f['Handler'],'Timeout':f['Timeout'],'Environment':f['Environment']}
        lam.get_function_configuration.side_effect=function
        lam.get_function_concurrency.side_effect=lambda FunctionName:{} if FunctionName.endswith('inspector') and state['active'] and not state['forced_off'] else {'ReservedConcurrentExecutions':0}
        lam.put_function_concurrency.side_effect=lambda **kw:state.update(forced_off=True)
        lam.get_account_settings.return_value={'AccountLimit':{'UnreservedConcurrentExecutions':10}}
        lam.list_event_source_mappings.return_value={'EventSourceMappings':[]}
        lam.list_aliases.return_value={'Aliases':[]}
        class NotFound(Exception):pass
        lam.exceptions.ResourceNotFoundException=NotFound
        lam.get_policy.side_effect=NotFound;lam.get_function_url_config.side_effect=NotFound
        events.list_rule_names_by_target.return_value={'RuleNames':[]}
        sts.get_caller_identity.return_value={'Account':'666730517561'}
        s3.get_object.return_value={'VersionId':proof['code']['S3ObjectVersion'],'Body':io.BytesIO(blob)}
        db.get_item.side_effect=lambda **kw:{'Item':{'status':{'S':'STARTED'}}} if mode=='already_used' else {}
        def invoke(**kw):
            state['attempted']=True
            if mode=='invoke_timeout':raise TimeoutError('uncertain invocation')
            return {'StatusCode':200,'Payload':io.BytesIO(json.dumps({'status':'PILOT002_COMPLETED_UNSIGNED','actual_micro_usd':10000,'transport_invocations':1}).encode())}
        lam.invoke.side_effect=invoke
        scheduler=Mock();scheduler.get_paginator.return_value.paginate.return_value=[{'Schedules':[]}]
        clients={'cloudformation':cf,'lambda':lam,'dynamodb':db,'sts':sts,'s3':s3,'events':events,'scheduler':scheduler}
        session=Mock();session.client.side_effect=lambda name,**kw:clients[name]
        now=self.now
        class Clock(datetime):
            @classmethod
            def now(cls,tz=None):return now
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'scripts').mkdir();out=root/'output';out.mkdir()
            script=root/'scripts/run.py';script.write_bytes((ROOT/'scripts/run_pilot002_inspector_once.py').read_bytes())
            from build_pilot002_runtime_package import MATERIAL
            for name in MATERIAL:
                target=root/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes((ROOT/name).read_bytes())
            for name,value in [('pilot-002-inspector-live-review-candidate.json',self.plan),('pilot-002-inspector-live-preview.json',proof)]:
                (root/'factory/evidence'/name).write_text(json.dumps(value))
            allowance=root/'allowance.json';allowance.write_text(json.dumps({'payload':self.plan['allowance_payload'],'signature':'fixture'}))
            argv=[str(script),str(allowance),str(out),'--approved-plan-digest',p.PLAN,'--approved-change-set',proof['change_set_arn'],'--signing-workflow-run','1']
            # Cryptography is tested separately; this exercises runner ordering,
            # uncertain SDK outcomes, exclusive markers, and verified shutdown.
            with patch('sys.argv',argv),patch('datetime.datetime',Clock),patch('time.time',return_value=now.timestamp()),\
                    patch('boto3.Session',return_value=session),patch('factory_runtime.pilot002_authorization.verify'),\
                    patch('factory_state.signers.validate_trusted_signers',return_value={}),contextlib.redirect_stdout(io.StringIO()):
                if mode=='already_used':
                    with self.assertRaises(AssertionError):runpy.run_path(str(script),run_name='__main__')
                    cf.execute_change_set.assert_not_called();lam.invoke.assert_not_called();return
                runpy.run_path(str(script),run_name='__main__')
                report=json.loads((out/'inspector-report.json').read_bytes())
                self.assertTrue(report['shutdown_verified']);self.assertEqual(report['shutdown_errors'],[])
                self.assertFalse(state['active']);self.assertTrue(state['forced_off'])
                self.assertEqual(lam.invoke.call_count,0 if mode=='activation_timeout' else 1)
                self.assertEqual(cf.execute_change_set.call_count,1)
                with self.assertRaises(FileExistsError):runpy.run_path(str(script),run_name='__main__')
                self.assertEqual(cf.execute_change_set.call_count,1)

    def test_success_invokes_once_and_disables(self):self.run_fixture('success')
    def test_uncertain_invocation_is_not_retried_and_disables(self):self.run_fixture('invoke_timeout')
    def test_uncertain_activation_never_invokes_and_disables(self):self.run_fixture('activation_timeout')
    def test_used_attempt_never_activates(self):self.run_fixture('already_used')


if __name__=='__main__':unittest.main()
