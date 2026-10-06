"""Synthetic deployment fixtures; no live signing, claims or provider traffic."""
import base64
from datetime import timedelta
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import test_review_role_lambda as role_fixtures
from test_review_provider_scope import fixture
from scripts.scope_dispatch_canary import sign
from factory_runtime import review_controller_lambda as entry
from factory_runtime.worker import digest
from factory_state.model import StateError
from factory_state.scope import canonical


class ControllerEntryTests(unittest.TestCase):
    def setUp(self):
        self.f=role_fixtures.EntryTests();self.f.setUp();self.addCleanup(self.f.doCleanups)
        self.now=self.f.f.now;self.root=self.f.root;self.material=self.f.material
        self.env={'FACTORY_BOUNDED_CONTROLLER_ENABLED':'true','AWS_REGION':'ca-central-1',
            'AWS_LAMBDA_FUNCTION_NAME':entry.NAME,
            'FACTORY_BOUNDED_REVIEW_MATERIAL_DIGEST':digest(self.f.raw)}
        self.doc={'activation':{'activation_id':entry.TASK,'factory_id':entry.FACTORY,'task_id':entry.TASK,
            'source_commit':self.material.source_commit,'contract_digest':digest(self.material.contract_bytes),
            'starts_at':(self.now-timedelta(seconds=1)).isoformat(),
            'expires_at':(self.now+timedelta(seconds=300)).isoformat()},
            'function_arns':{r:f'arn:aws:lambda:ca-central-1:666730517561:function:tims-factory-{r}:1'
                             for r in entry.PROVIDERS},
            'job_versions':{s:{'version_id':'fixture-version','sha256':'sha256:'+'a'*64} for s in entry.ROLES},
            'providers':{}}
        for role in entry.PROVIDERS:
            _,price,ready,payload=fixture(role)
            for value in (price,ready,payload):
                value.update(self.material.prepared(role).scope.bindings(),
                    issued_at=int(self.now.timestamp())-1,expires_at=int(self.now.timestamp())+600)
            payload.update(pricing_digest=digest(canonical(price)),readiness_digest=digest(canonical(ready)))
            envelope={'payload':payload,'signature_base64':base64.b64encode(
                sign(payload,self.f.private['tim_brydges'],self.f.tmp.name)).decode()}
            self.doc['providers'][role]={'allowance':envelope,'pricing':price,'readiness':ready}
        self.save()
        self.context=SimpleNamespace(invoked_function_arn=f'arn:aws:lambda:ca-central-1:666730517561:function:{entry.NAME}:1',
            get_remaining_time_in_millis=lambda:300000)
        p=patch.object(entry,'load_trusted_signers',return_value=self.f.keys);p.start();self.addCleanup(p.stop)

    def save(self):
        raw=canonical(self.doc);(self.root/'REVIEW_CONTROLLER.json').write_bytes(raw)
        self.env['FACTORY_BOUNDED_REVIEW_CONTROLLER_DIGEST']=digest(raw)

    def load(self):return entry.load_deployment(self.root,self.env,clock=lambda:self.now)
    def dispatch(self,event=None):return entry.dispatch(entry.EVENT if event is None else event,
        self.context,root=self.root,env=self.env,clock=lambda:self.now)

    def test_all_three_real_fixture_signatures_and_routes_validate(self):
        material,activation,doc,versions,keys=self.load()
        self.assertEqual(material,self.material);self.assertEqual(activation.task_id,entry.TASK)
        self.assertEqual(set(versions),set(entry.ROLES));self.assertEqual(keys(self.now),self.f.keys)
        self.assertEqual(len({p['allowance']['payload']['provider'] for p in doc['providers'].values()}),3)

    def test_disabled_rejects_before_files_and_clients(self):
        self.env['FACTORY_BOUNDED_CONTROLLER_ENABLED']='false'
        with patch.object(entry,'_read') as read,patch.object(entry,'_aws_session') as aws:
            with self.assertRaises(StateError):self.dispatch()
            read.assert_not_called();aws.assert_not_called()

    def test_wrong_event_mutable_version_and_bad_pin_reject_before_clients(self):
        with patch.object(entry,'_aws_session') as aws:
            with self.assertRaises(StateError):self.dispatch({**entry.EVENT,'provider':'openai'})
            arn=self.context.invoked_function_arn;self.context.invoked_function_arn=arn.rsplit(':',1)[0]+':$LATEST'
            with self.assertRaises(StateError):self.dispatch()
            self.context.invoked_function_arn=arn;self.env['FACTORY_BOUNDED_REVIEW_CONTROLLER_DIGEST']='sha256:'+'0'*64
            with self.assertRaises(StateError):self.dispatch()
            aws.assert_not_called()

    def test_forged_allowance_and_cross_role_route_reject_despite_matching_pin(self):
        self.doc['function_arns']['qa']=self.doc['function_arns']['builder'];self.save()
        with self.assertRaises(StateError):self.load()
        self.doc['function_arns']['qa']='arn:aws:lambda:ca-central-1:666730517561:function:tims-factory-qa:1'
        self.doc['providers']['inspector']['allowance']['signature_base64']=base64.b64encode(b'x'*64).decode();self.save()
        with self.assertRaises(StateError):self.load()

    def test_activation_cannot_outlive_allowance_or_change_task(self):
        self.doc['activation']['expires_at']=(self.now+timedelta(seconds=601)).isoformat();self.save()
        with self.assertRaises(StateError):self.load()
        self.doc['activation']['expires_at']=(self.now+timedelta(seconds=300)).isoformat()
        self.doc['activation']['task_id']='historical-task';self.save()
        with self.assertRaises(StateError):self.load()

    def test_composition_has_three_credential_free_guards_and_one_fixed_tick(self):
        def fake(service):return SimpleNamespace(meta=SimpleNamespace(
            endpoint_url=f'https://{service}.ca-central-1.amazonaws.com',
            config=SimpleNamespace(retries={'total_max_attempts':1})))
        db=fake('dynamodb');sts=fake('sts')
        sts.get_caller_identity=lambda:{'Account':'666730517561',
            'Arn':f'arn:aws:sts::666730517561:assumed-role/{entry.EXECUTION_ROLE}/fixture'}
        with patch.object(entry,'_aws_session',return_value=object()),\
                patch.object(entry,'client',side_effect=lambda s,n:{'sts':sts,'dynamodb':db}[n]),\
                patch.object(entry,'runtime_client',side_effect=lambda s,n:fake(n)),\
                patch.object(entry,'BoundedReviewController') as controller:
            controller.return_value.tick.return_value={'status':'FIXTURE'}
            self.assertEqual(self.dispatch(),{'status':'FIXTURE'})
            controller.return_value.tick.assert_called_once_with(entry.FACTORY,entry.TASK)
            config=controller.call_args.kwargs
            self.assertEqual(config['test_count'],17)
            self.assertEqual(set(config['guards']),set(entry.PROVIDERS))
            for role,guard in config['guards'].items():
                self.assertIsNone(guard.load_credential)
                self.assertEqual(guard.prepared.scope.role,role)
            sts.get_caller_identity=lambda:{'Account':'666730517561','Arn':'wrong-role'}
            controller.reset_mock()
            with self.assertRaises(StateError):self.dispatch()
            controller.assert_not_called()
