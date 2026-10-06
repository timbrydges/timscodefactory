import base64
import json
import tempfile
import unittest
from dataclasses import asdict
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch, Mock

import test_review_test_proof_import as proof_fixtures
from test_review_provider_scope import fixture
from scripts.prepare_bounded_review_material import prepare
from scripts.scope_dispatch_canary import fixture_keys, sign
from factory_runtime import review_role_lambda as entry
from factory_runtime.review_material import PinnedReviewMaterial
from factory_runtime.worker import digest
from factory_state.model import StateError
from factory_state.scope import canonical


class EntryTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        self.f=proof_fixtures.TestProofImportTests();self.f.setUp();self.addCleanup(self.f.doCleanups)
        self.keys,self.private=fixture_keys(self.tmp.name,('tim_brydges',))
        self.raw=prepare(self.f.commit,123,api=self.f.api,clock=lambda:self.f.now)
        self.material=PinnedReviewMaterial.load(self.raw,expected_digest=digest(self.raw),
            deployed_commit=self.f.commit,clock=lambda:self.f.now)
        (self.root/'REVIEW_MATERIAL.json').write_bytes(self.raw)
        (self.root/'BUILD.json').write_bytes(canonical({'source_commit':self.f.commit}))
        self.env={'FACTORY_BOUNDED_REVIEW_ENABLED':'true','FACTORY_BOUNDED_REVIEW_ROLE':'qa',
            'FACTORY_BOUNDED_REVIEW_MATERIAL_DIGEST':digest(self.raw),'AWS_REGION':'ca-central-1',
            'AWS_LAMBDA_FUNCTION_NAME':'tims-factory-qa'}
        scope=self.material.prepared('qa').scope
        _,price,ready,payload=fixture('qa')
        times={'issued_at':int(self.f.now.timestamp())-1,'expires_at':int(self.f.now.timestamp())+600}
        for value in (price,ready,payload):value.update(scope.bindings(),**times)
        payload.update(pricing_digest=digest(canonical(price)),readiness_digest=digest(canonical(ready)))
        envelope={'payload':payload,'signature_base64':base64.b64encode(
            sign(payload,self.private['tim_brydges'],self.tmp.name)).decode()}
        self.doc={'role':'qa','allowance':envelope,'pricing':price,'readiness':ready,
            'credential':{'kind':'secretsmanager','secret_arn':entry.SECRETS['qa'],
                          'version_id':'a'*32,'json_key':'api_key'}}
        self.save_doc()
        self.context=SimpleNamespace(invoked_function_arn='arn:aws:lambda:ca-central-1:666730517561:function:tims-factory-qa:1',
                                     get_remaining_time_in_millis=lambda:180000)
        self.event={'schema_version':'1.0','factory_id':'tims-software-factory','task_id':'bounded-review-002',
            'worker_id':'bounded-review-controller','dispatch_id':'d'*64,'request':asdict(scope.request),
            'input_base64':base64.b64encode(self.material.prepared('qa').input_bytes).decode()}
        key_patch=patch.object(entry,'load_trusted_signers',return_value=self.keys)
        key_patch.start();self.addCleanup(key_patch.stop)

    def save_doc(self):
        raw=canonical(self.doc);(self.root/'REVIEW_ROLE.json').write_bytes(raw)
        self.env['FACTORY_BOUNDED_REVIEW_ROLE_DIGEST']=digest(raw)

    def load(self):return entry.load_deployment(self.root,self.env,clock=lambda:self.f.now)
    def dispatch(self):return entry.dispatch(self.event,self.context,root=self.root,env=self.env,clock=lambda:self.f.now)

    def test_valid_signed_deployment_and_immutable_secret_version(self):
        role,material,doc,keys=self.load()
        self.assertEqual(role,'qa');self.assertEqual(material,self.material)
        self.assertEqual(doc['credential']['version_id'],'a'*32)
        self.assertEqual(keys(self.f.now),self.keys)

    def test_forged_signature_or_changed_secret_is_rejected_even_with_new_file_hash(self):
        self.doc['credential']['secret_arn']=entry.SECRETS['builder'];self.save_doc()
        with self.assertRaises(StateError):self.load()
        self.doc['credential']['secret_arn']=entry.SECRETS['qa']
        self.doc['allowance']['signature_base64']=base64.b64encode(b'x'*64).decode();self.save_doc()
        with self.assertRaises(StateError):self.load()

    def test_disabled_has_no_file_or_sdk_access(self):
        self.env['FACTORY_BOUNDED_REVIEW_ENABLED']='false'
        with patch.object(entry,'_read',side_effect=AssertionError('file')),patch.object(entry,'_aws_session') as aws:
            with self.assertRaises(StateError):self.dispatch()
            aws.assert_not_called()

    def test_mutable_version_changed_event_and_wrong_pin_stop_before_clients(self):
        with patch.object(entry,'_aws_session') as aws:
            old=self.context.invoked_function_arn
            self.context.invoked_function_arn=old.rsplit(':',1)[0]+':$LATEST'
            with self.assertRaises(StateError):self.dispatch()
            self.context.invoked_function_arn=old
            self.event['task_id']='historical-task'
            with self.assertRaises(StateError):self.dispatch()
            self.event['task_id']='bounded-review-002';self.env['FACTORY_BOUNDED_REVIEW_ROLE_DIGEST']='sha256:'+'0'*64
            with self.assertRaises(StateError):self.dispatch()
            aws.assert_not_called()

    def test_qa_composition_defers_secret_read_to_backend(self):
        session=object()
        db=SimpleNamespace(meta=SimpleNamespace(endpoint_url='https://dynamodb.ca-central-1.amazonaws.com',
            config=SimpleNamespace(retries={'total_max_attempts':1})))
        sts=SimpleNamespace(get_caller_identity=lambda:{'Account':'666730517561',
            'Arn':'arn:aws:sts::666730517561:assumed-role/tims-factory-review-qa/test'})
        clients={'sts':sts,'dynamodb':db,'kms':object()}
        validate_event=entry.BoundedReviewRoleRuntime.validate_event
        with patch.object(entry,'_aws_session',return_value=session),patch.object(entry,'client',side_effect=lambda s,n:clients[n]),\
                patch.object(entry,'_credential') as secret,patch.object(entry,'BoundedReviewRoleRuntime') as runtime:
            runtime.return_value=SimpleNamespace(handle=Mock(return_value={'fixture':True}))
            # Keep event validation real; only replace the final service transport.
            runtime.validate_event.side_effect=validate_event
            result=self.dispatch()
            self.assertEqual(result,{'fixture':True});secret.assert_not_called()
            backend=runtime.call_args.kwargs['backend']
            self.assertEqual(backend.prepared.scope.role,'qa')
            self.assertEqual(backend.evidence.test_count,17)
            backend.load_credential();secret.assert_called_once_with(session,self.doc['credential'])
            from factory_runtime.pilot002_transport import ProviderHTTPStatusError, ProviderTimeoutError
            for cause,expected in ((ProviderHTTPStatusError(429),'http 429'),
                                   (ProviderTimeoutError(),'timeout'),(RuntimeError('secret'),'unknown')):
                failure=entry.BoundedProviderFailure('provider transport',cause)
                failure.args=('secret provider body',)
                runtime.return_value.handle.side_effect=failure
                with self.assertRaises(entry.BoundedProviderFailure) as error:self.dispatch()
                self.assertIn(expected,str(error.exception))
                self.assertNotIn('secret',str(error.exception))
            from factory_runtime.review_provider_protocol import ResponseValidationFailure
            for code,expected in (('output-binding','output-binding'),('secret','provider-envelope')):
                failure=entry.BoundedProviderFailure('response validation',ResponseValidationFailure('output-binding'))
                failure.category=code;failure.args=('secret response',)
                runtime.return_value.handle.side_effect=failure
                with self.assertRaises(entry.BoundedProviderFailure) as error:self.dispatch()
                self.assertIn(expected,str(error.exception))
                self.assertNotIn('secret',str(error.exception))

    def test_wrong_execution_role_stops_before_backend_and_redacts_sdk_errors(self):
        sts=SimpleNamespace(get_caller_identity=lambda:{'Account':'666730517561',
            'Arn':'arn:aws:sts::666730517561:assumed-role/tims-factory-executor-builder/test'})
        with patch.object(entry,'_aws_session',return_value=object()),\
                patch.object(entry,'client',return_value=sts) as client,\
                patch.object(entry,'_credential') as secret:
            with self.assertRaisesRegex(StateError,'reconcile permanent claims'):self.dispatch()
            self.assertEqual(client.call_count,1);secret.assert_not_called()
            sts.get_caller_identity=Mock(side_effect=RuntimeError('sensitive SDK detail'))
            with self.assertRaises(StateError) as error:self.dispatch()
            self.assertNotIn('sensitive',str(error.exception));secret.assert_not_called()
