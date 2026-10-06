import base64,json
from unittest.mock import Mock,patch
import unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
from test_handoff003_qa_paid_recovery_authorization import RecoveryAuthorizationTests,ROOT
from test_pilot002_transport import Connection,Response,KEY
from factory_runtime import handoff003_qa_paid_recovery_runtime as r
from factory_runtime.handoff003_packets import review_packet,REVIEW_BINDINGS
from factory_runtime.pilot002_transport import ProviderTimeoutError
from factory_state.scope import canonical
from factory_state.model import StateError

class RecoveryRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.f=RecoveryAuthorizationTests();self.f.setUp()
        private=Ed25519PrivateKey.generate();self.keys={**self.f.keys,r.IDENTITIES['qa']:private.public_key().public_bytes(Encoding.PEM,PublicFormat.SubjectPublicKeyInfo)}
        self.trace=[];self.claimed=False;self.db=Mock()
        def claim(**kwargs):
            self.trace.append('claim')
            if self.claimed:raise RuntimeError('consumed')
            self.claimed=True
        self.db.put_item.side_effect=claim
        self.db.update_item.side_effect=lambda **kwargs:self.trace.append('complete')
        def credential():self.trace.append('credential');return KEY
        def sign(payload,**kwargs):self.trace.append('sign');return private.sign(canonical(payload))
        self.args=dict(root=ROOT,source_commit='a'*40,qualification=self.f.q,readiness=self.f.r,trusted_keys=self.keys,
            store=r.RecoveryAttemptStore(self.db),load_credential=credential,sign_receipt=sign,clock=lambda:self.f.now,enabled=True)
        self.builder=base64.b64decode(json.loads((ROOT/'factory/evidence/handoff-003-live/builder-live-result.json').read_bytes())['output_base64'])
        packet=review_packet(ROOT,role='qa',builder_response=self.builder,candidate_commit=r.CANDIDATE)
        output={**{k:packet[k] for k in REVIEW_BINDINGS},'verdict':'ACCEPTED','rationale':'Synthetic independent review','findings':[]}
        self.raw=canonical({'modelVersion':'gemini-3.7-flash','candidates':[{'finishReason':'STOP','content':{'role':'model','parts':[{'text':canonical(output).decode()}]}}],
            'usageMetadata':{'promptTokenCount':100,'candidatesTokenCount':30,'totalTokenCount':130}})
    def run_once(self,**changes):return r.run_once(self.f.signed(),**{**self.args,**changes})
    def test_claim_precedes_one_provider_call_and_signature_completion(self):
        with patch.object(r,'RecoveryTransport') as t:
            def send(**kw):self.trace.append('send');return self.raw
            t.return_value.send_once.side_effect=send
            result=self.run_once()
            self.assertEqual(self.trace,['claim','credential','send','sign','complete'])
            self.assertEqual(result['payload']['kind'],'handoff003_qa_paid_recovery002_result')
            self.assertEqual(result['payload']['actual_micro_usd'],188)
            with self.assertRaisesRegex(r.RecoveryStopped,'reservation'):self.run_once()
            t.return_value.send_once.assert_called_once()
    def test_provider_timeout_consumes_claim_and_keeps_redacted_category(self):
        with patch.object(r,'RecoveryTransport') as t:
            t.return_value.send_once.side_effect=ProviderTimeoutError()
            with self.assertRaises(r.RecoveryStopped) as error:self.run_once()
            self.assertEqual(error.exception.failure_code,'timeout')
            with self.assertRaisesRegex(r.RecoveryStopped,'reservation'):self.run_once()
            t.return_value.send_once.assert_called_once();self.db.update_item.assert_not_called()
    def test_disabled_or_wrong_store_never_claims_or_reads_credentials(self):
        with self.assertRaisesRegex(StateError,'disabled'):self.run_once(enabled=False)
        with self.assertRaisesRegex(StateError,'Isolated'):self.run_once(store=Mock())
        self.assertEqual(self.trace,[])
    def test_receipt_or_completion_failure_does_not_repeat_provider(self):
        self.db.update_item.side_effect=TimeoutError('private detail')
        with patch.object(r,'RecoveryTransport') as t:
            t.return_value.send_once.return_value=self.raw
            with self.assertRaisesRegex(r.RecoveryStopped,'completion'):self.run_once()
            with self.assertRaisesRegex(r.RecoveryStopped,'reservation'):self.run_once()
            t.return_value.send_once.assert_called_once()
    def test_invalid_provider_output_or_signature_never_completes(self):
        for failure in ('response','signing'):
            with self.subTest(failure=failure):
                self.setUp()
                if failure=='signing':self.args['sign_receipt']=lambda *a,**k:b'not a valid signature'
                with patch.object(r,'RecoveryTransport') as t:
                    t.return_value.send_once.return_value=b'{}' if failure=='response' else self.raw
                    with self.assertRaisesRegex(r.RecoveryStopped,failure):self.run_once()
                    with self.assertRaisesRegex(r.RecoveryStopped,'reservation'):self.run_once()
                    t.return_value.send_once.assert_called_once();self.db.update_item.assert_not_called()
    def test_qa_transport_has_fixed_longer_timeout_and_no_retries(self):
        from factory_runtime import pilot002_transport as transport
        connection=Connection(Response(self.raw))
        with patch.object(transport.http.client,'HTTPSConnection',return_value=connection) as connect:
            t=r.RecoveryTransport(ROOT,role='qa',builder_response=self.builder,candidate_commit=r.CANDIDATE,enabled=True)
            kw={'request_bytes':self.f.args['request_bytes'],'credential':KEY,'expected_request_digest':self.f.bound['request_digest']}
            self.assertEqual(t.send_once(**kw),self.raw)
            self.assertEqual(connect.call_args.kwargs['timeout'],150)
            with self.assertRaisesRegex(StateError,'already attempted'):t.send_once(**kw)
            self.assertEqual(len(connection.calls),1)
        with self.assertRaisesRegex(StateError,'QA-only'):r.RecoveryTransport(ROOT,role='builder')
