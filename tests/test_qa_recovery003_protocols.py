import copy
import base64
import hashlib
import json
import unittest
from pathlib import Path
from unittest.mock import patch
from factory_state.model import StateError
from factory_state.scope import canonical
from factory_runtime import pilot002_packets as old_packets,pilot002_protocols as old_protocols
from factory_runtime import qa_recovery003_packets as packets,qa_recovery003_protocols as protocols
from factory_runtime.qa_recovery003 import CANDIDATE,REQUEST_DIGEST,digest
from factory_runtime.qa_recovery003_transport import Pilot002Transport
import test_qa_recovery003_runtime as runtime

ROOT=Path(__file__).resolve().parents[1]


class RecoveryModelIsolationTests(unittest.TestCase):
    def setUp(self):
        self.args={'role':'qa','builder_response':(ROOT/'tests/pilot002_reviewer_builder_context.json').read_bytes(),'candidate_commit':CANDIDATE}

    def test_model_override_preserves_original_and_rebinds_contract_and_request(self):
        before=old_packets.review_packet(ROOT,**self.args)
        historical=old_protocols.request_bytes(ROOT,**self.args)
        new=packets.review_packet(ROOT,**self.args)
        self.assertEqual(old_packets.review_packet(ROOT,**self.args),before)
        self.assertEqual(digest(historical),'sha256:6891cd13c024807b3d02ff30e6f5872207deeeb38f4c7fd23b7ec825c6ef4ed7')
        self.assertEqual(new['model_id'],'gemini-3.7-flash')
        self.assertEqual(new['original_contract_digest'],before['contract_digest'])
        for key in ('contract_digest','packet_digest'):self.assertNotEqual(new[key],before[key])
        for key in ('candidate_digest','builder_response_digest','builder_packet_digest','untrusted_files','criteria'):
            self.assertEqual(new[key],before[key])
        old_providers=copy.deepcopy(before['untrusted_contract']['providers'])
        next(p for p in old_providers if p['role']=='qa')['model_id']='gemini-3.7-flash'
        self.assertEqual(new['untrusted_contract']['providers'],old_providers)
        self.assertEqual(digest(protocols.request_bytes(ROOT,**self.args)),REQUEST_DIGEST)

    def test_actual_send_uses_only_37_endpoint_and_once(self):
        fx=runtime.RecoveryRuntimeTests();fx.setUp();fx.run_event()
        call=fx.connection.request.call_args
        self.assertEqual(call.args[:2],('POST','/v1beta/models/gemini-3.7-flash:generateContent'))
        self.assertEqual(digest(call.kwargs['body']),REQUEST_DIGEST)
        with self.assertRaises(StateError):fx.run_event()
        self.assertEqual(fx.connection.request.call_count,1)

    def test_old_request_rejected_before_network(self):
        transport=Pilot002Transport(ROOT,**self.args,enabled=True)
        old=old_protocols.request_bytes(ROOT,**self.args)
        with patch('http.client.HTTPSConnection') as connection,self.assertRaises(StateError):
            transport.send_once(request_bytes=old,credential='synthetic-private-key',expected_request_digest=digest(old))
        connection.assert_not_called()

    def test_old_model_or_old_review_bindings_rejected(self):
        fx=runtime.RecoveryRuntimeTests();fx.setUp()
        envelope=json.loads(fx.raw)
        envelope['modelVersion']='gemini-3.8-flash'
        with self.assertRaises(StateError):protocols.parse_response(canonical(envelope),ROOT,**self.args)
        envelope=json.loads(fx.raw)
        packet=old_packets.review_packet(ROOT,**self.args)
        value=json.loads(envelope['candidates'][0]['content']['parts'][0]['text'])
        value.update({k:packet[k] for k in packets.REVIEW_BINDINGS})
        envelope['candidates'][0]['content']['parts'][0]['text']=canonical(value).decode()
        with self.assertRaises(StateError):protocols.parse_response(canonical(envelope),ROOT,**self.args)

    def test_other_roles_and_candidate_rejected(self):
        for args in ({**self.args,'role':'builder'},{**self.args,'role':'inspector'},{**self.args,'candidate_commit':'a'*40}):
            with self.assertRaises(StateError):protocols.request_bytes(ROOT,**args)

    def test_37_review_cannot_be_relabelled_as_original_38_review(self):
        fx=runtime.RecoveryRuntimeTests();fx.setUp()
        text=json.loads(fx.raw)['candidates'][0]['content']['parts'][0]['text'].encode()
        with self.assertRaises(StateError):old_packets.parse_review(text,root=ROOT,**self.args)

    def captured_response(self):
        evidence=json.loads((ROOT/'factory/evidence/qa-recovery-003-response-407.json').read_bytes())
        raw=base64.b64decode(evidence['lambda_result']['provider_response_base64'],validate=True)
        self.assertEqual(hashlib.sha256(raw).hexdigest(),'367c56e4cc233321cfc2d417dd61e0d86ae76bd3ae25fd92fa97c44a245ec3fe')
        return raw

    def test_exact_captured_standard_response_parses_without_network_or_authority(self):
        with patch('http.client.HTTPSConnection') as network:
            parsed=protocols.parse_response(self.captured_response(),ROOT,**self.args)
        network.assert_not_called()
        self.assertEqual(parsed['usage'],{'input_tokens':5468,'output_tokens_including_reasoning':424,'total_tokens':5892})
        self.assertEqual(parsed['parsed_output']['verdict'],'ACCEPTED')
        self.assertFalse(parsed['gate_authority']);self.assertFalse(parsed['production_release_authorized'])

    def test_standard_metadata_does_not_allow_other_tiers_or_unknown_usage(self):
        original=json.loads(self.captured_response())
        for tier in ('priority','flex','unspecified','',None,True,{},[]):
            bad=copy.deepcopy(original);bad['usageMetadata']['serviceTier']=tier
            with self.subTest(tier=tier),self.assertRaises(StateError):
                protocols.parse_response(canonical(bad),ROOT,**self.args)
        for change in ({'unknownField':0},{'cachedContentTokenCount':1},{'toolUsePromptTokenCount':1},
                       {'totalTokenCount':5893}):
            bad=copy.deepcopy(original);bad['usageMetadata'].update(change)
            with self.assertRaises(StateError):protocols.parse_response(canonical(bad),ROOT,**self.args)
        del original['usageMetadata']['serviceTier']
        self.assertEqual(protocols.parse_response(canonical(original),ROOT,**self.args)['usage']['total_tokens'],5892)
