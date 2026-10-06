import base64
import copy
from datetime import datetime, timezone
from pathlib import Path
import unittest
from unittest.mock import Mock, patch
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from factory_runtime import handoff004_packets as packets, handoff004_protocols as protocols
from factory_runtime.handoff004_attempts import Handoff004AttemptStore
from factory_runtime.handoff004_receipts import IDENTITIES, sha, verify_chain
from factory_runtime.handoff004_workflow import prepare_pricing, run_once, HandoffStopped
from factory_state.model import OWNER_IDENTITY, StateError
from factory_state.scope import canonical

ROOT = Path(__file__).resolve().parents[1]


class HandoffWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 10, 6, tzinfo=timezone.utc)
        self.private = {identity: Ed25519PrivateKey.generate() for identity in (OWNER_IDENTITY, *IDENTITIES.values())}
        self.keys = {identity: key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
                     for identity, key in self.private.items()}
        self.db = Mock(); self.claimed = set(); self.trace = []
        def put(**kw):
            self.trace.append('claim')
            key = kw['Item']['PK']['S']
            if key in self.claimed: raise RuntimeError('already consumed')
            self.claimed.add(key)
        self.db.put_item.side_effect = put
        self.db.update_item.side_effect = lambda **_: self.trace.append('complete')
        self.store = Handoff004AttemptStore(self.db)
        self.chain = {}; self.requests = {}

    def setup_role(self, role):
        builder = None if role == 'builder' else base64.b64decode(self.chain['builder']['output_base64'])
        context = {'role': role, **({} if role == 'builder' else {'builder_response': builder, 'candidate_commit': 'b'*40})}
        value = protocols.packet(ROOT, **context)
        raw = protocols.request_bytes(ROOT, **context)
        prior = None if role == 'builder' else sha(canonical(self.chain['builder' if role == 'inspector' else 'inspector']['payload']))
        bindings = {key: value[key] for key in ('role', 'model_id', 'task_id', 'contract_digest', 'packet_digest')}
        bindings.update(source_commit='a'*40, request_digest=sha(raw), predecessor_receipt_digest=prior)
        window = {'issued_at': int(self.now.timestamp())-1, 'expires_at': int(self.now.timestamp())+120}
        qualification = {'kind': 'handoff004_rate_qualification', **bindings, **window,
            'input_token_bound': 512, 'output_token_bound': 4096, 'input_micro_usd_per_million': 4000000,
            'output_micro_usd_per_million': 20000000, 'complete_request_bound_qualified': True,
            'evidence_digest': sha(b'synthetic test qualification')}
        pricing = prepare_pricing(ROOT, source_commit='a'*40, qualification=qualification,
            predecessor_receipt_digest=prior, **context)
        readiness = {'kind': 'handoff004_provider_readiness', **bindings, **window,
            'credential_route_verified': True, 'model_metadata_verified': True, 'repository_binding_verified': True,
            'single_attempt_failure_risk_accepted': True, 'evidence_digest': sha(b'synthetic readiness')}
        payload = {'kind': 'handoff004_exact_request_allowance', 'owner_identity': OWNER_IDENTITY,
            **bindings, **window, 'budget_approval_digest': 'sha256:'+packets.PINNED[packets.APPROVAL],
            'pricing_digest': packets.digest(pricing), 'readiness_digest': packets.digest(readiness),
            'reserved_micro_usd': 250000, 'approved_cap_micro_usd': 250000, 'maximum_provider_calls': 1,
            'retries': 0, 'task_state_writes': 0, 'gate_authority': False, 'production_release_authorized': False}
        allowance = {'payload': payload, 'signature': base64.b64encode(self.private[OWNER_IDENTITY].sign(canonical(payload))).decode()}
        def credential(): self.trace.append('credential'); return 'synthetic-credential'
        def signer(receipt, *, now):
            self.trace.append('sign')
            return self.private[IDENTITIES[role]].sign(canonical(receipt))
        args = dict(root=ROOT, role=role, source_commit='a'*40, qualification=qualification, readiness=readiness,
            trusted_keys=self.keys, store=self.store, load_credential=credential, sign_receipt=signer,
            clock=lambda: self.now, enabled=True)
        if role != 'builder':
            args.update(predecessors=copy.deepcopy(self.chain), predecessor_request_digests=dict(self.requests), candidate_commit='b'*40)
        output = ({'task_id': packets.TASK, 'packet_digest': value['packet_digest'], 'files': value['untrusted_files']}
            if role == 'builder' else {**{key: value[key] for key in packets.REVIEW_BINDINGS},
                'verdict': 'ACCEPTED', 'rationale': 'Reviewed exact fixture', 'findings': []})
        text = canonical(output).decode()
        if role == 'builder':
            response = {'model': value['model_id'], 'status': 'completed', 'service_tier': 'default',
                'output': [{'type': 'message', 'role': 'assistant', 'status': 'completed', 'content': [{'type': 'output_text', 'text': text}]}],
                'usage': {'input_tokens': 100, 'output_tokens': 30, 'total_tokens': 130,
                    'input_tokens_details': {'cached_tokens': 0}, 'output_tokens_details': {'reasoning_tokens': 0}}}
        elif role == 'inspector':
            response = {'stopReason': 'end_turn', 'output': {'message': {'role': 'assistant', 'content': [{'text': text}]}},
                'usage': {'inputTokens': 100, 'outputTokens': 30, 'totalTokens': 130}}
        else:
            response = {'modelVersion': value['model_id'], 'candidates': [{'finishReason': 'STOP',
                'content': {'role': 'model', 'parts': [{'text': text}]}}],
                'usageMetadata': {'promptTokenCount': 100, 'candidatesTokenCount': 30, 'totalTokenCount': 130}}
        return allowance, args, canonical(response)

    def execute(self, role):
        allowance, args, response = self.setup_role(role)
        with patch('factory_runtime.handoff004_workflow.Handoff004Transport') as transport:
            def send(**_): self.trace.append('send'); return response
            transport.return_value.send_once.side_effect = send
            result = run_once(allowance, **args)
            with self.assertRaisesRegex(HandoffStopped, 'reservation'):
                run_once(allowance, **args)
            transport.return_value.send_once.assert_called_once()
        self.chain[role] = result
        self.requests[role] = result['payload']['request_digest']

    def test_three_roles_ordered_real_signatures_and_nonreusable_claims(self):
        for role in IDENTITIES: self.execute(role)
        self.assertEqual(self.trace[:6], ['claim', 'credential', 'send', 'sign', 'complete', 'claim'])
        result = verify_chain(self.chain, root=ROOT, trusted_keys=self.keys, source_commit='a'*40,
            candidate_commit='b'*40, request_digests=self.requests, now=self.now,
            verify_executed_tests=lambda commit, digest: commit == 'b'*40 and digest ==
                packets.parse_builder(base64.b64decode(self.chain['builder']['output_base64']), root=ROOT)['candidate_digest'])
        self.assertEqual(result['reported_actual_micro_usd'], 3000)
        self.assertFalse(result['gate_authority'])

    def test_failed_signature_does_not_repeat_paid_response(self):
        allowance, args, response = self.setup_role('builder')
        args['sign_receipt'] = lambda *_args, **_kwargs: bytes(64)
        with patch('factory_runtime.handoff004_workflow.Handoff004Transport') as transport:
            transport.return_value.send_once.return_value = response
            with self.assertRaises(HandoffStopped) as error: run_once(allowance, **args)
            self.assertEqual(error.exception.stage, 'signing')
            self.assertEqual(error.exception.response, response)
            with self.assertRaisesRegex(HandoffStopped, 'reservation'): run_once(allowance, **args)
            transport.return_value.send_once.assert_called_once()
        self.db.update_item.assert_not_called()

    def test_tampered_predecessor_stops_before_new_hold(self):
        self.execute('builder')
        allowance, args, response = self.setup_role('inspector')
        args['predecessors']['builder']['signature_base64'] = base64.b64encode(bytes(64)).decode()
        with patch('factory_runtime.handoff004_workflow.Handoff004Transport') as transport:
            with self.assertRaisesRegex(HandoffStopped, 'predecessor'): run_once(allowance, **args)
            transport.assert_not_called()
        self.assertEqual(len(self.claimed), 1)

    def test_changed_rates_or_disabled_execution_never_claim(self):
        allowance, args, _ = self.setup_role('builder')
        with self.assertRaises(StateError): run_once(allowance, **{**args, 'enabled': False})
        args['qualification']['input_micro_usd_per_million'] += 1
        with self.assertRaisesRegex(HandoffStopped, 'authorization'): run_once(allowance, **args)
        self.db.put_item.assert_not_called()

    def test_uncertain_provider_call_is_redacted_and_consumed(self):
        allowance, args, _ = self.setup_role('builder')
        with patch('factory_runtime.handoff004_workflow.Handoff004Transport') as transport:
            transport.return_value.send_once.side_effect = RuntimeError('sensitive provider detail')
            with self.assertRaises(HandoffStopped) as error: run_once(allowance, **args)
            self.assertEqual(error.exception.stage, 'provider')
            self.assertIsNone(error.exception.response)
            self.assertEqual(error.exception.failure, {'failure_category': 'unknown', 'http_status': None})
            self.assertNotIn('sensitive', str(error.exception))
            with self.assertRaisesRegex(HandoffStopped, 'reservation'): run_once(allowance, **args)
            transport.return_value.send_once.assert_called_once()
        self.db.update_item.assert_not_called()

    def test_timeout_and_http_failure_keep_bounded_diagnostics_and_permanent_claim(self):
        from factory_runtime.pilot002_transport import ProviderTimeoutError, ProviderHTTPStatusError
        for exception,expected in ((ProviderTimeoutError(), {'failure_category':'timeout','http_status':None}),
                (ProviderHTTPStatusError(503), {'failure_category':'http_status','http_status':503})):
            with self.subTest(expected=expected):
                self.setUp()
                allowance,args,_=self.setup_role('builder')
                with patch('factory_runtime.handoff004_workflow.Handoff004Transport') as transport:
                    transport.return_value.send_once.side_effect=exception
                    with self.assertRaises(HandoffStopped) as error:run_once(allowance,**args)
                    self.assertEqual(error.exception.failure,expected)
                    with self.assertRaisesRegex(HandoffStopped,'reservation'):run_once(allowance,**args)
                    transport.return_value.send_once.assert_called_once()
                self.db.update_item.assert_not_called()

    def test_predecessor_expiry_is_rechecked_before_provider(self):
        self.execute('builder')
        allowance, args, _ = self.setup_role('inspector')
        times = iter((self.now, self.now, datetime.fromtimestamp(int(self.now.timestamp())+121, timezone.utc)))
        args['clock'] = lambda: next(times)
        with patch('factory_runtime.handoff004_workflow.Handoff004Transport') as transport:
            with self.assertRaisesRegex(HandoffStopped, 'provider'): run_once(allowance, **args)
            transport.assert_not_called()
