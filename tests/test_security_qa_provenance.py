import base64
import json
from dataclasses import replace
from datetime import timedelta
import tempfile
import unittest
from unittest.mock import Mock

from factory_runtime.security_qa_provenance import ConsumedQAProvenance
from factory_runtime.security_contract import contract, validate_link
from factory_runtime.worker import digest
from factory_state.model import TaskState, Lease, CONTROLLER_IDENTITY, StateError
from factory_state.dispatch import DynamoDBDispatchStore
from factory_state.scope import canonical
from scripts.scope_dispatch_canary import fixture_keys, sign
from test_security_provider_scope import fixture, NOW


class QAProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.keys, self.private = fixture_keys(self.temp.name, ('qa_engineer_service', 'tim_brydges'))
        scope, _, _, _ = fixture()
        scope = replace(scope, binding=replace(scope.binding, qa=replace(scope.binding.qa,
            allowed_paths=('fingerprint.py', 'tests/test_fingerprint.py'))))
        self.qa = replace(scope.binding.qa, source_commit='e'*40)
        self.request = replace(scope.request, source_commit=self.qa.source_commit,
                               input_digest=self.qa.input_digest, lease_id='previous-qa')
        output = {k:getattr(self.qa,k) for k in self.qa.__dataclass_fields__ if k != 'allowed_paths'}
        output.update(kind='factory_review_v1', verdict='ACCEPTED', rationale='Fixture.', findings=[])
        self.output = canonical(output)
        issued = NOW-timedelta(hours=2)
        self.payload = {'kind':'role_result','factory_id':self.qa.factory_id,'task_id':self.qa.task_id,
            'binding':DynamoDBDispatchStore._binding(self.request),'dispatch_id':'d'*64,
            'producer_identity':'qa_engineer_service','output_digest':digest(self.output),
            'issued_at':int(issued.timestamp()),'expires_at':int(issued.timestamp())+300}
        self.binding = replace(scope.binding, qa_result_digest=digest(canonical(self.payload)))
        self.row = {'status':{'S':'RECEIPT_RECORDED'},'dispatch_id':{'S':'d'*64},
            'receipt_digest':{'S':self.binding.qa_result_digest},
            'result_payload':{'S':canonical(self.payload).decode()},
            'result_signature':{'S':base64.b64encode(sign(self.payload,
                self.private['qa_engineer_service'],self.temp.name)).decode()},
            'result_output':{'S':base64.b64encode(self.output).decode()}}
        self.state = TaskState(self.qa.factory_id,self.qa.task_id,'SECURITY_REVIEW',7,NOW,
            CONTROLLER_IDENTITY,(Lease('previous-qa','qa_engineer','qa_engineer_service',issued+timedelta(minutes=5)),),
            consumed_evidence_ids=frozenset({'result-'+self.binding.qa_result_digest[7:]}))
        self.states = Mock(load_state=Mock(return_value=self.state))
        self.ledger = Mock(read=Mock(return_value=self.row), _binding=DynamoDBDispatchStore._binding)
        self.loader = Mock(return_value=self.keys)
        self.verify = ConsumedQAProvenance(binding=self.binding, qa_binding=self.qa,
            qa_request=self.request, states=self.states, ledger=self.ledger,
            historical_key_loader=self.loader, clock=lambda:NOW)

    def test_expired_result_is_only_consumed_provenance_for_same_candidate(self):
        self.assertTrue(self.verify(self.binding))
        self.assertEqual(self.loader.call_args.args[0],NOW-timedelta(hours=2))
        self.assertNotEqual(self.qa.source_commit,self.binding.qa.source_commit)

    def fresh_contract(self):
        raw = contract(source_commit=self.binding.qa.source_commit,
            test_evidence_digest=self.binding.qa.test_evidence_digest,
            qa_binding=self.qa, qa_result_digest=self.binding.qa_result_digest)
        binding = replace(self.binding, qa=replace(self.binding.qa, contract_digest=digest(raw)))
        return binding, raw

    def test_fresh_contract_authenticates_prior_qa_without_renewing_grant(self):
        binding, raw = self.fresh_contract()
        verifier = ConsumedQAProvenance(binding=binding, qa_binding=self.qa,
            qa_request=self.request, states=self.states, ledger=self.ledger,
            historical_key_loader=self.loader, clock=lambda:NOW, contract_bytes=raw)
        self.assertTrue(verifier(binding))
        value = json.loads(raw)
        self.assertEqual(value['prior_qa_binding']['contract_digest'], self.qa.contract_digest)
        self.assertFalse(value['historical_authority_renewed'])
        self.assertFalse(value['production_release_authorized'])
        self.assertEqual((value['maximum_provider_calls'], value['retries'],
            value['reserved_micro_usd'], value['aggregate_ceiling_micro_usd']), (1,0,250000,3500000))
        with self.assertRaises(StateError):
            ConsumedQAProvenance(binding=binding, qa_binding=self.qa,
                qa_request=self.request, states=self.states, ledger=self.ledger,
                historical_key_loader=self.loader, clock=lambda:NOW)

    def test_contract_substitution_and_changed_pins_fail(self):
        binding, raw = self.fresh_contract()
        for field, replacement in [('qa_result_digest', digest(b'other-result')),
                ('security_scope_digest', digest(b'other-policy'))]:
            with self.subTest(field=field), self.assertRaises(StateError):
                validate_link(replace(binding, **{field:replacement}), self.qa, raw)
        for field, replacement in [('source_commit','f'*40),
                ('test_evidence_digest',digest(b'other-proof')), ('candidate_commit','c'*40)]:
            with self.subTest(field=field), self.assertRaises(StateError):
                validate_link(replace(binding,qa=replace(binding.qa,**{field:replacement})),self.qa,raw)
        value = json.loads(raw); value['retries'] = 1
        altered = canonical(value)
        with self.assertRaises(StateError):
            validate_link(replace(binding,qa=replace(binding.qa,contract_digest=digest(altered))),
                self.qa, altered)
        with self.assertRaises(StateError):
            validate_link(binding,replace(self.qa,contract_digest=digest(b'other-contract')),raw)

    def test_unconsumed_or_wrong_stage_cannot_supply_prerequisite(self):
        for state in (replace(self.state,consumed_evidence_ids=frozenset()),
                      replace(self.state,state='RELEASE_READY'),replace(self.state,task_id='other')):
            self.states.load_state.return_value=state
            self.assertFalse(self.verify(self.binding))
        self.loader.assert_not_called()

    def test_tampered_output_or_signature_and_missing_key_fail(self):
        self.row['result_output']={'S':base64.b64encode(b'changed').decode()}
        self.assertFalse(self.verify(self.binding))
        self.row['result_output']={'S':base64.b64encode(self.output).decode()}
        self.loader.return_value={}
        self.assertFalse(self.verify(self.binding))
        self.loader.return_value=self.keys
        self.row['result_signature']={'S':base64.b64encode(b'x'*64).decode()}
        self.assertFalse(self.verify(self.binding))

    def test_candidate_or_receipt_substitution_rejected(self):
        self.assertFalse(self.verify(replace(self.binding,qa_result_digest=digest(b'other'))))
        with self.assertRaises(StateError):
            ConsumedQAProvenance(binding=replace(self.binding,qa=replace(self.binding.qa,candidate_commit='c'*40)),
                qa_binding=self.qa,qa_request=self.request,states=self.states,ledger=self.ledger,
                historical_key_loader=self.loader,clock=lambda:NOW)


if __name__ == '__main__': unittest.main()
