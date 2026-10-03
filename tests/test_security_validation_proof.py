import copy
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT/'src'),str(ROOT/'scripts')]
from verify_security_validation_proof import verify, verify_document, PROOF
from factory_runtime.review_preparation import digest
from factory_state.model import StateError


class ValidationProofTests(unittest.TestCase):
    def setUp(self):
        self.proof=json.loads((ROOT/PROOF).read_bytes())

    def test_real_proof_retains_owner_decision_boundary(self):
        result=verify(ROOT)
        self.assertEqual(result['case_count'],5)
        self.assertEqual(result['open_findings'],3)
        self.assertTrue(result['owner_scope_acceptance_required'])
        self.assertFalse(result['gate_authority'])

    def test_preservation_or_shutdown_claim_changes_rejected(self):
        for field,value in [('task_version',15),('task_unchanged',False),('invocations',2),
                            ('model_calls',1),('permissions_unchanged',False)]:
            with self.subTest(field=field),self.assertRaises(StateError):
                verify_document({**self.proof,field:value},root=ROOT)
        altered=copy.deepcopy(self.proof); altered['shutdown']['concurrency']=1
        with self.assertRaises(StateError): verify_document(altered,root=ROOT)

    def test_rehashed_findings_or_case_changes_rejected(self):
        for field,value in [('findings',[]),('cases',[]),('gate_authority',True)]:
            altered=copy.deepcopy(self.proof); report=altered['result']['report']
            report[field]=value
            report['report_digest']=digest({k:v for k,v in report.items() if k!='report_digest'})
            with self.assertRaises(StateError): verify_document(altered,root=ROOT)

    def test_signature_cannot_be_repurposed_for_gate(self):
        altered=copy.deepcopy(self.proof)
        altered['result']['payload']['gate_authority']=True
        with self.assertRaises(StateError): verify_document(altered,root=ROOT)


if __name__=='__main__': unittest.main()
