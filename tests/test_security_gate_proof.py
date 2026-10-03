import copy
import json
import sys
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'src'),str(ROOT/'scripts')]
import verify_security_gate_proof as verifier
from factory_state.model import StateError


class SecurityGateProofTests(unittest.TestCase):
    def test_pinned_proof_verifies_without_new_authority(self):
        result=verifier.verify()
        self.assertEqual((result['state'],result['version']),('RELEASE_READY',16))
        self.assertEqual(len(result['retained_findings']),3)
        self.assertFalse(result['new_execution_authorized'])
        self.assertFalse(result['production_release_authorized'])

    def test_tampering_is_rejected(self):
        original=json.loads((ROOT/verifier.PROOF).read_text())
        changes=[
            (('final_state','version'),17),
            (('final_state','leases'),[]),
            (('signed_result','payload','production_release_authorized'),True),
            (('signed_result','signature_base64'),'AAAA'),
            (('audit_events',),[]),
            (('original_access_expiration',),'2026-10-03T16:25:43+00:00'),
            (('shutdown','disabled'),False),
            (('access_removed','logging_only'),False),
            (('signing_invocations',),2),
        ]
        for path,value in changes:
            with self.subTest(path=path):
                proof=copy.deepcopy(original); target=proof
                for key in path[:-1]: target=target[key]
                target[path[-1]]=value
                with self.assertRaises(StateError): verifier.verify_document(proof,root=ROOT)


if __name__=='__main__': unittest.main()
