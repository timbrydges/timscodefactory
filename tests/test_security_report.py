import sys
import tempfile
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from factory_runtime import security_report as report
from factory_runtime.review_preparation import PACKET,REVIEW,BOOTSTRAP,prepare
from factory_state.model import StateError


class SecurityReportTests(unittest.TestCase):
    def test_report_retains_findings_and_does_not_claim_a_gate(self):
        result=report.execute(ROOT)
        self.assertEqual(len(result['findings']),3)
        self.assertEqual(result['candidate_executions'],0)
        self.assertEqual(result['observations']['read_request_bytes'],4097)
        self.assertTrue(result['observations']['output_contains_full_input'])
        self.assertFalse(result['gate_authority'])
        self.assertFalse(result['production_release_authorized'])
        self.assertTrue(report.validate_execution(result,prepare(ROOT,role='security'),root=ROOT))

    def test_qa_packet_or_forged_candidate_rejected(self):
        with self.assertRaises(StateError): report.execute(ROOT,packet=prepare(ROOT,role='qa'))
        packet=prepare(ROOT,role='security')
        packet['untrusted_material']['files']['fingerprint.py']='print("safe")'
        with self.assertRaises(StateError): report.execute(ROOT,packet=packet)

    def test_modified_qa_proof_or_historical_registry_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            for name in (PACKET,REVIEW,BOOTSTRAP,report.QA_PROOF,report.HISTORICAL_REGISTRY):
                p=root/name; p.parent.mkdir(parents=True,exist_ok=True); p.write_bytes((ROOT/name).read_bytes())
            for name in (report.QA_PROOF,report.HISTORICAL_REGISTRY):
                p=root/name; raw=p.read_bytes(); p.write_bytes(raw+b' ')
                with self.assertRaises(StateError): report.execute(root)
                p.write_bytes(raw)


if __name__=='__main__': unittest.main()
