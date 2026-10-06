import json
from pathlib import Path
import shutil
import tempfile
import unittest
from verify_handoff004_saved_evidence import verify,ROOT

class SavedHandoffTests(unittest.TestCase):
    def test_three_provider_completion_is_historical_evidence_only(self):
        report=verify(ROOT/'factory/evidence/handoff-004-live')
        self.assertEqual(report['status'],'HISTORICAL_COMPLETE_HANDOFF_VERIFIED_NOT_AUTHORIZATION')
        self.assertEqual(report['independent_tests'],17)
        self.assertGreater(report['reported_completed_micro_usd'],0)
        self.assertLess(report['reported_completed_micro_usd'],750000)
        self.assertFalse(report['execution_authorized'])
        self.assertFalse(report['gate_authority'])
        self.assertFalse(report['invoice_verified'])

    def test_tampering_with_receipts_claims_tests_or_shutdown_fails_closed(self):
        for name,mutate in (
            ('qa-live-result',lambda v:v['payload'].update(actual_micro_usd=0)),
            ('inspector-live-result',lambda v:v['payload'].update(predecessor_receipt_digest='sha256:'+'0'*64)),
            ('builder-attempt-observation',lambda v:v.update(status={'S':'STARTED'})),
            ('qa-controller-observation',lambda v:v.update(signed_receipt={'S':'{}'})),
            ('qa-dispatch-journal',lambda v:v[-1].update(errors=['worker concurrency'])),
            ('completion-recovery-result',lambda v:v.update(worker_invocations=1)),
            ('candidate-python312-proof',lambda v:v.update(exit_code=1)),
            ('final-observation',lambda v:v['workers']['handoff004_qa'].update(reserved_concurrency=1)),
            ('final-observation',lambda v:v['attempts']['handoff003_qa'].update(reported_actual_micro_usd=0)),
            ('chain-verification',lambda v:v.update(gate_authority=True))):
            with self.subTest(name=name),tempfile.TemporaryDirectory() as d:
                folder=Path(d)/'evidence';shutil.copytree(ROOT/'factory/evidence/handoff-004-live',folder)
                path=folder/(name+'.json');value=json.loads(path.read_bytes());mutate(value)
                path.write_text(json.dumps(value))
                with self.assertRaises((ValueError,RuntimeError)):verify(folder)
