import json
from pathlib import Path
import shutil
import tempfile
import unittest
from verify_handoff003_saved_evidence import verify,ROOT

class SavedPartialTests(unittest.TestCase):
    def test_completed_signatures_and_uncertain_cost_are_distinct(self):
        result=verify(ROOT/'factory/evidence/handoff-003-live')
        self.assertEqual(result['reported_completed_micro_usd'],101892)
        self.assertFalse(result['qa_actual_cost_known'])
        self.assertFalse(result['execution_authorized'])

    def test_signature_claim_replay_cost_and_test_tampering_fail_closed(self):
        for name,mutate in (
            ('inspector-live-result',lambda v:v['payload'].update(actual_micro_usd=0)),
            ('qa-attempt-observation',lambda v:v.update(status={'S':'COMPLETE'})),
            ('stopped-recovery-result',lambda v:v.update(worker_invocations=1)),
            ('partial-verification',lambda v:v.update(qa_actual_cost_known=True)),
            ('candidate-python312-proof',lambda v:v.update(exit_code=1))):
            with self.subTest(name=name),tempfile.TemporaryDirectory() as d:
                folder=Path(d)/'evidence';shutil.copytree(ROOT/'factory/evidence/handoff-003-live',folder)
                p=folder/(name+'.json');value=json.loads(p.read_bytes());mutate(value);p.write_text(json.dumps(value))
                with self.assertRaises((ValueError,RuntimeError)):verify(folder)
