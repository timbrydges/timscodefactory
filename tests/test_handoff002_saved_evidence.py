import json
from pathlib import Path
import shutil
import tempfile
import unittest
from verify_handoff002_saved_evidence import verify,ROOT

class SavedHandoffTests(unittest.TestCase):
    def test_actual_signatures_and_no_live_authority(self):
        result=verify(ROOT/'factory/evidence/handoff-002-live')
        self.assertEqual(result['reported_micro_usd'],108387)
        self.assertFalse(result['execution_authorized'])
        self.assertFalse(result['gate_authority'])

    def test_altered_signature_test_observation_and_cost_fail_closed(self):
        for name,mutate in (
            ('qa-live-result',lambda v:v['payload'].update(actual_micro_usd=1)),
            ('candidate-python312-proof',lambda v:v.update(exit_code=1)),
            ('chain-verification',lambda v:v.update(reported_actual_micro_usd=0))):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as d:
                target=Path(d)/'evidence';shutil.copytree(ROOT/'factory/evidence/handoff-002-live',target)
                path=target/(name+'.json');value=json.loads(path.read_bytes());mutate(value);path.write_text(json.dumps(value))
                with self.assertRaises((ValueError,RuntimeError)):verify(target)
