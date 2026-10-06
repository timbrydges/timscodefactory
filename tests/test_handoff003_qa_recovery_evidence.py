import json,shutil,tempfile,unittest
from pathlib import Path
import verify_handoff003_qa_recovery_evidence as audit

class RecoveryEvidenceTests(unittest.TestCase):
    def test_saved_failure_is_not_authority_and_cost_remains_unknown(self):
        result=audit.verify(audit.ROOT/'factory/evidence/handoff-003-qa-recovery-001-live')
        self.assertFalse(result['execution_authorized']);self.assertFalse(result['actual_cost_known'])
        self.assertEqual(result['two_qa_holds_micro_usd'],500000)
    def test_fake_completion_released_hold_or_enabled_worker_rejected(self):
        for name,mutate in [('attempt-observation',lambda v:v.update(status={'S':'COMPLETE'})),
            ('attempt-observation',lambda v:v.update(reserved_micro_usd={'N':'0'})),
            ('attempt-observation',lambda v:v.update(actual_micro_usd={'N':'0'})),
            ('live-result',lambda v:v.update(attempt_reusable=True)),
            ('final-status',lambda v:v['workers']['handoff003_qa_recovery001'].update(reserved_concurrency=1))]:
            with self.subTest(name=name),tempfile.TemporaryDirectory() as temporary:
                folder=Path(temporary)/'evidence';shutil.copytree(audit.ROOT/'factory/evidence/handoff-003-qa-recovery-001-live',folder)
                p=folder/(name+'.json');v=json.loads(p.read_bytes());mutate(v);p.write_text(json.dumps(v))
                with self.assertRaises(ValueError):audit.verify(folder)
