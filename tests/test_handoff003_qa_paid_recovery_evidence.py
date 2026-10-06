import json,shutil,tempfile,unittest
from pathlib import Path
import verify_handoff003_qa_paid_recovery_evidence as audit

class PaidRecoveryEvidenceTests(unittest.TestCase):
    def test_signed_acceptance_is_historical_not_live_authority(self):
        result=audit.verify(audit.ROOT/audit.FOLDER)
        self.assertEqual(result['reported_micro_usd'],4979)
        self.assertFalse(result['execution_authorized']);self.assertFalse(result['gate_authority'])
    def test_tampered_output_cost_claim_or_disabled_observation_rejected(self):
        for name,mutate in [('live-result',lambda v:v.update(output_base64='e30=')),
            ('attempt-observation',lambda v:v.update(actual_micro_usd={'N':'0'})),
            ('attempt-observation',lambda v:v.update(PK={'S':'HANDOFF#003#QA_RECOVERY#001'})),
            ('final-status',lambda v:v['workers']['handoff003_qa_paid_recovery002'].update(reserved_concurrency=1)),
            ('final-status',lambda v:v['attempts']['handoff003_qa'].update(reserved_micro_usd=0))]:
            with self.subTest(name=name),tempfile.TemporaryDirectory() as temporary:
                folder=Path(temporary)/'evidence';shutil.copytree(audit.ROOT/audit.FOLDER,folder)
                p=folder/(name+'.json');v=json.loads(p.read_bytes());mutate(v);p.write_text(json.dumps(v))
                with self.assertRaises(ValueError):audit.verify(folder)
