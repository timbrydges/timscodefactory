import json
from pathlib import Path
import tempfile
import unittest
from prepare_handoff003_qa_paid_recovery import prepare,ROOT,SCOPE

class RecoveryPreparationTests(unittest.TestCase):
    def test_fresh_scope_does_not_reuse_prior_attempt_or_authorize_execution(self):
        result=prepare(ROOT,'a'*40)
        self.assertEqual(result['new_cap_micro_usd'],250000)
        self.assertEqual(result['batch_reserved_after_micro_usd'],1250000)
        self.assertNotEqual(result['attempt_table'],'tims-factory-handoff-003-attempts')
        self.assertFalse(result['prior_qa_hold_released'])
        self.assertFalse(result['prior_qa_charge_known'])
        self.assertFalse(result['execution_authorized'])
        self.assertFalse(result['signed_allowance_present'])
        self.assertEqual(result['provider_calls'],0)

    def test_changed_budget_or_namespace_rejected_before_historical_reads(self):
        for field,value in (('approved_cap_micro_usd',3000000),('new_attempt_table','tims-factory-handoff-003-attempts'),('retries',1)):
            with self.subTest(field=field),tempfile.TemporaryDirectory() as d:
                root=Path(d);p=root/SCOPE;p.parent.mkdir(parents=True)
                scope=json.loads((ROOT/SCOPE).read_bytes());scope[field]=value;p.write_text(json.dumps(scope))
                with self.assertRaisesRegex(ValueError,'scope differs'):prepare(root,'a'*40)
