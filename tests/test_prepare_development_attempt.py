from datetime import datetime, timedelta, timezone
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

from factory_runtime.development_approval import approval_pins_match
from factory_runtime.task_queue import QueuedTask

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('prepare_attempt', ROOT/'scripts'/'prepare_development_attempt.py')
prep = importlib.util.module_from_spec(spec); spec.loader.exec_module(prep)
attempt_spec = importlib.util.spec_from_file_location('attempt_entry', ROOT/'scripts'/'development_attempt.py')
attempt = importlib.util.module_from_spec(attempt_spec); attempt_spec.loader.exec_module(attempt)


class PrepareTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        self.out = Path(tmp.name).resolve()/'pagination-001'
        self.now = datetime(2026, 11, 1, 12, tzinfo=timezone.utc)
        self.kw = dict(output=self.out, attempt_id='pagination-001',
            image_ref='docker.io/library/node@sha256:'+'a'*64,
            source_config_sha256='sha256:'+'b'*64, manifest='sha256:'+'c'*64,
            input_price='4.00', output_price='20.00', pricing_source='openai-pricing-2026-11-01',
            now=self.now, hours=12, source_commit='d'*40)

    def test_files_satisfy_the_attempt_and_approval_checks(self):
        result = prep.prepare(**self.kw)
        self.assertEqual((result['status'], result['model_calls']), ('PREPARED', 0))
        load = lambda n: json.loads((self.out/f'{n}.json').read_text())
        pins, approval, pricing = load('pins'), load('approval'), load('pricing')
        self.assertTrue(approval_pins_match(approval, pins))
        contract = (self.out/'contract.json').read_bytes()
        self.assertEqual(contract, prep.TASK.read_bytes())
        self.assertEqual(pins['contract_digest'], attempt.digest(contract))
        self.assertEqual((pins['repository'], pins['target_commit']),
                         ('timbrydges/bonus-library', 'ef88df95bc3f046d080af51e3654d2259759072b'))
        self.assertEqual((pins['builder_cap'], pins['reviewer_cap'], pins['total_cap']),
                         ('0.50', '0.25', '1.50'))
        self.assertEqual(pins['repair_rounds'], 1)
        from decimal import Decimal
        worst = lambda tokens: (Decimal(pins['max_request_bytes'])*Decimal(pricing['input_usd_per_million_tokens'])
            + Decimal(tokens)*Decimal(pricing['output_usd_per_million_tokens']))/Decimal(1_000_000)
        self.assertLessEqual(worst(pins['max_output_tokens']), Decimal(pins['builder_cap']))
        self.assertLessEqual(worst(min(pins['max_output_tokens'], 4096)), Decimal(pins['reviewer_cap']))
        QueuedTask(pins['attempt_id'], 'development-local', json.loads(contract)['task_id'],
                   pins['attempt_id'], pins['source_commit'], pins['contract_digest'],
                   'IMPLEMENTATION').validate()
        quote = attempt.PinnedPricing(pricing).value
        self.assertEqual(quote.model_id, 'gpt-5.6-sol')
        self.assertEqual(quote.expires_at - quote.effective_at, timedelta(hours=24))
        self.assertEqual(datetime.fromisoformat(approval['expires_at']), self.now+timedelta(hours=12))

    def test_single_round_has_no_repair_pin_and_lower_total(self):
        prep.prepare(**dict(self.kw, repair_rounds=0))
        pins = json.loads((self.out/'pins.json').read_text())
        self.assertNotIn('repair_rounds', pins)
        self.assertEqual(pins['total_cap'], '0.75')

    def test_invalid_inputs_write_nothing(self):
        for change in (dict(attempt_id='Bad_ID'), dict(image_ref='node:22'),
                       dict(manifest='sha256:short'), dict(input_price='0'),
                       dict(output_price='abc'), dict(hours=25), dict(hours=0),
                       dict(output=Path('relative')), dict(repair_rounds=2), dict(output=prep.ROOT/'out')):
            with self.subTest(change=change), self.assertRaises(ValueError):
                prep.prepare(**dict(self.kw, **change))
        self.assertFalse(self.out.exists())

    def test_existing_output_is_never_overwritten(self):
        prep.prepare(**self.kw)
        with self.assertRaises(FileExistsError):
            prep.prepare(**self.kw)

    def test_cli_requires_owner_authorization(self):
        import contextlib, io
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            prep.main(['--output', str(self.out), '--attempt-id', 'x', '--image-ref', 'x',
                       '--source-config-sha256', 'x', '--manifest', 'x', '--input-price', '1',
                       '--output-price', '1', '--pricing-source', 'x'])
        self.assertFalse(self.out.exists())


if __name__ == '__main__':
    unittest.main()
