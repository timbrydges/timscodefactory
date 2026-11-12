import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

from factory_runtime import approved_models
from factory_runtime.development_composition import BONUS_TASKS

ROOT = Path(__file__).resolve().parents[1]
spec_ = importlib.util.spec_from_file_location('prepare_models', ROOT/'scripts'/'prepare_development_attempt.py')
prep = importlib.util.module_from_spec(spec_); spec_.loader.exec_module(prep)


class ApprovedModelTests(unittest.TestCase):
    def write(self, data):
        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        path = Path(tmp.name)/'models.json'
        path.write_text(json.dumps(data))
        return path

    def entry(self, i='4.00', o='20.00'):
        return {'max_input_usd_per_million_tokens': i, 'max_output_usd_per_million_tokens': o}

    def test_repository_list_keeps_the_current_model_as_default(self):
        default, approved = approved_models.load()
        self.assertEqual(default, 'gpt-5.6-sol')
        self.assertIn('gpt-5.6-sol', approved)

    def test_every_task_resolves_to_an_approved_model(self):
        for task_id in BONUS_TASKS:
            with self.subTest(task=task_id):
                spec = json.loads((ROOT/'factory/projects'/task_id/'task.json').read_bytes())
                self.assertIn(prep.limits_for(spec)['model_id'], approved_models.load()[1])

    def test_cheaper_model_is_routed_and_unknown_model_fails_closed(self):
        path = self.write({'schema': 1, 'default': 'gpt-5.6-sol',
                           'models': {'gpt-5.6-sol': self.entry(), 'gpt-mini-x': self.entry('0.40', '1.60')}})
        self.assertEqual(approved_models.resolve({'model': 'gpt-mini-x'}, path)[0], 'gpt-mini-x')
        self.assertEqual(approved_models.resolve({}, path)[0], 'gpt-5.6-sol')
        with self.assertRaises(ValueError):
            approved_models.resolve({'model': 'gpt-unlisted'}, path)

    def test_list_rejects_models_above_the_cap_ceiling_and_malformed_files(self):
        bad = [
            {'schema': 1, 'default': 'a', 'models': {'a': self.entry('4.01')}},
            {'schema': 1, 'default': 'a', 'models': {'a': self.entry('4.00', '20.5')}},
            {'schema': 1, 'default': 'a', 'models': {'a': self.entry('NaN')}},
            {'schema': 1, 'default': 'b', 'models': {'a': self.entry()}},
            {'schema': 1, 'default': 'A B', 'models': {'A B': self.entry()}},
            {'schema': 2, 'default': 'a', 'models': {'a': self.entry()}},
            [],
        ]
        for data in bad:
            with self.subTest(data=data), self.assertRaises(ValueError):
                approved_models.load(self.write(data))

    def test_prepare_refuses_a_price_above_the_model_maximum(self):
        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        from datetime import datetime, timezone
        with self.assertRaisesRegex(ValueError, 'approved maximum'):
            prep.prepare(output=Path(tmp.name)/'a', attempt_id='models-001',
                image_ref='img@sha256:' + 'a'*64, source_config_sha256='sha256:' + 'b'*64,
                input_price='4.50', output_price='20.00', pricing_source='test',
                now=datetime.now(timezone.utc), hours=1, source_commit='c'*40,
                task=ROOT/'factory/projects/bonus-library-library-page/task.json')
        self.assertFalse((Path(tmp.name)/'a').exists())


if __name__ == '__main__':
    unittest.main()
