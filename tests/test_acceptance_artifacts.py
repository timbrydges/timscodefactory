import json
import shutil
import tempfile
import unittest
from pathlib import Path

from factory_runtime.acceptance_artifacts import builder_context, validate_builder_artifacts
from factory_state.model import StateError

ROOT = Path(__file__).resolve().parents[1]


class AcceptanceArtifactTests(unittest.TestCase):
    def artifact(self, **files):
        return json.dumps({'schema_version': '1.0', 'files': files}).encode()

    def test_complete_source_package_is_structurally_valid(self):
        validate_builder_artifacts(self.artifact(**{
            'fingerprint.py': 'import hashlib\ndef main():\n    pass\n',
            'tests/test_fingerprint.py': 'import unittest\n'}))

    def test_prose_missing_files_extra_paths_invalid_sources_and_duplicate_fields_fail(self):
        valid = {'fingerprint.py': 'pass\n', 'tests/test_fingerprint.py': 'pass\n'}
        cases = [b'Please provide the immutable contract.', b'[]', b'null', b'\xff',
                 self.artifact(**{'fingerprint.py': 'pass'}),
                 self.artifact(**{**valid, '../outside.py': 'pass'}),
                 self.artifact(**{**valid, 'fingerprint.py': '# no implementation'}),
                 self.artifact(**{**valid, 'fingerprint.py': 'def invalid('}),
                 self.artifact(**{**valid, 'fingerprint.py': None}),
                 b'{"schema_version":"1.0","schema_version":"1.0","files":{}}',
                 b'x' * 65537]
        for raw in cases:
            with self.subTest(raw=raw[:80]), self.assertRaises(StateError):
                validate_builder_artifacts(raw)

    def test_context_binds_exact_contract_and_absent_starting_files(self):
        context = json.loads(builder_context(ROOT, 'task request'))
        self.assertEqual(context['source']['base_commit'],
                         'fcb4c535d4ea00962b26db14f59e34917ef2389f')
        self.assertEqual(context['contract']['behavior']['input'],
                         'One UTF-8 file path argument; maximum 4096 bytes.')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            shutil.copytree(ROOT / 'factory', root / 'factory')
            path = root / 'factory/autonomy/acceptance-contract.json'
            path.write_bytes(path.read_bytes() + b' ')
            with self.assertRaisesRegex(StateError, 'context is missing or invalid'):
                builder_context(root, 'task request')


if __name__ == '__main__':
    unittest.main()
