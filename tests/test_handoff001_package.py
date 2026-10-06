import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import zipfile
import build_handoff001_package as package


class HandoffPackageTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(); self.addCleanup(self.directory.cleanup)
        self.base = Path(self.directory.name); self.root = self.base/'repo'; self.root.mkdir()
        subprocess.run(['git', 'init', '-q', str(self.root)], check=True)
        for name in package.PINNED:
            target = self.root/name; target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((package.ROOT/name).read_bytes())
        for name, raw in {'.gitignore': b'.env.local\nsrc/ignored.py\n',
            'src/factory_runtime/__init__.py': b'', 'src/factory_runtime/committed.py': b'VALUE = 1\n',
            'requirements-role-lambda.txt': b'# verification lock\n',
            'requirements-aws-signing.txt': b'# SDK lock\n'}.items():
            target = self.root/name; target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(raw)
        subprocess.run(['git', 'add', '.'], cwd=self.root, check=True, capture_output=True)
        subprocess.run(['git', '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.test',
            'commit', '-qm', 'fixture'], cwd=self.root, check=True)
        (self.root/'.env.local').write_text('SYNTHETIC_PRIVATE_VALUE=not-a-credential')
        (self.root/'src/ignored.py').write_text('IGNORED = True')

    def test_only_committed_source_and_pinned_dependencies_packaged(self):
        locks = []
        def dependencies(target, lock):
            locks.append(lock.read_bytes())
            return {'synthetic_dependency.py': b'# dependency fixture\n'}
        with patch.object(package, 'ROOT', self.root), patch.object(package, '_dependencies', side_effect=dependencies):
            result = package.build(self.base/'package.zip')
        with zipfile.ZipFile(self.base/'package.zip') as archive:
            names = archive.namelist()
            self.assertNotIn('.env.local', names)
            self.assertNotIn('ignored.py', names)
            self.assertNotIn('src/ignored.py', names)
            self.assertEqual(archive.read('factory_runtime/committed.py'), b'VALUE = 1\n')
            self.assertEqual(json.loads(archive.read('BUILD.json'))['source_commit'], result['source_commit'])
        self.assertIn(b'# SDK lock', locks[0])
        self.assertIn(b'# verification lock', locks[0])
        self.assertFalse(result['execution_enabled'])

    def test_dirty_source_rejected_before_dependency_install(self):
        (self.root/'src/factory_runtime/committed.py').write_text('VALUE = 2\n')
        with patch.object(package, 'ROOT', self.root), patch.object(package, '_dependencies') as dependencies:
            with self.assertRaises(RuntimeError): package.build(self.base/'package.zip')
            dependencies.assert_not_called()
