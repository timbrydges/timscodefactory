from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from scripts.build_manifest import render_manifest


class BuildManifestTests(unittest.TestCase):
    def test_mixed_case_and_nested_paths_have_platform_independent_order(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            names = ['z.txt', 'lower.txt', 'UPPER.txt', 'nested/item.txt', 'nested-file.txt']
            for name in names:
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(b'fixture')
            paths = [line.split('  ', 1)[1] for line in render_manifest(root).splitlines()]
            self.assertEqual(paths, ['UPPER.txt', 'lower.txt', 'nested/item.txt', 'nested-file.txt', 'z.txt'])

    def test_terraform_cache_is_not_repository_source(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'source.txt').write_text('source', encoding='utf-8')
            cache = root / 'infra' / 'aws' / '.terraform' / 'providers'
            cache.mkdir(parents=True)
            (cache / 'terraform-provider-aws').write_bytes(b'generated binary')

            manifest = render_manifest(root)

            self.assertIn('source.txt', manifest)
            self.assertNotIn('.terraform', manifest)
            self.assertNotIn('terraform-provider-aws', manifest)


if __name__ == '__main__':
    unittest.main()
