from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from scripts.build_manifest import render_manifest


class BuildManifestTests(unittest.TestCase):
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
