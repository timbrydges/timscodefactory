import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
import build_pilot002_bootstrap_package as package


class PackageTests(unittest.TestCase):
    def test_identical_archive_with_windows_and_linux_zip_defaults(self):
        original=zipfile.ZipInfo
        with tempfile.TemporaryDirectory() as directory:
            paths=[]
            for platform in (0,3):
                class PlatformInfo(original):
                    def __init__(self,*args,**kwargs):
                        super().__init__(*args,**kwargs); self.create_system=platform
                path=Path(directory)/f'{platform}.zip'; paths.append(path)
                with patch.object(package.subprocess,'check_output',side_effect=['','a'*40]), \
                     patch.object(package.zipfile,'ZipInfo',PlatformInfo):
                    package.build(path)
            self.assertEqual(paths[0].read_bytes(),paths[1].read_bytes())
            with zipfile.ZipFile(paths[0]) as archive:
                self.assertEqual(len(archive.namelist()),8)
                self.assertTrue(all(i.create_system==3 for i in archive.infolist()))
                self.assertNotIn('factory_runtime/google_qa.py',archive.namelist())


if __name__=='__main__':unittest.main()
