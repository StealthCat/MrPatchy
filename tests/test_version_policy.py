"""Version-policy acceptance without importing the web application."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from tools import check_version


class VersionPolicyTests(unittest.TestCase):
    def project(self, root, current):
        (root/'app').mkdir()
        (root/'app/main.py').write_text(
            f"APP_VERSION='{current}'\n"
            "app=FastAPI(version=APP_VERSION)\n"
            "def health():\n    return {'version':APP_VERSION}\n")
        (root/'CHANGELOG.md').write_text(f'## {current} — 2026-10-30\n\n1. Update\n')

    def test_other_major_versions_are_rejected_even_with_matching_metadata(self):
        for current in ('0.17.1','2.0.0','10.0.0'):
            with self.subTest(current=current),tempfile.TemporaryDirectory() as directory:
                root=Path(directory);self.project(root,current)
                with patch.object(check_version,'ROOT',root):
                    with self.assertRaisesRegex(ValueError,'Major version must remain 1'):
                        check_version.check()

    def test_minor_and_patch_advances_remain_valid(self):
        for current,base in (('1.17.1','1.17.0'),('1.18.0','1.17.0'),('1.17.10','1.17.9')):
            with self.subTest(current=current,base=base),tempfile.TemporaryDirectory() as directory:
                root=Path(directory);self.project(root,current)
                with patch.object(check_version,'ROOT',root),patch.object(check_version.subprocess,'check_output',side_effect=[f"APP_VERSION='{base}'\n",'# Changelog\n']):
                    self.assertEqual(check_version.check('policy-base'),current)

    def test_unchanged_or_decreasing_versions_still_fail(self):
        for current,base in (('1.17.0','1.17.0'),('1.17.0','1.17.1'),('1.16.99','1.17.0')):
            with self.subTest(current=current,base=base),tempfile.TemporaryDirectory() as directory:
                root=Path(directory);self.project(root,current)
                with patch.object(check_version,'ROOT',root),patch.object(check_version.subprocess,'check_output',return_value=f"APP_VERSION='{base}'\n"):
                    with self.assertRaisesRegex(ValueError,'Integration revision must increase'):
                        check_version.check('policy-base')

    def test_transition_from_legacy_zero_major_is_valid(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);self.project(root,'1.17.0')
            with patch.object(check_version,'ROOT',root),patch.object(check_version.subprocess,'check_output',side_effect=["APP_VERSION='0.17.0'\n",'# Changelog\n']):
                self.assertEqual(check_version.check('policy-base'),'1.17.0')
