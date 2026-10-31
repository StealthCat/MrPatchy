"""Comparison process counts and native Debian semantics (also runnable alone)."""
from pathlib import Path
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from app import debian_versions


class DebianVersionsTests(unittest.TestCase):
    def test_unchanged_inventory_never_launches_native_comparator(self):
        with patch.object(debian_versions.subprocess, 'run') as run:
            self.assertEqual(debian_versions.newer_flags([('1.0-1', '1.0-1')] * 2000), [False] * 2000)
        run.assert_not_called()

    def test_mixed_inventory_reuses_pairs_and_preserves_order(self):
        pairs = [('2', '1'), ('1', '2'), ('1', '1')] * 1000
        def native(args, **kwargs):
            self.assertEqual(kwargs['timeout'], 10)
            return SimpleNamespace(returncode=0 if args[2] == '2' else 1)
        with patch.object(debian_versions.subprocess, 'run', side_effect=native) as run:
            self.assertEqual(debian_versions.newer_flags(pairs), [True, False, False] * 1000)
        self.assertEqual(run.call_count, 2)

    def test_cache_is_bounded_and_does_not_survive_inventory(self):
        pairs = [(str(i + 1), '0') for i in range(600)]
        with patch.object(debian_versions.subprocess, 'run', return_value=SimpleNamespace(returncode=0)) as run:
            debian_versions.newer_flags(pairs + [pairs[0]])
            self.assertEqual(run.call_count, 601)  # oldest pair evicted
            debian_versions.newer_flags([pairs[-1]])
            self.assertEqual(run.call_count, 602)

    def test_errors_and_timeouts_fail_closed(self):
        with patch.object(debian_versions.subprocess, 'run', return_value=SimpleNamespace(returncode=2)):
            with self.assertRaises(ValueError):
                debian_versions.newer_flags([('invalid', '1')])
        with patch.object(debian_versions.subprocess, 'run', side_effect=subprocess.TimeoutExpired('dpkg', 10)):
            with self.assertRaises(subprocess.TimeoutExpired):
                debian_versions.newer_flags([('2', '1')])

    @unittest.skipUnless(Path('/usr/bin/dpkg').exists(), 'requires native Debian dpkg')
    def test_native_epoch_revision_tilde_and_equivalent_spelling(self):
        pairs = [('1:1.0', '9.9'), ('1.0~rc1', '1.0'), ('1.0-2', '1.0-1'),
                 ('1.0', '1.0-0'), ('1.00', '1.0'), ('1.0+git2', '1.0+git1')]
        self.assertEqual(debian_versions.newer_flags(pairs), [True, False, True, False, False, True])


if __name__ == '__main__':
    unittest.main()
