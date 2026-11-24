"""Pure cloud-init script-directory contract (#1271)."""
import os
import stat
import tempfile
import unittest

from app import cloud_init_scripts as c


def listed(*entries, complete=True, noexec=False):
    return {'state': 'listed', 'complete': complete, 'noexec': noexec, 'entries': list(entries)}


def f(name, mode=0o755):
    return {'name': name, 'type': 'file', 'mode': mode}


ABSENT = {'state': 'absent'}


def full(**overrides):
    dirs = {'per-boot': ABSENT, 'per-instance': ABSENT, 'per-once': ABSENT}
    dirs.update({k.replace('_', '-'): v for k, v in overrides.items()})
    return c.assess(dirs)


def by_dir(result, subdir):
    return next(d for d in result['directories'] if d['directory'].endswith('/' + subdir))


def upstream_runparts(dirp):
    """Line-for-line port of cloud-init 24.4 ``subp.runparts`` selection, without executing."""
    if not os.path.isdir(dirp):
        return None
    attempted = []
    for exe_name in sorted(os.listdir(dirp)):
        exe_path = os.path.join(dirp, exe_name)
        if os.path.isfile(exe_path) and os.access(exe_path, os.X_OK):
            attempted.append(exe_path)
    return attempted


def observe(dirp):
    """Collector used only by the test: the metadata the contract expects."""
    if not os.path.lexists(dirp):
        return {'state': 'absent'}
    if not os.path.isdir(dirp):
        return {'state': 'not_directory'}
    entries = []
    for name in os.listdir(dirp):
        p = os.path.join(dirp, name)
        st = os.lstat(p)
        if stat.S_ISLNK(st.st_mode):
            try:
                t = os.stat(p)
            except OSError:
                target = None
            else:
                kind = 'file' if stat.S_ISREG(t.st_mode) else 'directory' if stat.S_ISDIR(t.st_mode) else 'other'
                target = {'type': kind, 'mode': stat.S_IMODE(t.st_mode), 'noexec': False}
            entries.append({'name': name, 'type': 'symlink', 'link_target': os.readlink(p), 'target': target})
        elif stat.S_ISREG(st.st_mode):
            entries.append({'name': name, 'type': 'file', 'mode': stat.S_IMODE(st.st_mode)})
        elif stat.S_ISDIR(st.st_mode):
            entries.append({'name': name, 'type': 'directory'})
        else:
            entries.append({'name': name, 'type': 'other'})
    return listed(*entries)


class CloudInitScriptsTest(unittest.TestCase):
    def test_runs_every_executable_in_code_point_order_with_frequency(self):
        r = full(per_boot=listed(f('b'), f('a'), f('B'), f('10-x'), f('9-y')),
                 per_instance=listed(f('setup')), per_once=listed(f('first')))
        self.assertTrue(r['complete'], r['gaps'])
        self.assertEqual([s['name'] for s in by_dir(r, 'per-boot')['scripts']], ['10-x', '9-y', 'B', 'a', 'b'])
        self.assertEqual([(s['path'], s['frequency'], s['runs_as'], s['argv']) for s in r['scripts']][-2:], [
            ('/var/lib/cloud/scripts/per-instance/setup', 'instance', 'root',
             ['/var/lib/cloud/scripts/per-instance/setup']),
            ('/var/lib/cloud/scripts/per-once/first', 'once', 'root', ['/var/lib/cloud/scripts/per-once/first'])])
        self.assertEqual([s['order'] for s in by_dir(r, 'per-boot')['scripts']], [1, 2, 3, 4, 5])
        self.assertEqual(r['origin'], 'not_assessed')
        self.assertIsNone(r['verdict'])

    def test_no_run_parts_name_filter(self):
        names = ['.hidden', 'backup~', 'x.dpkg-old', 'UPPER', 'has space', 'x.sh', 'café']
        r = full(per_boot=listed(*(f(n) for n in names)))
        ran = by_dir(r, 'per-boot')['scripts']
        self.assertEqual([s['name'] for s in ran], sorted(names))
        self.assertTrue(next(s for s in ran if s['name'] == '.hidden')['hidden_name'])

    def test_any_execute_bit_runs_for_root_and_none_is_skipped(self):
        r = full(per_boot=listed(f('other-x', 0o601), f('group-x', 0o610), f('none', 0o644), f('setuid', 0o4000)))
        d = by_dir(r, 'per-boot')
        self.assertEqual([s['name'] for s in d['scripts']], ['group-x', 'other-x'])
        self.assertEqual({s['name']: s['reason'] for s in d['skipped']},
                         {'none': 'not_executable', 'setuid': 'not_executable'})
        self.assertTrue(r['complete'])

    def test_symlinks_are_followed_and_special_files_skipped(self):
        r = full(per_boot=listed(
            {'name': 'link', 'type': 'symlink', 'link_target': '/opt/run.sh',
             'target': {'type': 'file', 'mode': 0o700, 'noexec': False}},
            {'name': 'dangling', 'type': 'symlink', 'link_target': '/gone', 'target': None},
            {'name': 'todir', 'type': 'symlink', 'target': {'type': 'directory'}},
            {'name': 'noexec-link', 'type': 'symlink', 'target': {'type': 'file', 'mode': 0o755, 'noexec': True}},
            {'name': 'sub', 'type': 'directory'}, {'name': 'fifo', 'type': 'other'}))
        d = by_dir(r, 'per-boot')
        self.assertEqual([(s['name'], s['link_target']) for s in d['scripts']], [('link', '/opt/run.sh')])
        self.assertEqual({s['name']: s['reason'] for s in d['skipped']}, {
            'dangling': 'stat_failed', 'todir': 'directory', 'noexec-link': 'noexec_mount', 'sub': 'directory',
            'fifo': 'not_plain_file'})
        self.assertTrue(r['complete'])

    def test_noexec_directory_and_unobserved_mount(self):
        r = full(per_boot=listed(f('a'), noexec=True), per_once=listed(f('b'), noexec=None))
        self.assertEqual(by_dir(r, 'per-boot')['skipped'][0]['reason'], 'noexec_mount')
        self.assertTrue(by_dir(r, 'per-once')['scripts'][0]['mount_unobserved'])

    def test_absent_and_not_directory_run_nothing(self):
        r = full(per_boot={'state': 'not_directory'})
        self.assertTrue(r['complete'])
        self.assertEqual(r['scripts'], [])
        bad = full(per_boot={'state': 'absent', 'entries': [f('a')]})
        self.assertFalse(bad['complete'])

    def test_fails_closed(self):
        cases = {
            'directory_not_observed': c.assess({'per-boot': ABSENT, 'per-instance': ABSENT}),
            'directory_unreadable': full(per_boot={'state': 'unreadable'}),
            'listing_incomplete': full(per_boot=listed(f('a'), complete=False)),
            'duplicate_name': full(per_boot=listed(f('a'), f('a'))),
            'metadata_missing': full(per_boot=listed({'name': 'a', 'type': 'file'})),
            'symlink_target_unobserved': full(per_boot=listed({'name': 'a', 'type': 'symlink'})),
            'too_many_entries': full(per_boot=listed(*(f(str(i)) for i in range(c.MAX_ENTRIES + 1)))),
        }
        for code, r in cases.items():
            with self.subTest(code):
                self.assertFalse(r['complete'])
                self.assertIn(code, [g['code'] for g in r['gaps']])
        for bad in ({'name': 'a/b', 'type': 'file', 'mode': 0o755}, {'name': '..', 'type': 'file', 'mode': 1},
                    {'name': 'a', 'type': 'socket'}, 'a', {'name': 'a', 'type': 'file', 'mode': True},
                    {'name': 'x' * 256, 'type': 'file', 'mode': 0o755}):
            with self.subTest(bad=bad):
                r = full(per_boot=listed(bad))
                self.assertFalse(r['complete'])
                self.assertEqual(r['scripts'], [])
        for top in (None, [], {'per-boot': ABSENT, 'other': ABSENT}, {'per-boot': {'state': 'bogus'}}):
            with self.subTest(top=top):
                self.assertFalse(c.assess(top)['complete'])
        missing_flag = full(per_boot={'state': 'listed', 'entries': []})
        self.assertFalse(missing_flag['complete'])

    def test_gaps_are_bounded(self):
        r = full(per_boot=listed(*({'name': str(i), 'type': 'symlink'} for i in range(200))))
        self.assertEqual(len(r['gaps']), c.MAX_GAPS)
        self.assertEqual(r['gaps'][-1]['code'], 'gaps_truncated')

    def test_matches_upstream_selection_on_a_real_directory_tree(self):
        if os.geteuid() != 0:
            self.skipTest('root X_OK semantics need root')
        with tempfile.TemporaryDirectory() as tmp:
            d = os.path.join(tmp, 'per-boot')
            os.mkdir(d)
            target = os.path.join(tmp, 'target.sh')
            with open(target, 'w') as fh:
                fh.write('#!/bin/sh\n')
            os.chmod(target, 0o700)
            for name, mode in (('.hidden', 0o700), ('b~', 0o001), ('A', 0o644), ('a.dpkg-old', 0o755),
                               ('z', 0o000), ('café', 0o010)):
                p = os.path.join(d, name)
                open(p, 'w').close()
                os.chmod(p, mode)
            os.mkdir(os.path.join(d, 'subdir'))
            os.mkfifo(os.path.join(d, 'pipe'))
            os.symlink(target, os.path.join(d, 'link'))
            os.symlink(os.path.join(tmp, 'gone'), os.path.join(d, 'dangling'))
            os.symlink(tmp, os.path.join(d, 'dirlink'))
            r = c.assess({'per-boot': observe(d), 'per-instance': observe(os.path.join(tmp, 'per-instance')),
                          'per-once': observe(target)})
            self.assertTrue(r['complete'], r['gaps'])
            self.assertEqual([os.path.basename(s['path']) for s in by_dir(r, 'per-boot')['scripts']],
                             [os.path.basename(p) for p in upstream_runparts(d)])
            self.assertIsNone(upstream_runparts(os.path.join(tmp, 'per-instance')))
            self.assertIsNone(upstream_runparts(target))
            self.assertEqual(by_dir(r, 'per-instance')['scripts'] + by_dir(r, 'per-once')['scripts'], [])


if __name__ == '__main__':
    unittest.main()
