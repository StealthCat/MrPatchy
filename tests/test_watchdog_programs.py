"""Tests for the pure watchdog daemon program contract (#1369)."""
from __future__ import annotations

import os
import random
import shutil
import stat
import subprocess
import tempfile
import unittest

from app import watchdog_programs as wp

LISTED_EMPTY = {'state': 'listed', 'complete': True, 'entries': []}


def run(text, options='', directories=None):
    if directories is None:
        directories = {wp.DEFAULT_TEST_DIRECTORY: LISTED_EMPTY}
    return wp.evaluate({'state': 'read', 'text': text}, options, directories)


def codes(result):
    return [g['code'] for g in result['gaps']]


class ParseTests(unittest.TestCase):
    def test_default_config_runs_nothing_but_lists_default_directory(self):
        result = run('# nothing\n')
        self.assertTrue(result['complete'])
        self.assertTrue(result['starts'])
        self.assertEqual(result['test_programs'], [])
        self.assertEqual(result['test_directory'], {'path': '/etc/watchdog.d', 'line': None})
        self.assertIsNone(result['repair_binary'])
        self.assertEqual(result['runs_as'], 'root')

    def test_test_binaries_accumulate_and_repair_takes_last(self):
        result = run('test-binary = /a\nrepair-binary=/r1\n  test-binary\t=\t/b c  \nrepair-binary = /r2\n')
        self.assertEqual([p['argv'] for p in result['test_programs']], [['/a'], ['/b c']])
        self.assertEqual(result['repair_binary']['path'], '/r2')
        self.assertEqual(result['repair_binary']['line'], 4)
        self.assertEqual(result['test_programs'][0]['repair_argv'], ['/r2', '<errcode>', '/a'])

    def test_blank_values(self):
        result = run('repair-binary = /r\nrepair-binary =\ntest-binary =\ntest-directory =\n', directories={})
        self.assertIsNone(result['repair_binary'])
        self.assertEqual(result['test_programs'], [])
        self.assertIsNone(result['test_directory'])
        self.assertTrue(result['complete'])

    def test_no_inline_comments_quotes_or_case_folding(self):
        result = run('test-binary = /x # c\nTest-Binary = /y\ntest-binary = "/z"\n#test-binary = /w\n'
                     'test-binary /v\n')
        self.assertEqual([p['path'] for p in result['test_programs']], ['/x # c', '"/z"'])
        self.assertIn('relative_program_path', codes(result))

    def test_white_space_is_only_the_c_set(self):
        result = run('\btest-binary\b=\b/a\r\n\vtest-binary = /b\ntest-binary = /c\f\n')
        self.assertEqual([p['path'] for p in result['test_programs']], ['/a', '/c\f'])

    def test_nul_truncates_line(self):
        result = run('test-binary = /a\0/b\n\0test-binary = /c\n')
        self.assertEqual([p['path'] for p in result['test_programs']], ['/a'])

    def test_first_equals_splits(self):
        result = run('test-binary = /a=b\n')
        self.assertEqual(result['test_programs'][0]['path'], '/a=b')

    def test_interval_fatal(self):
        for value, starts in (('0', False), ('-1', False), ('-', False), ('x', True), ('', True), ('5', True),
                              ('+3', True), ('4294967296', False), ('99999999999', True)):
            with self.subTest(value=value):
                result = run(f'test-binary = /a\ninterval = {value}\n')
                self.assertIs(result['starts'], starts)
                self.assertEqual(bool(result['test_programs']), starts)

    def test_config_absent_means_daemon_does_not_start(self):
        result = wp.evaluate({'state': 'absent'}, '', {})
        self.assertIs(result['starts'], False)
        self.assertTrue(result['complete'])

    def test_config_unreadable_or_missing_is_blocking(self):
        self.assertIn('config_unreadable', codes(wp.evaluate({'state': 'unreadable'}, '', {})))
        self.assertIn('config_not_observed', codes(wp.evaluate(None, '', {})))
        self.assertFalse(wp.evaluate(None, '', {})['complete'])


class OptionTests(unittest.TestCase):
    def test_modelled_flags(self):
        for options in ('', '-v', '-Fvs', '--verbose --sync', '-q -b'):
            with self.subTest(options=options):
                self.assertTrue(run('', options)['complete'])

    def test_config_option_or_unknown_is_gap(self):
        for options in ('-c /tmp/x', '--config-file=/tmp/x', '-vc/tmp/x', '-X 3', 'junk'):
            with self.subTest(options=options):
                result = run('', options)
                self.assertIn('options_unverified', codes(result))
                self.assertFalse(result['complete'])

    def test_options_not_observed(self):
        self.assertIn('options_not_observed', codes(run('', None)))


class DirectoryTests(unittest.TestCase):
    def listing(self, *entries, complete=True):
        return {'/etc/watchdog.d': {'state': 'listed', 'complete': complete, 'entries': list(entries)}}

    def test_executable_regular_files_run_as_v1(self):
        result = run('repair-binary = /r\n', directories=self.listing(
            {'name': 'ok', 'type': 'file', 'mode': 0o700},
            {'name': '.hidden', 'type': 'file', 'mode': 0o755},
            {'name': 'noexec', 'type': 'file', 'mode': 0o644},
            {'name': 'groupexec', 'type': 'file', 'mode': 0o455},
            {'name': 'wonly', 'type': 'file', 'mode': 0o300},
            {'name': 'sub', 'type': 'directory'},
            {'name': 'dangling', 'type': 'stat_failed'},
            {'name': 'fifo', 'type': 'other'}))
        self.assertEqual([p['argv'] for p in result['test_programs']], [['/etc/watchdog.d/ok', 'test']])
        self.assertEqual(result['test_programs'][0]['repair_argv'],
                         ['/etc/watchdog.d/ok', 'repair', '<errcode>', '/etc/watchdog.d/ok'])
        reasons = {s['name']: s['reason'] for s in result['skipped_entries']}
        self.assertEqual(reasons, {'.hidden': 'hidden', 'noexec': 'not_owner_executable',
                                   'groupexec': 'not_owner_executable', 'wonly': 'not_owner_readable',
                                   'sub': 'not_regular', 'dangling': 'stat_failed', 'fifo': 'not_regular'})
        self.assertTrue(result['complete'])

    def test_path_max(self):
        name = 'a' * (wp.PATH_MAX - len('/etc/watchdog.d/'))
        result = run('', directories=self.listing({'name': name, 'type': 'file', 'mode': 0o700},
                                                  {'name': name[:-1], 'type': 'file', 'mode': 0o700}))
        self.assertEqual([p['path'] for p in result['test_programs']], ['/etc/watchdog.d/' + name[:-1]])

    def test_directory_gaps(self):
        self.assertIn('directory_not_observed', codes(run('', directories={})))
        self.assertIn('listing_incomplete', codes(run('', directories=self.listing(complete=False))))
        unreadable = run('', directories={'/etc/watchdog.d': {'state': 'unreadable'}})
        self.assertIn('directory_unreadable', codes(unreadable))
        self.assertFalse(unreadable['complete'])
        self.assertTrue(run('', directories={'/etc/watchdog.d': {'state': 'absent'}})['complete'])

    def test_nondefault_and_relative_directory(self):
        result = run('test-directory = /opt/t\n', directories={
            '/opt/t': {'state': 'listed', 'complete': True, 'entries': [{'name': 'x', 'type': 'file',
                                                                          'mode': 0o755}]}})
        self.assertEqual([p['path'] for p in result['test_programs']], ['/opt/t/x'])
        self.assertIn('directory_not_observed', codes(run('test-directory = /opt/t\n')))
        self.assertIn('relative_test_directory', codes(run('test-directory = t\n')))

    def test_malformed_entry(self):
        result = run('', directories=self.listing({'name': 'a/b', 'type': 'file', 'mode': 0o700},
                                                  {'name': 'x', 'type': 'file', 'mode': True}))
        self.assertIn('input_malformed', codes(result))
        self.assertFalse(result['complete'])


WATCHDOG_SRC = os.environ.get('WATCHDOG_SRC')  # path to an extracted watchdog-5.16 source tree
HARNESS = r'''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include "extern.h"
int log_message(int level, const char *fmt, ...) { (void)level; (void)fmt; return 0; }
void fatal_error(int code, const char *fmt, ...) { (void)code; (void)fmt; printf("FATAL\n"); exit(0); }
void *xcalloc(size_t n, size_t s) { void *p = calloc(n, s); if (!p) exit(3); return p; }
char *xstrdup(const char *s) { char *p = strdup(s); if (!p) exit(3); return p; }
static void pr(const char *s) { for (; *s; s++) printf("%02x", (unsigned char)*s); }
int main(int argc, char **argv) {
  struct list *a;
  read_config(argv[1]);
  for (a = tr_bin_list; a; a = a->next) { printf("T %d ", a->version); pr(a->name); printf("\n"); }
  printf("R "); if (repair_bin) pr(repair_bin); else printf("-"); printf("\n");
  return 0;
}
'''


@unittest.skipUnless(WATCHDOG_SRC and shutil.which('gcc') and not os.path.exists(wp.DEFAULT_TEST_DIRECTORY),
                     'needs WATCHDOG_SRC, gcc and no local /etc/watchdog.d')
class UpstreamDifferentialTests(unittest.TestCase):
    """Compile upstream read_config with a stub harness and compare random configs and directories."""

    @classmethod
    def setUpClass(cls):
        cls.work = tempfile.mkdtemp()
        harness = os.path.join(cls.work, 'harness.c')
        with open(harness, 'w') as fh:
            fh.write(HARNESS)
        cls.binary = os.path.join(cls.work, 'harness')
        subprocess.run(['gcc', '-w', '-I', os.path.join(WATCHDOG_SRC, 'include'), '-I', WATCHDOG_SRC,
                        '-DTESTBIN_PATH="/etc/watchdog.d"', '-DTIMER_MARGIN=60', '-o', cls.binary,
                        harness, os.path.join(WATCHDOG_SRC, 'src', 'configfile.c'),
                        os.path.join(WATCHDOG_SRC, 'src', 'read-conf.c')], check=True)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.work, ignore_errors=True)

    def _random_value(self, rng):
        pieces = ['/bin/x', '/a b', '#', '=', ' ', '\t', '\b', '\r', '\v', '\f', '"', "'", '\\', '0', '-1', '+2',
                  '/r', 'rel', '\0', 'é']
        return ''.join(rng.choice(pieces) for _ in range(rng.randint(0, 4)))

    def _random_config(self, rng, test_dir):
        keys = ['test-binary', 'repair-binary', 'interval', 'test-directory', 'Test-Binary', 'test-binary ',
                'file', '#test-binary', 'verbose']
        lines = []
        for _ in range(rng.randint(0, 8)):
            pre = rng.choice(['', ' ', '\t', '\b', '\v'])
            key = rng.choice(keys)
            if key == 'test-directory' and rng.random() < 0.7:
                value = test_dir
            elif key == 'interval':
                value = rng.choice(['0', '1', '-3', 'x', '', ' 5', '4294967296'])
            else:
                value = self._random_value(rng)
            sep = rng.choice(['=', ' = ', '\t=\t', '=\b', ' '])
            lines.append(pre + key + sep + value + rng.choice(['', ' ', '\r', '\b']))
        return '\n'.join(lines) + rng.choice(['', '\n'])

    def _populate(self, rng, directory):
        os.mkdir(directory)
        entries = []
        for i in range(rng.randint(0, 6)):
            name = rng.choice(['t', '.h', 'x-', 'a b', 'é']) + str(i)
            path = os.path.join(directory, name)
            kind = rng.choice(['file', 'file', 'dir', 'link', 'dangling', 'fifo'])
            mode = rng.choice([0o700, 0o755, 0o644, 0o455, 0o300, 0o500, 0o100])
            if kind == 'dir':
                os.mkdir(path)
                entries.append({'name': name, 'type': 'directory'})
            elif kind == 'fifo':
                os.mkfifo(path)
                entries.append({'name': name, 'type': 'other'})
            elif kind == 'dangling':
                os.symlink(os.path.join(directory, 'missing' + str(i)), path)
                entries.append({'name': name, 'type': 'stat_failed'})
            else:
                target = path if kind == 'file' else os.path.join(self.work, f'target{rng.random()}')
                with open(target, 'w') as fh:
                    fh.write('#!/bin/sh\n')
                os.chmod(target, mode)
                if kind == 'link':
                    os.symlink(target, path)
                entries.append({'name': name, 'type': 'file', 'mode': stat.S_IMODE(os.stat(path).st_mode)})
        return {'state': 'listed', 'complete': True, 'entries': entries}

    def test_random_configs_match_upstream(self):
        rng = random.Random(1369)
        checked = 0
        for trial in range(400):
            test_dir = os.path.join(self.work, f'd{trial}')
            listing = self._populate(rng, test_dir)
            text = self._random_config(rng, test_dir)
            conf = os.path.join(self.work, f'c{trial}.conf')
            with open(conf, 'wb') as fh:
                fh.write(text.encode('utf-8', 'surrogateescape'))
            out = subprocess.run([self.binary, conf], capture_output=True, check=True).stdout.decode().splitlines()
            directories = {test_dir: listing, wp.DEFAULT_TEST_DIRECTORY: {'state': 'absent'}}
            result = wp.evaluate({'state': 'read', 'text': text}, '', directories)
            if out == ['FATAL']:
                self.assertIs(result['starts'], False, text)
                continue
            self.assertIs(result['starts'], True, text)
            tests = [line.split(' ', 2) for line in out if line.startswith('T ')]
            v0 = [bytes.fromhex(t[2]) if len(t) > 2 else b'' for t in tests if t[1] == '0']
            v1 = sorted(bytes.fromhex(t[2]) for t in tests if t[1] == '1')
            mine_v0 = [p['path'].encode('utf-8', 'surrogateescape') for p in result['test_programs']
                       if p['version'] == 0]
            mine_v1 = sorted(p['path'].encode('utf-8', 'surrogateescape') for p in result['test_programs']
                             if p['version'] == 1)
            self.assertEqual(mine_v0, v0, text)
            if not any(g['code'] == 'relative_test_directory' for g in result['gaps']):
                self.assertEqual(mine_v1, v1, text)
            repair = out[-1][2:]
            mine_repair = result['repair_binary']['path'].encode('utf-8', 'surrogateescape').hex() \
                if result['repair_binary'] else '-'
            self.assertEqual(mine_repair, repair, text)
            checked += 1
        self.assertGreater(checked, 200)


if __name__ == '__main__':
    unittest.main()
