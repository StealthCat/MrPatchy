"""Tests for the pure GDM display-manager script contract (#1405)."""
from __future__ import annotations

import unittest

from app import gdm_scripts as g

SHA = 'a' * 64
CONF = '/etc/gdm3'


def exe(sha: str | None = SHA) -> dict:
    return {'state': 'present', 'kind': 'regular', 'executable': True, 'sha256': sha}


def plain() -> dict:
    return {'state': 'present', 'kind': 'regular', 'executable': False}


def directory() -> dict:
    return {'state': 'present', 'kind': 'directory'}


ABSENT = {'state': 'absent'}


def obs(paths: dict, listings: dict | None = None, confdir: str = CONF) -> dict:
    return {'confdir': confdir, 'paths': paths, 'listings': listings or {}}


class SelectTests(unittest.TestCase):
    def test_display_script_wins_over_host_and_default(self) -> None:
        o = obs({f'{CONF}/PostLogin/:0': exe(), f'{CONF}/PostLogin/ws1': exe(), f'{CONF}/PostLogin/Default': exe()})
        r = g.select(o, 'PostLogin', ':0', 'ws1')
        self.assertTrue(r['complete'])
        self.assertEqual((r['outcome'], r['script'], r['selector']), ('runs', f'{CONF}/PostLogin/:0', 'display_name'))
        self.assertEqual(r['argv'], [f'{CONF}/PostLogin/:0'])
        self.assertEqual(len(r['candidates']), 1)
        self.assertTrue(r['failure_aborts_login'])
        self.assertEqual(r['runs_as'], 'root')
        self.assertEqual(r['enoexec_fallback'], '/bin/sh')

    def test_falls_through_non_qualifying_candidates_in_order(self) -> None:
        o = obs({f'{CONF}/PreSession/:1': plain(), f'{CONF}/PreSession/ws1': directory(),
                 f'{CONF}/PreSession/Default': exe()})
        r = g.select(o, 'PreSession', ':1', 'ws1')
        self.assertEqual((r['outcome'], r['selector']), ('runs', 'default'))
        self.assertEqual([c.get('skipped_because') for c in r['candidates']],
                         ['no_execute_bit', 'not_regular_file', None])

    def test_dangling_or_absent_everywhere_runs_nothing(self) -> None:
        o = obs({f'{CONF}/PostSession/:0': ABSENT, f'{CONF}/PostSession/Default': ABSENT})
        r = g.select(o, 'PostSession', ':0')
        self.assertEqual(r['outcome'], 'none')
        self.assertTrue(r['complete'])
        self.assertFalse(r['failure_aborts_login'])

    def test_init_ignores_remote_host_and_runs_with_gdm_user(self) -> None:
        o = obs({f'{CONF}/Init/:0': ABSENT, f'{CONF}/Init/Default': exe()})
        r = g.select(o, 'Init', ':0', 'ws1')
        self.assertEqual((r['outcome'], r['selector'], r['env_user']), ('runs', 'default', 'gdm'))
        self.assertEqual([c['selector'] for c in r['candidates']], ['display_name', 'default'])

    def test_wayland_session_tries_phase_path_itself(self) -> None:
        # The phase path is an executable file, so g_build_filename(dir, NULL) runs it.
        o = obs({f'{CONF}/PostLogin': exe()})
        r = g.select(o, 'PostLogin', None)
        self.assertEqual((r['outcome'], r['script'], r['selector']), ('runs', f'{CONF}/PostLogin', 'empty_display_name'))
        # Normally the phase path is a directory and Default is next.
        o = obs({f'{CONF}/PostLogin': directory(), f'{CONF}/PostLogin/Default': exe()})
        r = g.select(o, 'PostLogin', '')
        self.assertEqual((r['outcome'], r['script']), ('runs', f'{CONF}/PostLogin/Default'))

    def test_unknown_candidate_is_undetermined_gap(self) -> None:
        o = obs({f'{CONF}/PostLogin/Default': exe()})
        r = g.select(o, 'PostLogin', ':0')
        self.assertEqual(r['outcome'], 'undetermined')
        self.assertFalse(r['complete'])
        self.assertEqual(r['gaps'][0]['code'], 'candidate_not_observed')
        o = obs({f'{CONF}/PostLogin/:0': {'state': 'present', 'kind': 'regular'}})
        self.assertEqual(g.select(o, 'PostLogin', ':0')['outcome'], 'undetermined')

    def test_host_with_slash_or_reparsed_path_is_a_gap(self) -> None:
        o = obs({f'{CONF}/PostLogin/:0': ABSENT})
        r = g.select(o, 'PostLogin', ':0', '../../tmp/x')
        self.assertEqual((r['outcome'], r['gaps'][0]['code']), ('undetermined', 'name_leaves_phase_directory'))
        o = obs({'/opt/my gdm/PostLogin/:0': exe()}, confdir='/opt/my gdm')
        r = g.select(o, 'PostLogin', ':0')
        self.assertEqual(r['script'], '/opt/my gdm/PostLogin/:0')
        self.assertIsNone(r['argv'])
        self.assertEqual((r['outcome'], r['gaps'][0]['code']),
                         ('undetermined', 'script_path_reparsed_by_shell_parse_argv'))

    def test_malformed_input(self) -> None:
        for bad in (None, {}, {'confdir': 'etc'}, {'confdir': CONF, 'paths': {'/x': {'state': 'gone'}}},
                    {'confdir': CONF, 'paths': {'/x': {'state': 'absent', 'kind': 'regular'}}},
                    {'confdir': CONF, 'paths': {'/x': {'state': 'present', 'kind': 'directory', 'sha256': SHA}}},
                    {'confdir': CONF, 'paths': {'/x': {'state': 'present', 'executable': 1}}},
                    {'confdir': CONF, 'extra': 1}):
            r = g.select(bad, 'PostLogin', ':0')
            self.assertEqual((r['outcome'], r['complete']), ('undetermined', False), bad)
            self.assertEqual(r['gaps'][0]['code'], 'invalid_observation')
        self.assertEqual(g.select(obs({}), 'Login', ':0')['gaps'][0]['code'], 'invalid_observation')


class EvaluateTests(unittest.TestCase):
    def _full(self, extra: dict | None = None, listings: dict | None = None) -> dict:
        paths = {f'{CONF}/{p}': directory() for p in g.PHASES}
        paths.update(extra or {})
        names = {f'{CONF}/{p}': [] for p in g.PHASES}
        names.update(listings or {})
        return obs(paths, names)

    def test_debian_default_layout(self) -> None:
        o = self._full({f'{CONF}/Init/Default': exe(), f'{CONF}/PreSession/Default': exe(),
                        f'{CONF}/PostSession/Default': exe(), f'{CONF}/PostLogin/Default.sample': plain()},
                       {f'{CONF}/Init': ['Default'], f'{CONF}/PreSession': ['Default'],
                        f'{CONF}/PostSession': ['Default'], f'{CONF}/PostLogin': ['Default.sample']})
        r = g.evaluate(o)
        self.assertTrue(r['complete'], r['gaps'])
        by = {p['phase']: p for p in r['phases']}
        self.assertEqual([s['path'] for s in by['PreSession']['scripts']], [f'{CONF}/PreSession/Default'])
        self.assertEqual(by['PostLogin']['scripts'], [])
        self.assertEqual(by['PostLogin']['inert'][0]['skipped_because'], 'no_execute_bit')
        self.assertTrue(by['PreSession']['failure_aborts_login'])
        self.assertEqual(by['Init']['applies_to'], 'legacy_xorg_and_xdmcp_displays')

    def test_display_host_and_unused_names(self) -> None:
        o = self._full({f'{CONF}/PostLogin/:0': exe(), f'{CONF}/PostLogin/ws1': exe(), f'{CONF}/Init/ws1': exe()},
                       {f'{CONF}/PostLogin': [':0', 'ws1'], f'{CONF}/Init': ['ws1']})
        r = g.evaluate(o)
        by = {p['phase']: p for p in r['phases']}
        self.assertEqual({s['name']: s['selector'] for s in by['PostLogin']['scripts']},
                         {':0': 'display_name', 'ws1': 'remote_host'})
        self.assertEqual(by['Init']['scripts'], [])
        self.assertEqual(by['Init']['inert'][0]['skipped_because'], 'name_never_selected')

    def test_executable_phase_file_runs_for_sessions_without_display(self) -> None:
        o = self._full({f'{CONF}/PostSession': exe()})
        by = {p['phase']: p for p in g.evaluate(o)['phases']}
        self.assertEqual(by['PostSession']['scripts'][0]['runs_for'], 'sessions_without_x11_display_name')

    def test_missing_listing_or_entry_is_a_gap(self) -> None:
        o = obs({f'{CONF}/{p}': directory() for p in g.PHASES}, {f'{CONF}/Init': []})
        r = g.evaluate(o)
        self.assertFalse(r['complete'])
        self.assertEqual({x['code'] for x in r['gaps']}, {'directory_listing_not_observed'})
        o = self._full(listings={f'{CONF}/PreSession': ['Default']})
        r = g.evaluate(o)
        self.assertEqual([(x['code'], x['phase']) for x in r['gaps']], [('candidate_not_observed', 'PreSession')])
        r = g.evaluate(obs({}))
        self.assertEqual({x['code'] for x in r['gaps']}, {'phase_path_not_observed'})

    def test_absent_phases_are_complete_and_empty(self) -> None:
        r = g.evaluate(obs({f'/etc/gdm/{p}': ABSENT for p in g.PHASES}, confdir='/etc/gdm/'))
        self.assertTrue(r['complete'])
        self.assertEqual(r['confdir'], '/etc/gdm')
        self.assertTrue(all(not p['scripts'] for p in r['phases']))

    def test_invalid_listing(self) -> None:
        for names in (['a/b'], ['..'], ['x', 'x'], [''], 'Default'):
            r = g.evaluate(obs({}, {f'{CONF}/Init': names}))
            self.assertEqual(r['gaps'][0]['code'], 'invalid_observation', names)


if __name__ == '__main__':
    unittest.main()
