"""Pure LightDM seat-script contract (#1301)."""
import ctypes
import random

import pytest

from app import lightdm_scripts as ls

D = '/etc/lightdm/lightdm.conf.d'
USR = '/usr/share/lightdm/lightdm.conf.d'
LOCAL = '/usr/local/share/lightdm/lightdm.conf.d'
XDG = '/etc/xdg/lightdm/lightdm.conf.d'
EMPTY = {USR: [], LOCAL: [], XDG: [], D: []}


def run(main=None, files=None, listings=None, **kw):
    all_files = dict(files or {})
    if main is not None:
        all_files[ls.MAIN_PATH] = main
    return ls.evaluate(files=all_files, listings={**EMPTY, **(listings or {})}, main_missing=main is None, **kw)


def scripts(result, seat=0):
    return {s['key']: s for s in result['seats'][seat]['scripts']}


def test_main_file_script_runs_as_root_with_hash():
    r = run('[Seat:*]\nsession-setup-script = /usr/local/bin/setup --x \n')
    assert r['status'] == 'loads' and r['complete'] and r['origin'] == 'not_assessed' and r['runs_as'] == 'root'
    s = scripts(r)['session-setup-script']
    assert s['runs'] and s['command'] == '/usr/local/bin/setup --x ' and s['runs_as'] == 'root'
    assert s['source'] == ls.MAIN_PATH and s['section'] == 'Seat:*' and len(s['command_sha256']) == 64


def test_load_order_drop_ins_then_main_and_seat_defaults_alias():
    r = run('[SeatDefaults]\ndisplay-setup-script=/main\n',
            files={USR + '/50-a.conf': '[Seat:*]\ndisplay-setup-script=/usr\ngreeter-setup-script=/usr-g\n',
                   XDG + '/10-x.conf': '[Seat:*]\ngreeter-setup-script=/xdg\n',
                   D + '/a.conf': '[Seat:*]\nsession-cleanup-script=/d\n'},
            listings={USR: ['50-a.conf', 'README'], XDG: ['10-x.conf'], D: ['a.conf', 'b.conf.bak']})
    assert r['files_read'] == [USR + '/50-a.conf', XDG + '/10-x.conf', D + '/a.conf', ls.MAIN_PATH]
    got = scripts(r)
    assert got['display-setup-script']['command'] == '/main'
    assert got['greeter-setup-script']['command'] == '/xdg'
    assert got['session-cleanup-script']['source'] == D + '/a.conf' and r['complete']


def test_data_dirs_earlier_directory_wins():
    first, second = '/opt/a/lightdm/lightdm.conf.d', '/opt/b/lightdm/lightdm.conf.d'
    r = ls.evaluate(files={first + '/x.conf': '[Seat:*]\ndisplay-stopped-script=/a\n',
                           second + '/x.conf': '[Seat:*]\ndisplay-stopped-script=/b\n'},
                    listings={first: ['x.conf'], second: ['x.conf'], XDG: [], D: []},
                    data_dirs=('/opt/a', '/opt/b'), main_missing=True)
    assert scripts(r)['display-stopped-script']['command'] == '/a'


def test_seat_glob_sections_apply_on_top_in_group_order():
    r = run('[Seat:seat*]\nsession-setup-script=/glob\n[Seat:*]\nsession-setup-script=/all\n'
            '[Seat:seat1]\nsession-setup-script=/one\n', seat_names=('seat0', 'seat1', 'other'))
    assert [scripts(r, i)['session-setup-script']['command'] for i in range(3)] == ['/glob', '/one', '/all']
    assert r['seats'][1]['sections'] == ['Seat:*', 'Seat:seat*', 'Seat:seat1']


def test_escapes_and_invalid_value_unsets_script():
    r = run('[Seat:*]\nsession-setup-script=/bin/a\\sb\\tc\n[Seat:seat0]\ndisplay-setup-script=/x\n'
            '[Seat:seat*]\ndisplay-setup-script=/bad\\q\n')
    got = scripts(r)
    assert got['session-setup-script']['command'] == '/bin/a b\tc'
    assert got['display-setup-script']['runs'] is False and got['display-setup-script']['command'] is None


def test_refused_drop_in_is_skipped_and_refused_main_stops_lightdm():
    r = run('[Seat:*]\ndisplay-setup-script=/main\n',
            files={D + '/a.conf': 'display-setup-script=/no-group\n',
                   D + '/b.conf': '[Seat:*]\ngreeter-setup-script=/b\n'},
            listings={D: ['b.conf', 'a.conf']})
    assert [g['code'] for g in r['gaps']] == ['file_refused'] and r['complete']
    assert scripts(r)['greeter-setup-script']['command'] == '/b'
    bad = run('[Seat:*]\nnot a pair\n', files={D + '/b.conf': '[Seat:*]\ngreeter-setup-script=/b\n'},
              listings={D: ['b.conf']})
    assert bad['status'] == 'config_error' and bad['seats'] == []


def test_empty_command_is_flagged():
    got = scripts(run('[Seat:*]\nsession-cleanup-script=  \n'))
    assert got['session-cleanup-script']['empty'] is True


@pytest.mark.parametrize('case', ['unobserved_dir', 'unread_file', 'binary', 'utf8', 'big'])
def test_fail_closed(case):
    listings, files, main = {}, {}, '[Seat:*]\n'
    if case == 'unobserved_dir':
        listings = {D: None}
    elif case == 'unread_file':
        listings, files = {D: ['a.conf']}, {D + '/a.conf': None}
    elif case == 'binary':
        main = b'[Seat:*]\x00\n'
    elif case == 'utf8':
        main = b'[Seat:*]\nsession-setup-script=/x\xff\n'
    else:
        main = '[Seat:*]\n#' + 'x' * ls.MAX_TEXT
    assert run(main, files=files, listings=listings)['complete'] is False


# --- Differential check against the system GLib GKeyFile -------------------------------------------

def _glib():
    try:
        lib = ctypes.CDLL('libglib-2.0.so.0')
    except OSError:
        pytest.skip('libglib-2.0 is not available')
    lib.g_key_file_new.restype = ctypes.c_void_p
    lib.g_key_file_load_from_data.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_ssize_t, ctypes.c_int,
                                              ctypes.c_void_p]
    lib.g_key_file_get_groups.restype = ctypes.POINTER(ctypes.c_char_p)
    lib.g_key_file_get_groups.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    lib.g_key_file_get_keys.restype = ctypes.POINTER(ctypes.c_char_p)
    lib.g_key_file_get_keys.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_void_p]
    for fn in (lib.g_key_file_get_value, lib.g_key_file_get_string):
        fn.restype = ctypes.c_void_p
        fn.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p]
    lib.g_free.argtypes = [ctypes.c_void_p]
    lib.g_key_file_free.argtypes = [ctypes.c_void_p]
    return lib


def _glib_parse(lib, data: bytes):
    def strv(p):
        out, i = [], 0
        while p and p[i] is not None:
            out.append(p[i])
            i += 1
        return out

    def take(ptr):
        if not ptr:
            return None
        value = ctypes.string_at(ptr)
        lib.g_free(ptr)
        return value.decode('utf-8')

    kf = lib.g_key_file_new()
    try:
        if not lib.g_key_file_load_from_data(kf, data, len(data), 0, None):
            return None
        out = []
        for group in strv(lib.g_key_file_get_groups(kf, None)):
            values = {}
            for key in strv(lib.g_key_file_get_keys(kf, group, None, None)):
                if key.endswith(b']'):
                    continue  # translations depend on the process locale and never name a script
                values[key.decode()] = (take(lib.g_key_file_get_value(kf, group, key, None)),
                                        take(lib.g_key_file_get_string(kf, group, key, None)))
            out.append((group.decode(), values))
        return out
    finally:
        lib.g_key_file_free(kf)


_PIECES = ['[Seat:*]', '[SeatDefaults]', '[Seat:seat0]', '[LightDM]', '[ A ]', '[a]b', '[]', '[x]  ', ' [y]\t',
           '[a[b]', '[c]]', 'session-setup-script', 'k', ' k', 'k ', 'k[de]', 'k[d e]', 'k[]', 'k[x]y', 'a b',
           'Encoding', '=', ' = ', '/bin/x', '\\s', '\\n', '\\t', '\\r', '\\\\', '\\q', '\\', '#', '# c', '\r',
           ' ', '\t', '\v', 'UTF-8', 'latin1', ';', '"q"', 'é']


def _random_file(rng):
    lines = []
    for _ in range(rng.randint(0, 8)):
        lines.append(''.join(rng.choice(_PIECES) for _ in range(rng.randint(0, 4))))
    return '\n'.join(lines) + rng.choice(['', '\n', '\r\n'])


def test_keyfile_parser_matches_glib():
    lib = _glib()
    rng = random.Random(1301)
    fixed = ['[Seat:*]\nk=v\n', 'k=v\n', '[A]\nk=1\nk=2\n', '[A]\n k [de]= v\n', '[A]\n=v\n', '[A]x\nk=v\n',
             '[A]\nk\n', '[A]\nEncoding=latin1\n', '[B]\n[A]\nEncoding=latin1\n', '  [A]  \nk=v\r\n']
    cases = fixed + [_random_file(rng) for _ in range(4000)]
    mismatches = []
    for text in cases:
        expected = _glib_parse(lib, text.encode())
        try:
            got = [(g, {k: (v, ls.unescape(v)) for k, v in vals.items()}) for g, vals in ls.parse_keyfile(text)]
        except ls.KeyFileError:
            got = None
        if got != expected:
            mismatches.append((text, expected, got))
    assert not mismatches, mismatches[:3]


@pytest.mark.parametrize('pattern,name,ok', [('*', '', True), ('seat?', 'seat1', True), ('seat?', 'seat', False),
                                             ('s*t*', 'seat0', True), ('*0', 'seat0', True), ('[s]eat0', 'seat0', False)])
def test_pattern_match_simple(pattern, name, ok):
    assert ls._match_simple(pattern, name) is ok
