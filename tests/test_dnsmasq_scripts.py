"""Tests for the pure dnsmasq script contract (#1365)."""
from __future__ import annotations

import pytest

from app import dnsmasq_scripts as d

ARGV = list(d.DEBIAN_ARGV)
DIR = '/etc/dnsmasq.d'


def files(**texts):
    """Map paths to captured texts with distinct identities."""
    out = {}
    for i, (path, text) in enumerate(texts.items(), 1):
        out[path] = {'error': text} if text in ('ENOENT', 'EACCES') else {'text': text, 'dev': 1, 'ino': i}
    return out


def conf(text, extra=None, entries=None, argv=None, **kw):
    fs = {d.DEFAULT_CONF: {'text': text, 'dev': 1, 'ino': 1}}
    fs.update(extra or {})
    dirs = {DIR: entries if entries is not None else []}
    return d.evaluate(argv or ARGV, fs, dirs, **kw)


def only(result):
    assert result['complete'], result
    return {p['kind']: p for p in result['programs']}


def test_dhcp_script_runs_as_root_by_default():
    prog = only(conf('dhcp-range=10.0.0.2,10.0.0.9\ndhcp-script=/usr/local/sbin/lease\n'))['dhcp-script']
    assert prog['command'] == '/usr/local/sbin/lease'
    assert prog['run_as'] == 'root' and prog['runs'] is True
    assert prog['source'] == {'path': d.DEFAULT_CONF, 'line': 2}
    assert prog['origin'] == 'not_assessed'


def test_scriptuser_applies_only_with_a_dhcp_range():
    # dnsmasq.c applies dhcp-scriptuser only when daemon->dhcp or dhcp6 is set.
    base = 'dhcp-script=/s\ndhcp-scriptuser=nobody\n'
    assert only(conf(base + 'dhcp-range=10.0.0.2,10.0.0.9\n'))['dhcp-script']['run_as'] == 'nobody'
    tftp = only(conf(base + 'enable-tftp\n'))['dhcp-script']
    assert tftp['run_as'] == 'root' and tftp['activated_by'] == ['enable-tftp']
    idle = only(conf(base))['dhcp-script']
    assert idle['runs'] is False and idle['activated_by'] == []


def test_no_daemon_keeps_root():
    prog = only(conf('dhcp-range=a\ndhcp-script=/s\ndhcp-scriptuser=nobody\nno-daemon\n'))['dhcp-script']
    assert prog['run_as'] == 'root'


def test_comment_quote_and_escape_rules():
    # '#' starts a comment only after whitespace; quotes hide it.
    assert only(conf('dhcp-script=/a#b\n'))['dhcp-script']['command'] == '/a#b'
    assert only(conf('dhcp-script=/a #b\n'))['dhcp-script']['command'] == '/a'
    assert only(conf('dhcp-script="/my dir/x #1"\n'))['dhcp-script']['command'] == '/my dir/x #1'
    assert only(conf('dhcp-script="/q\\"x"\n'))['dhcp-script']['command'] == '/q"x'
    assert only(conf('  dhcp-script  =   /s   \n'))['dhcp-script']['command'] == '/s'
    assert conf('dhcp-script="/open\n')['refused'] == f'missing " at line 1 of {d.DEFAULT_CONF}'


def test_option_names_are_exact():
    assert conf('dhcp-scrip=/s\n')['refused'].startswith('bad option')
    # A quoted name hides metacharacters, so it no longer matches.
    assert conf('"dhcp-script"=/s\n')['refused'].startswith('bad option')
    assert conf('dhcp-script\n')['refused'].startswith('missing parameter')
    assert conf('no-daemon=1\n')['refused'].startswith('extraneous parameter')


def test_single_value_options_and_overrides():
    assert conf('dhcp-script=/a\ndhcp-script=/b\n')['refused'].startswith('illegal repeated keyword dhcp-script')
    # A file value overrides the command line once.
    prog = only(conf('dhcp-script=/file\n', argv=ARGV + ['--dhcp-script=/cl']))['dhcp-script']
    assert prog['command'] == '/file'
    assert d.evaluate(ARGV + ['-6', '/a', '-6/b'], files(**{d.DEFAULT_CONF: ''}), {DIR: []})['refused'] \
        == 'illegal repeated flag --dhcp-script'
    # An empty value clears the script.
    assert only(conf('', argv=ARGV + ['--dhcp-script=/cl'], extra={}))['dhcp-script']['command'] == '/cl'
    assert only(conf('dhcp-script=\n', argv=ARGV + ['--dhcp-script=/cl'])) == {}


def test_lua_script_last_value_and_build_support():
    text = 'dhcp-luascript=/a.lua\ndhcp-luascript=/b.lua\n'
    assert only(conf(text, lua_support=True))['dhcp-luascript']['command'] == '/b.lua'
    assert conf(text, lua_support=False)['refused'].startswith('recompile with HAVE_LUASCRIPT')
    blocked = conf(text)
    assert not blocked['complete'] and blocked['gaps'][0]['code'] == 'lua_support_unobserved'


def test_conf_dir_filters_and_order():
    entries = [
        {'name': 'b.conf', 'type': 'regular'}, {'name': 'B.conf', 'type': 'regular'},
        {'name': 'x.conf~', 'type': 'regular'}, {'name': '#x#', 'type': 'regular'},
        {'name': '.hidden', 'type': 'regular'}, {'name': 'old.dpkg-old', 'type': 'regular'},
        {'name': 'sub', 'type': 'directory'}, {'name': 'a.conf', 'type': 'regular'},
    ]
    extra = files(**{f'{DIR}/b.conf': 'dhcp-script=/b\n', f'{DIR}/B.conf': '', f'{DIR}/a.conf': ''})
    for i, path in enumerate(extra, 10):
        extra[path]['ino'] = i
    result = conf('', extra=extra, entries=entries)
    assert result['files_read'][:3] == [f'{DIR}/B.conf', f'{DIR}/a.conf', f'{DIR}/b.conf']
    reasons = {s['path'].rsplit('/', 1)[1]: s['reason'] for s in result['skipped']}
    assert reasons == {'x.conf~': 'backup_or_dotfile', '#x#': 'backup_or_dotfile', '.hidden': 'backup_or_dotfile',
                       'old.dpkg-old': 'ignored_suffix', 'sub': 'not_regular_file'}
    assert only(result)['dhcp-script']['source']['path'] == f'{DIR}/b.conf'


def test_conf_dir_required_suffix_and_comma_trimming():
    chosen, skipped = d.conf_dir_files('/c', ['*.conf'], [{'name': 'a.conf', 'type': 'regular'},
                                                          {'name': '.conf', 'type': 'regular'},
                                                          {'name': 'b.txt', 'type': 'regular'}])
    assert chosen == ['/c/a.conf']
    assert [s['reason'] for s in skipped] == ['backup_or_dotfile', 'missing_required_suffix']
    # The suffix must be strictly shorter than the name.
    assert d.conf_dir_files('/c', ['*.conf'], [{'name': 'x', 'type': 'regular'}])[0] == []
    pairs = d.parse_line('/etc/x , *.conf ,  .bak\n')
    assert d.split_commas(pairs) == ['/etc/x', '*.conf', '.bak']
    quoted = d.parse_line('"/etc/a,b",.bak\n')
    assert d.split_commas(quoted) == ['/etc/a,b', '.bak']


def test_repeated_files_are_read_once_and_conf_file_order():
    extra = {'/etc/extra.conf': {'text': 'dhcp-script=/x\n', 'dev': 1, 'ino': 1}}
    result = conf('conf-file=/etc/extra.conf\n', extra=extra)
    assert result['skipped'] == [{'path': '/etc/extra.conf', 'reason': 'already_read'}]
    assert only(result) == {}


def test_main_file_rules():
    # The default file may be missing; an explicit one may not.
    missing = d.evaluate(['dnsmasq'], files(**{d.DEFAULT_CONF: 'ENOENT'}), {})
    assert missing['complete'] and missing['skipped'][0]['reason'] == 'default_file_missing'
    explicit = d.evaluate(['dnsmasq', '-C', '/etc/x.conf'], files(**{'/etc/x.conf': 'ENOENT'}), {})
    assert explicit['refused'] == 'cannot read /etc/x.conf: ENOENT'
    # The first -C is read after the command line, so its value overrides a later -7 file.
    fs = files(**{'/m.conf': 'dhcp-script=/main\n', '/d/z.conf': 'dhcp-luascript=/z.lua\n'})
    result = d.evaluate(['dnsmasq', '-C/m.conf', '--conf-dir=/d'], fs,
                        {'/d': [{'name': 'z.conf', 'type': 'regular'}]}, lua_support=True)
    assert result['files_read'] == ['/d/z.conf', '/m.conf']


def test_conf_script_is_reported_and_blocks():
    result = conf('conf-script=/usr/local/bin/gen-config\n')
    assert result['programs'] == [{
        'kind': 'conf-script', 'command': '/usr/local/bin/gen-config', 'via': '/bin/sh -c',
        'when': 'while the configuration is read', 'run_as': 'root',
        'source': {'path': d.DEFAULT_CONF, 'line': 1}, 'origin': 'not_assessed'}]
    assert not result['complete'] and result['gaps'][0]['code'] == 'conf_script_output_unobserved'


@pytest.mark.parametrize(('argv', 'fs', 'dirs', 'code'), [
    (None, {}, {}, 'argv_unobserved'),
    (ARGV, {}, {DIR: []}, 'file_unobserved'),
    (ARGV, files(**{d.DEFAULT_CONF: ''}), {}, 'directory_unobserved'),
    (ARGV, {d.DEFAULT_CONF: {'text': ''}}, {DIR: []}, 'file_identity_unobserved'),
    (['dnsmasq', '--dhcp-scr=/x'], files(**{d.DEFAULT_CONF: ''}), {}, 'abbreviated_long_option'),
    (['dnsmasq', '-C', '-'], {}, {}, 'stdin_configuration'),
    (['dnsmasq'], files(**{d.DEFAULT_CONF: 'x' * 1100 + '\n'}), {}, 'line_too_long'),
    (['dnsmasq', '-7', '/d'], files(**{d.DEFAULT_CONF: ''}), {'/d': [{'name': 'a'}]}, 'directory_entry_type_unobserved'),
])
def test_blocking_gaps(argv, fs, dirs, code):
    result = d.evaluate(argv, fs, dirs)
    assert not result['complete'] and result['programs'] == []
    assert result['gaps'][0]['code'] == code and result['gaps'][0]['blocking']


@pytest.mark.parametrize(('argv', 'reason'), [
    (['dnsmasq', '--no-such-option'], 'unrecognized option --no-such-option'),
    (['dnsmasq', '-Q'], 'option -Q requires an argument'),
    (['dnsmasq', '-j'], 'option -j requires an argument'),
    (['dnsmasq', 'stray'], 'junk found in command line'),
    (['dnsmasq', '--no-daemon=1'], 'option --no-daemon does not take an argument'),
])
def test_command_line_refusals(argv, reason):
    assert d.evaluate(argv, files(**{d.DEFAULT_CONF: ''}), {})['refused'] == reason


def test_short_option_clusters_consume_arguments():
    # -k takes no argument; -x takes /p, so -6 is read as dnsmasq's next option.
    fs = files(**{d.DEFAULT_CONF: ''})
    prog = only(d.evaluate(['dnsmasq', '-kx', '/p', '-6', '/s', '-F', 'a'], fs, {}))['dhcp-script']
    assert prog['command'] == '/s' and prog['source'] == {'path': None, 'line': None}
    assert prog['activated_by'] == ['dhcp-range']


def test_option_table_matches_source_counts():
    # opts[] in dnsmasq 2.92 has 194 long options.
    assert len(d.LONG_OPTIONS) == 194
    assert d.LONG_OPTIONS['conf-file'] == 2 and d.LONG_OPTIONS['dhcp-script'] == 1
    assert d.SHORT_OPTIONS['6'] is True and d.SHORT_OPTIONS['d'] is False


def test_only_newline_ends_a_line():
    # fgets() keeps '\r' in the line; read_file() turns it into a space before '=' is found.
    prog = only(conf('dhcp-script=/a\rdhcp-script=/b\n'))['dhcp-script']
    assert prog['command'] == '/a dhcp-script=/b'
    assert only(conf('dhcp-script=/last'))['dhcp-script']['command'] == '/last'


def test_refusal_names_the_innermost_file():
    extra = {'/etc/inc.conf': {'text': '\nbogus\n', 'dev': 1, 'ino': 2}}
    result = conf('# head\nconf-file=/etc/inc.conf\n', extra=extra)
    assert result['refused'] == 'bad option at line 2 of /etc/inc.conf'


def test_conf_file_without_value():
    fs = files(**{d.DEFAULT_CONF: 'dhcp-script=/default\n'})
    # The first value-less --conf-file leaves the default main file in place.
    assert only(d.evaluate(['dnsmasq', '--conf-file'], fs, {}))['dhcp-script']['command'] == '/default'
    assert only(conf('conf-file\n')) == {}


def test_line_length_boundary():
    fits = 'dhcp-script=/' + 'a' * (1023 - len('dhcp-script=/')) + '\n'
    assert len(fits) == 1024
    assert only(conf(fits))['dhcp-script']['command'].startswith('/aaa')
    # One more byte and fgets() would split the line.
    assert conf('#' + fits)['gaps'][0]['code'] == 'line_too_long'
