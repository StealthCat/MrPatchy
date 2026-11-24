"""Tests for the pure netfilter-persistent plugin contract (#1479).

Expected outcomes follow the netfilter-persistent 1.0.24 script under dash and
debianutils run-parts.
"""
from app import netfilter_persistent as nf

# The defaults file shipped by netfilter-persistent 1.0.24, abridged to its assignments.
SHIPPED = """# Configuration for netfilter-persistent
# Plugins may extend this file or have their own

FLUSH_ON_STOP=0

# IPTABLES_SKIP_SAVE=yes
IPTABLES_EXPLICIT_FLUSH=no
IP6TABLES_EXPLICIT_FLUSH=no
IPTABLES_TEST_RULESET=yes
IP6TABLES_TEST_RULESET=yes
"""
LISTED = {'path': nf.DEFAULT_PLUGINS, 'state': 'directory'}
SHIPPED_PLUGINS = [
    {'name': '25-ip6tables', 'type': 'file', 'mode': 0o755},
    {'name': '15-ip4tables', 'type': 'file', 'mode': 0o755},
    {'name': '10-ipset', 'type': 'file', 'mode': 0o755},
    {'name': '40-ipset', 'type': 'file', 'mode': 0o755},
]


def run(text=SHIPPED, entries=SHIPPED_PLUGINS, directory=LISTED, state='file'):
    return nf.evaluate(defaults={'state': state, 'text': text}, directory=directory, entries=entries)


def codes(result):
    return {g['code'] for g in result['gaps']}


def test_shipped_install_runs_plugins_in_byte_order_and_does_not_flush_at_stop():
    result = run()
    assert result['complete'] is True
    assert result['user'] == 'root' and result['origin'] == 'not_assessed'
    assert result['defaults']['sourced_as_root'] is True and result['defaults']['static'] is True
    assert [p['name'] for p in result['plugins']] == ['10-ipset', '15-ip4tables', '25-ip6tables', '40-ipset']
    start = result['actions']['start']
    assert start['argv'][0] == [f'{nf.DEFAULT_PLUGINS}/10-ipset', 'start']
    assert result['actions']['restart']['argv'] == start['argv'] == result['actions']['reload']['argv']
    assert result['actions']['save']['argv'][-1] == [f'{nf.DEFAULT_PLUGINS}/40-ipset', 'save']
    assert result['flush_on_stop'] is False
    assert result['actions']['stop'] == {'argument': None, 'runs_plugins': False, 'argv': []}


def test_absent_defaults_file_uses_default_directory_and_never_flushes():
    result = run(text=None, state='absent')
    assert result['complete'] is True
    assert result['defaults']['sourced_as_root'] is False
    assert result['plugins_directory'] == nf.DEFAULT_PLUGINS
    assert result['actions']['stop']['argv'] == []


def test_run_parts_name_filter_and_c_locale_order():
    entries = [{'name': n, 'type': 'file', 'mode': 0o755} for n in ('b', 'B', '_u', 'a.sh', '-x', '.hidden', 'x~', 'Zed')]
    result = run(entries=entries)
    assert [p['name'] for p in result['plugins']] == ['-x', 'B', 'Zed', '_u', 'b']
    ignored = {e['name'] for e in result['entries'] if e['status'] == 'ignored'}
    assert ignored == {'a.sh', '.hidden', 'x~'}


def test_entry_kinds_follow_symlinks_and_any_execute_bit():
    entries = [
        {'name': 'owner', 'type': 'file', 'mode': 0o700},
        {'name': 'other', 'type': 'file', 'mode': 0o601},
        {'name': 'plain', 'type': 'file', 'mode': 0o644},
        {'name': 'sub', 'type': 'directory', 'mode': 0o755},
        {'name': 'fifo', 'type': 'other', 'mode': 0o644},
        {'name': 'link', 'type': 'symlink', 'target_type': 'file', 'target_mode': 0o755},
        {'name': 'linknx', 'type': 'symlink', 'target_type': 'file', 'target_mode': 0o644},
        {'name': 'dangle', 'type': 'symlink', 'target_type': 'missing'},
        {'name': 'linkdir', 'type': 'symlink', 'target_type': 'directory'},
    ]
    result = run(entries=entries)
    assert result['complete'] is True
    status = {e['name']: e['status'] for e in result['entries']}
    assert [p['name'] for p in result['plugins']] == ['link', 'other', 'owner']
    assert status['plain'] == status['linknx'] == 'skipped_not_executable'
    assert status['sub'] == status['linkdir'] == 'skipped_directory'
    assert status['fifo'] == 'skipped_non_file' and status['dangle'] == 'skipped_dangling'


def test_defaults_file_redirects_plugins_and_enables_flush_on_stop():
    text = "PLUGINS='/opt/evil'  # moved\nFLUSH_ON_STOP=+1\n"
    directory = {'path': '/opt/evil', 'state': 'directory'}
    result = run(text=text, directory=directory, entries=[{'name': 'x', 'type': 'file', 'mode': 0o755}])
    assert result['complete'] is True
    assert result['plugins_directory'] == '/opt/evil'
    assert result['defaults']['assignments'] == {'PLUGINS': '/opt/evil', 'FLUSH_ON_STOP': '+1'}
    assert result['actions']['stop']['argv'] == [['/opt/evil/x', 'flush']]
    # The listing must be for the redirected directory.
    assert 'directory_mismatch' in codes(run(text=text))


def test_flush_on_stop_follows_dash_test_outcomes():
    assert [nf.flush_on_stop(v) for v in (None, '', '0', '1', '01', '-1', 'abc', '0x1', '9' * 20)] == [
        False, False, False, True, True, False, False, False, False]
    assert nf.flush_on_stop('1 2') is None and nf.flush_on_stop('*') is None
    result = run(text='FLUSH_ON_STOP="1 -o 1"\n')
    assert result['complete'] is False and 'flush_on_stop_unresolved' in codes(result)
    assert result['actions']['stop']['argv'] is None


def test_over_long_flush_on_stop_digits_fail_closed_without_raising():
    # More digits than Python's default integer-string conversion limit (4300), yet under MAX_TEXT.
    for value in ('1' * 5000, '-' + '9' * 5000, '+' + '1' * 5000):
        assert nf.flush_on_stop(value) is False
    # Leading zeros do not count towards the range check.
    assert nf.flush_on_stop('0' * 5000 + '1') is True
    assert nf.flush_on_stop('-' + '0' * 5000 + '1') is False
    assert nf.flush_on_stop(str(nf.INTMAX)) is True and nf.flush_on_stop(str(nf.INTMAX + 1)) is False
    result = run(text=f'FLUSH_ON_STOP={"1" * 5000}\n')
    assert result['complete'] is True and result['flush_on_stop'] is False
    assert result['actions']['stop']['argv'] == []


def test_plugins_path_limit_counts_encoded_bytes():
    under = '/' + 'é' * ((nf.MAX_PATH - 1) // 2)
    over = '/' + 'é' * (nf.MAX_PATH // 2)
    assert len(over) <= nf.MAX_PATH < len(over.encode('utf-8'))
    result = run(text=f"PLUGINS='{over}'\n", directory={'path': over, 'state': 'absent'}, entries=None)
    assert result['complete'] is False and 'plugins_over_limit' in codes(result)
    assert result['actions']['start']['argv'] is None
    ok = run(text=f"PLUGINS='{under}'\n", directory={'path': under, 'state': 'absent'}, entries=None)
    assert ok['complete'] is True and ok['actions']['start']['argv'] == []


def test_shell_code_or_path_and_ifs_assignments_are_blocking():
    for text, code in (('PLUGINS=$HOME/p\n', 'defaults_dynamic'), ('. /etc/other\n', 'defaults_dynamic'),
                       ('X=1 Y=2\n', 'defaults_dynamic'), ('PATH=/tmp:/usr/bin\n', 'path_assigned'),
                       ('IFS=:\n', 'ifs_assigned'), ('A=~\n', 'defaults_dynamic')):
        result = run(text=text)
        assert result['complete'] is False and code in codes(result), text
        assert result['plugins'] == [] and result['actions']['start']['argv'] is None


def test_plugins_values_that_split_glob_or_are_relative_are_unresolved():
    for value, code in (("'/a b'", 'plugins_unresolved'), ('"/p*"', 'plugins_unresolved'),
                        ('rel/dir', 'plugins_relative')):
        result = run(text=f'PLUGINS={value}\n')
        assert code in codes(result) and result['actions']['start']['argv'] is None
    empty = run(text="PLUGINS=''\n")
    assert empty['complete'] is True and empty['actions']['start']['argv'] == []


def test_missing_directory_runs_nothing_and_unobserved_input_is_blocking():
    absent = run(directory={'path': nf.DEFAULT_PLUGINS, 'state': 'absent'}, entries=None)
    assert absent['complete'] is True and absent['directory_exists'] is False
    assert absent['actions']['start']['argv'] == []
    assert 'defaults_not_observed' in codes(nf.evaluate())
    assert 'directory_not_observed' in codes(run(directory=None))
    assert 'mode_not_observed' in codes(run(entries=[{'name': 'x', 'type': 'file'}]))
    assert 'target_not_observed' in codes(run(entries=[{'name': 'x', 'type': 'symlink'}]))
    assert 'duplicate_entry' in codes(run(entries=SHIPPED_PLUGINS + SHIPPED_PLUGINS[:1]))


def test_malformed_defaults_text_is_blocking():
    assert 'invalid_utf8' in codes(run(text=b'PLUGINS=/a\xff\n'))
    assert 'binary' in codes(run(text='PLUGINS=/a\x00\n'))
    assert 'defaults_over_limit' in codes(run(text='#' * (nf.MAX_TEXT + 1)))
    assert 'defaults_unreadable' in codes(run(state='unreadable'))
    not_file = run(text=None, state='not_file')
    assert not_file['complete'] is True and not_file['defaults']['sourced_as_root'] is False
