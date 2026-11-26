"""Tests for the pure ISC dhcpd execute() contract (#1593).

Tests marked "native" reproduce runs of isc-dhcp-server 4.4.3-P1-4ubuntu2 on Ubuntu 24.04:
dhcpd started as the packaged unit starts it (``-user dhcpd -group dhcpd -f -4``) in one
network namespace, ``dhclient`` in another over a veth pair, traced with
``strace -f -e trace=execve``, and ``dhcpd -t -cf <file>`` for configuration tests. Each
hook appended ``basename uid=$(id -un) args=$*`` to a log; the expected runs are quoted.
"""
from __future__ import annotations

import ast
from pathlib import Path

from app import dhcpd_execute as dx

ARGV = ['dhcpd', '-user', 'dhcpd', '-group', 'dhcpd', '-f', '-4', '-cf', '/etc/dhcp/dhcpd.conf']


def run(text: str, argv: list[str] | None = ARGV, **extra):
    record = {'path': dx.DEFAULT_CONFIG, 'state': 'regular', 'text': text, **extra}
    return dx.assess_config([record], argv=argv)


def by_program(result):
    return {p['program']: p for p in result['programs']}


NATIVE_T1 = '''# native trace 1
execute("/usr/local/bin/g-scope", "global");
on commit { execute("/usr/local/bin/g-commit", binary-to-ascii(10, 8, ".", leased-address)); }
on expiry { execute("/usr/local/bin/g-expiry"); }
subnet 10.77.0.0 netmask 255.255.255.0 {
  range 10.77.0.50 10.77.0.60;
  on commit { execute("/usr/local/bin/first-commit"); }
  on commit {
    if option host-name = "nomatch" { execute("/usr/local/bin/cond-yes"); }
    else { execute("/usr/local/bin/s-commit", "sub", "two words"); }
  }
  on release { execute("pathsearch-release", "r"); }
}
'''


def test_native_global_scope_runs_as_root_at_startup_then_as_process_user():
    # native: g-scope uid=root args=global (x2 before privilege drop), then
    # g-scope uid=dhcpd args=global once per DHCPDISCOVER evaluation.
    result = run(NATIVE_T1)
    assert result['complete'] and not result['rejected_by_parser']
    g = by_program(result)['/usr/local/bin/g-scope']
    assert g['events'] == ['startup', 'config_test', 'scope_evaluation']
    assert g['run_as'] == ['root', 'dhcpd']
    assert g['runs_as_root_at_startup'] is True
    assert g['argv_literal'] == ['/usr/local/bin/g-scope', 'global']
    assert g['via_shell'] is False and g['synchronous'] is True


def test_native_last_on_commit_in_innermost_scope_wins():
    # native: only "s-commit uid=dhcpd args=sub two words" ran on DHCPACK; g-commit and
    # first-commit were replaced, and the false if-branch did not run.
    progs = by_program(run(NATIVE_T1))
    assert progs['/usr/local/bin/first-commit']['replaced_in_same_scope'] is True
    s_commit = progs['/usr/local/bin/s-commit']
    assert s_commit['replaced_in_same_scope'] is False
    assert s_commit['events'] == ['commit']
    assert s_commit['argv_literal'] == ['/usr/local/bin/s-commit', 'sub', 'two words']
    assert s_commit['conditions'] == ['not (option host-name = "nomatch")']
    assert progs['/usr/local/bin/cond-yes']['conditions'] == ['if option host-name = "nomatch"']
    g_commit = progs['/usr/local/bin/g-commit']
    assert g_commit['replaced_in_same_scope'] is False
    assert {tuple(m['scope']) for m in g_commit['may_be_replaced_by']} == {
        ('subnet 10.77.0.0 netmask 255.255.255.0',)}
    assert g_commit['argv_literal'] is None
    assert g_commit['arguments'] == [{
        'literal': False, 'value': None,
        'expression': 'binary-to-ascii(10, 8, ".", leased-address)'}]
    assert g_commit['run_as'] == ['dhcpd']


def test_native_release_uses_execvp_path_search_as_process_user():
    # native: execve walked $PATH for "pathsearch-release"; it ran as dhcpd on DHCPRELEASE.
    rel = by_program(run(NATIVE_T1))['pathsearch-release']
    assert rel['events'] == ['release'] and rel['path_search'] is True
    assert rel['run_as'] == ['dhcpd']


NATIVE_T2 = '''default-lease-time 4; max-lease-time 4; min-lease-time 4;
on commit or release { execute("/usr/local/bin/g-commit", "both"); }
on expiry { execute("/usr/local/bin/g-expiry", "exp"); }
class "allc" { match if substring(hardware, 0, 1) = 1; on commit { execute("/usr/local/bin/cond-yes", "class"); } }
subnet 10.77.0.0 netmask 255.255.255.0 {
  execute("/usr/local/bin/s-scope", "subnet");
  pool { range 10.77.0.50 10.77.0.60; allow members of "allc"; }
}
'''


def test_native_class_replaces_global_commit_but_not_release_and_subnet_scope_per_packet():
    # native: s-scope uid=dhcpd (DISCOVER and REQUEST, never at startup), cond-yes class on
    # commit instead of g-commit, g-expiry uid=dhcpd exp after the 4 s lease ended.
    result = run(NATIVE_T2)
    progs = by_program(result)
    s_scope = progs['/usr/local/bin/s-scope']
    assert s_scope['events'] == ['scope_evaluation']
    assert s_scope['run_as'] == ['dhcpd'] and s_scope['runs_as_root_at_startup'] is False
    g = progs['/usr/local/bin/g-commit']
    assert g['events'] == ['commit', 'release']
    assert g['may_be_replaced_by'] == [{'scope': ['class "allc"'], 'line': 4, 'events': ['commit'],
                                        'conditional': False}]
    assert progs['/usr/local/bin/g-expiry']['may_be_replaced_by'] == []
    assert progs['/usr/local/bin/cond-yes']['scope'] == ['class "allc"']


def test_native_config_test_runs_global_branches_and_expression_arguments():
    # native: `dhcpd -t` printed "cond-no uid=root args=else" and "second-commit uid=root args=ab".
    text = ('if exists host-name { execute("/usr/local/bin/cond-yes"); } '
            'else { execute("/usr/local/bin/cond-no", "else"); }\n'
            'execute("/usr/local/bin/second-commit", concat("a", "b"));\n')
    progs = by_program(run(text))
    assert progs['/usr/local/bin/cond-no']['conditions'] == ['not (exists host-name)']
    assert 'config_test' in progs['/usr/local/bin/cond-no']['events']
    second = progs['/usr/local/bin/second-commit']
    assert second['argv_literal'] is None
    assert second['arguments'][0]['expression'] == 'concat("a", "b")'


def test_native_else_if_and_case_insensitive_keyword():
    # native: rc=0, "second-commit uid=root args=else"; EXECUTE(...) ran "cond-no args=upper".
    text = ('if exists host-name { execute("/usr/local/bin/cond-yes"); } '
            'else if exists user-class { execute("/usr/local/bin/cond-no", "elseif"); } '
            'else { execute("/usr/local/bin/second-commit", "else"); }\n'
            'EXECUTE("/usr/local/bin/upper", "upper");\n')
    progs = by_program(run(text))
    assert progs['/usr/local/bin/cond-no']['conditions'] == [
        'not (exists host-name)', 'if exists user-class']
    assert progs['/usr/local/bin/second-commit']['conditions'] == [
        'not (exists host-name)', 'not (exists user-class)']
    assert '/usr/local/bin/upper' in progs


def test_native_escaped_nul_truncates_program():
    # native: execve("/usr/local/bin/cond-no", ["/usr/local/bin/cond-no", "nul"]).
    result = run('execute("/usr/local/bin/cond-no\\000tail", "nul");\n')
    prog = result['programs'][0]
    assert prog['program'] == '/usr/local/bin/cond-no' and prog['truncated_at_nul'] is True
    assert prog['argv_literal'] == ['/usr/local/bin/cond-no', 'nul']
    assert any(g['code'] == 'program_truncated_at_nul' for g in result['gaps'])


def test_native_rejected_configurations():
    # native: `dhcpd -t` exits 1 for each, and nothing runs.
    for text, reason in (
            ('execute(concat("/usr/local/bin/", "x"));', 'expecting_quoted_string'),
            ('on renew { execute("/usr/local/bin/cond-no"); }', 'expecting_lease_event_type'),
            ('execute "/usr/local/bin/cond-no";', 'left_parenthesis_expected'),
            ('subnet 10.9.0.0 netmask 255.255.0.0 { on commit { subnet 10.8.0.0 netmask '
             '255.255.0.0 { } } }', 'declaration_in_executable_block')):
        result = run(text)
        assert result['rejected_by_parser'], text
        assert reason in [e['reason'] for e in result['config_errors']], text
        assert all(p.get('runs_only_if_config_accepted') for p in result['programs'])


def test_comments_strings_and_escapes():
    text = ('# execute("/bin/commented");\n'
            'execute("/usr/bin/logger", "a#b", "tab\\there", "q\\"uote", "\\x41\\101");\n')
    prog = run(text)['programs'][0]
    assert prog['argv_literal'] == ['/usr/bin/logger', 'a#b', 'tab\there', 'q"uote', 'AA']
    assert prog['line'] == 2


def test_host_scope_outranks_class_and_subnet():
    text = ('subnet 10.0.0.0 netmask 255.0.0.0 { on commit { execute("/s"); } }\n'
            'class "c" { on commit { execute("/c"); } }\n'
            'host h { hardware ethernet 00:11:22:33:44:55; on commit { execute("/h"); } }\n')
    progs = by_program(run(text))
    assert [m['scope'] for m in progs['/s']['may_be_replaced_by']] == [['class "c"'], ['host h']]
    assert [m['scope'] for m in progs['/c']['may_be_replaced_by']] == [['host h']]
    assert progs['/h']['may_be_replaced_by'] == []


def test_conditional_later_on_may_replace_only():
    text = ('on commit { execute("/a"); }\n'
            'if exists host-name { on commit { execute("/b"); } }\n')
    progs = by_program(run(text))
    assert progs['/a']['replaced_in_same_scope'] is False
    assert progs['/a']['may_be_replaced_by'][0]['conditional'] is True


def test_partial_replacement_of_multi_event_on():
    progs = by_program(run('on commit or release { execute("/a"); }\non commit { execute("/b"); }\n'))
    assert progs['/a']['replaced_events'] == ['commit']
    assert progs['/a']['replaced_in_same_scope'] is False


def test_process_user_from_command_line():
    assert run('execute("/a");', argv=['dhcpd', '-f'])['programs'][0]['run_as'] == ['root']
    unobserved = run('execute("/a");', argv=None)
    assert unobserved['process_user']['source'] == 'packaged_unit_default'
    assert any(g['code'] == 'process_user_unobserved' and not g['blocking']
               for g in unobserved['gaps'])
    assert unobserved['complete'] is True


def test_include_and_nested_on_are_blocking_gaps():
    result = run('include "/etc/dhcp/extra.conf";\nexecute("/a");\n')
    assert not result['complete']
    assert [g['code'] for g in result['gaps']] == ['include']
    nested = run('on commit { on release { execute("/a"); } }\n')
    assert not nested['complete']
    assert 'nested_on_statement' in [g['code'] for g in nested['gaps']]


def test_execute_in_data_block_and_unbalanced_braces():
    assert 'execute_in_data_block' in [g['code'] for g in
                                       run('key k { execute("/a"); }')['gaps']]
    bad = run('subnet 10.0.0.0 netmask 255.0.0.0 { execute("/a");\n')
    assert not bad['complete'] and bad['rejected_by_parser']
    extra = run('execute("/a"); }\n')
    assert not extra['complete']


def test_file_states_and_limits():
    assert dx.assess_config([], argv=ARGV)['gaps'][0]['code'] == 'file_not_observed'
    missing = dx.assess_config([{'path': dx.DEFAULT_CONFIG, 'state': 'missing'}], argv=ARGV)
    assert missing['rejected_by_parser'] and missing['programs'] == []
    unknown = dx.assess_config([{'path': dx.DEFAULT_CONFIG, 'state': 'unknown'}], argv=ARGV)
    assert not unknown['complete']
    weird = dx.assess_config([{'path': dx.DEFAULT_CONFIG, 'state': 'socket'}], argv=ARGV)
    assert weird['gaps'][0]['code'] == 'file_state_not_modelled'
    assert run('x' * (dx.MAX_TEXT + 1))['gaps'][0]['code'] == 'over_limit'
    assert run('execute("/a");\x00')['gaps'][0]['code'] == 'binary'
    assert run('"' + 'a' * dx.TOKBUF + '";')['gaps'][0]['code'] == 'token_over_buffer'
    assert run('execute("/a);')['complete'] is False
    for result in (missing, unknown, weird):
        assert result['origin'] == 'not_assessed'


def test_gap_limit_is_bounded():
    text = '\n'.join('include "/f%d";' % i for i in range(dx.MAX_GAPS + 10))
    gaps = run(text)['gaps']
    assert len(gaps) == dx.MAX_GAPS + 1 and gaps[-1]['code'] == 'gaps_truncated'


def test_module_is_pure():
    tree = ast.parse(Path(dx.__file__).read_text())
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split('.')[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add((node.module or '').split('.')[0])
    assert imported <= {'__future__', 'typing'}
    for name in ('open', 'exec', 'eval', 'subprocess', 'os'):
        assert not any(isinstance(n, ast.Name) and n.id == name for n in ast.walk(tree))
