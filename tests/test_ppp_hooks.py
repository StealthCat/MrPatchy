"""Tests for the pure pppd hook contract (#1091)."""
from __future__ import annotations

import ast
from pathlib import Path

from app import ppp_hooks

ALL_DIRS = [{'path': path, 'state': 'listed'} for path in ppp_hooks.OBSERVED_DIRS]
VERIFIED = {path: 'unchanged' for path in ppp_hooks.SHIPPED_WRAPPERS}
WRAPPER_FILES = [{'path': path, 'type': 'file', 'mode': 0o755} for path in sorted(ppp_hooks.SHIPPED_WRAPPERS)]


def run(files=(), **kwargs):
    kwargs.setdefault('options_text', 'lock\n')
    kwargs.setdefault('directories', ALL_DIRS)
    kwargs.setdefault('wrappers', VERIFIED)
    kwargs.setdefault('version', '2.5.2-1+2build1')
    kwargs.setdefault('family', 'debian')
    return ppp_hooks.evaluate(list(WRAPPER_FILES) + list(files), **kwargs)


def codes(result):
    return [gap['code'] for gap in result['gaps']]


def script(result, event, path=None):
    scripts = result['events'][event]['scripts']
    if path is None:
        assert len(scripts) == 1
        return scripts[0]
    return next(item for item in scripts if item['path'] == path)


def test_default_wrappers_expand_run_parts_in_byte_order_as_root():
    result = run([
        {'path': '/etc/ppp/ip-up.d/0000usepeerdns', 'type': 'file', 'mode': 0o755},
        {'path': '/etc/ppp/ip-up.d/Zeta', 'type': 'file', 'mode': 0o755},
        {'path': '/etc/ppp/ip-up.d/alpha', 'type': 'file', 'mode': 0o010},  # group execute bit only
        {'path': '/etc/ppp/ip-up.d/hook.sh', 'type': 'file', 'mode': 0o755},
        {'path': '/etc/ppp/ip-up.d/noexec', 'type': 'file', 'mode': 0o644},
    ])
    assert result['complete'] is True, result['gaps']
    record = script(result, 'ip-up')
    assert record['status'] == 'runs_as_root' and record['configurations'] == ['options']
    expansion = record['expansion']
    assert expansion['mode'] == 'run_parts'
    by_path = {entry['path']: entry for entry in expansion['entries']}
    ordered = sorted((e for e in expansion['entries'] if 'order' in e), key=lambda e: e['order'])
    assert [e['path'].rsplit('/', 1)[1] for e in ordered] == ['0000usepeerdns', 'Zeta', 'alpha']
    assert by_path['/etc/ppp/ip-up.d/hook.sh']['reason_code'] == 'name_filtered'
    assert by_path['/etc/ppp/ip-up.d/noexec']['reason_code'] == 'not_executable'
    assert result['origin'] == 'not_assessed' and 'not a safety verdict' in result['note']


def test_missing_scripts_are_skipped_silently_and_auth_net_are_not_package_files():
    result = run([{'path': '/etc/ppp/auth-up', 'type': 'file', 'mode': 0o700}])
    assert result['complete'] is True
    auth_up = script(result, 'auth-up')
    assert auth_up['status'] == 'runs_as_root' and auth_up['not_shipped_by_package'] is True
    assert result['events']['auth-up']['override_option'] is None
    assert script(result, 'net-init')['reason_code'] == 'missing'
    assert 'not_shipped_by_package' not in script(result, 'net-init')
    assert result['events']['ip-up']['package_wrapper'] is True


def test_symlink_to_non_regular_and_dangling_script_do_not_run():
    result = run([
        {'path': '/etc/ppp/net-init', 'type': 'symlink', 'target': {'type': 'directory', 'mode': 0o755}},
        {'path': '/etc/ppp/net-down', 'type': 'symlink', 'target': None, 'link_target': '/nowhere'},
        {'path': '/etc/ppp/auth-down', 'type': 'symlink', 'target': {'type': 'file', 'mode': 0o755}},
    ])
    assert script(result, 'net-init')['reason_code'] == 'not_regular'
    assert script(result, 'net-down')['reason_code'] == 'unresolvable_symlink'
    assert script(result, 'net-down')['link_target'] == '/nowhere'
    assert script(result, 'auth-down')['status'] == 'runs_as_root'


def test_executable_local_replaces_run_parts():
    result = run([
        {'path': '/etc/ppp/ip-down.local', 'type': 'file', 'mode': 0o700},
        {'path': '/etc/ppp/ip-down.d/0000usepeerdns', 'type': 'file', 'mode': 0o755},
    ])
    expansion = script(result, 'ip-down')['expansion']
    assert expansion['mode'] == 'replaces'
    assert expansion['local_record']['status'] == 'runs_as_root'
    assert [e['reason_code'] for e in expansion['entries']] == ['skipped_by_local']
    assert result['complete'] is True


def test_dangling_or_non_executable_local_falls_through_to_run_parts():
    result = run([
        {'path': '/etc/ppp/ip-up.local', 'type': 'symlink', 'target': None},
        {'path': '/etc/ppp/ipv6-up.local', 'type': 'file', 'mode': 0o644},
        {'path': '/etc/ppp/ip-up.d/a', 'type': 'file', 'mode': 0o755},
        {'path': '/etc/ppp/ipv6-up.d/b', 'type': 'file', 'mode': 0o755},
    ])
    ip_up = script(result, 'ip-up')['expansion']
    ipv6_up = script(result, 'ipv6-up')['expansion']
    assert ip_up['mode'] == 'run_parts' and ip_up['local_record']['reason_code'] == 'unresolvable_symlink'
    assert ipv6_up['mode'] == 'run_parts' and ipv6_up['local_record']['reason_code'] == 'not_executable'
    assert ip_up['entries'][0]['status'] == 'runs_as_root' and ipv6_up['entries'][0]['order'] == 0


def test_local_directory_passes_test_x_but_exec_fails_so_nothing_runs():
    result = run([
        {'path': '/etc/ppp/ip-pre-up.local', 'type': 'directory', 'mode': 0o755},
        {'path': '/etc/ppp/ip-pre-up.d/a', 'type': 'file', 'mode': 0o755},
    ])
    expansion = script(result, 'ip-pre-up')['expansion']
    assert expansion['mode'] == 'fails'
    assert expansion['entries'][0]['reason_code'] == 'skipped_by_local'


def test_overrides_last_wins_and_peer_after_options():
    result = run(
        [{'path': '/usr/local/sbin/up', 'type': 'file', 'mode': 0o755},
         {'path': '/opt/peer-up', 'type': 'file', 'mode': 0o750}],
        options_text='# comment ip-up-script /ignored\nip-up-script /etc/ppp/first\nip-up-script /usr/local/sbin/up\n',
        peers={'isp': 'user me\nip-up-script /opt/peer-up # trailing\n', 'other': 'noauth\n'},
    )
    assert result['complete'] is True, result['gaps']
    options_record = script(result, 'ip-up', '/usr/local/sbin/up')
    assert options_record['configurations'] == ['options', 'peer:other']
    assert options_record['overridden'] is True and options_record['outside_conf_dir'] is True
    assert 'expansion' not in options_record
    peer_record = script(result, 'ip-up', '/opt/peer-up')
    assert peer_record['configurations'] == ['peer:isp'] and peer_record['status'] == 'runs_as_root'
    # The default wrapper is not selected, so its run-parts entries are reported as not run.
    assert all(path != '/etc/ppp/ip-up' for path in (s['path'] for s in result['events']['ip-up']['scripts']))


def test_comment_ends_the_line_and_long_words_are_gaps():
    result = run([{'path': '/usr/local/sbin/up', 'type': 'file', 'mode': 0o755}],
                 options_text='ip-up-script /usr/local/sbin/up # ip-up-script /etc/ppp/other\n')
    assert script(result, 'ip-up')['path'] == '/usr/local/sbin/up' and result['complete'] is True
    assert 'option_syntax_unsupported' in codes(run(options_text='ip-up-script /a#b\n'))
    assert 'option_syntax_unsupported' in codes(run(options_text='ip-up-script /' + 'a' * 1100 + '\n'))


def test_override_outside_etc_ppp_without_metadata_is_a_blocking_gap():
    result = run(options_text='ipv6-down-script /srv/x\n')
    assert script(result, 'ipv6-down')['status'] == 'unresolved'
    assert 'metadata_missing' in codes(result) and result['complete'] is False


def test_relative_override_is_a_gap():
    result = run(options_text='net-pre-up-script relative/up\n')
    assert script(result, 'net-pre-up')['status'] == 'unresolved'
    assert 'override_path_relative' in codes(result) and result['complete'] is False


def test_cross_event_override_to_another_wrapper_expands_that_wrapper():
    result = run([{'path': '/etc/ppp/ip-up.d/a', 'type': 'file', 'mode': 0o755}],
                 options_text='ip-down-script /etc/ppp/ip-up\n')
    record = script(result, 'ip-down')
    assert record['path'] == '/etc/ppp/ip-up' and record['expansion']['directory'] == '/etc/ppp/ip-up.d'


def test_unverified_wrapper_reports_only_the_wrapper_and_blocks():
    result = run([{'path': '/etc/ppp/ip-up.d/a', 'type': 'file', 'mode': 0o755},
                  {'path': '/etc/ppp/ip-up.local', 'type': 'file', 'mode': 0o755}],
                 wrappers={**VERIFIED, '/etc/ppp/ip-up': 'modified'})
    record = script(result, 'ip-up')
    assert record['status'] == 'runs_as_root'
    assert record['expansion'] == {'mode': 'not_verified', 'wrapper_state': 'modified'}
    assert 'wrapper_not_verified' in codes(result) and result['complete'] is False
    others = {item['path']: item['reason_code'] for item in result['other_files']}
    assert others == {'/etc/ppp/ip-up.d/a': 'wrapper_not_verified', '/etc/ppp/ip-up.local': 'wrapper_not_verified'}
    no_state = run(wrappers=None)
    assert script(no_state, 'ip-up')['expansion']['wrapper_state'] == 'unverified'


def test_options_syntax_and_includes_make_configuration_unknown():
    for text, code in (('ip-up-script "/etc/ppp/x y"\n', 'option_syntax_unsupported'),
                       ('call other\n', 'include_not_followed'),
                       ('file /etc/ppp/extra\n', 'include_not_followed'),
                       ('ip-up-script=/x\n', 'option_syntax_unsupported'),
                       ('lock\nip-up-script\n', 'option_missing_argument')):
        result = run(options_text=text)
        assert code in codes(result), text
        assert result['complete'] is False
        assert result['events']['ip-up']['unknown_configurations'] == ['options']
        assert result['events']['ip-up']['scripts'] == []


def test_unobserved_options_peer_dirs_and_environment_are_blocking():
    result = ppp_hooks.evaluate([], peers={'a': 'x\n'})
    assert {'options_not_observed', 'directory_not_observed', 'version_not_observed',
            'family_not_observed'} <= set(codes(result))
    assert result['events']['ip-up']['unknown_configurations'] == ['options', 'peer:a']
    for version, family, code in (('2.4.9-1', 'debian', 'version_unsupported'),
                                  ('2.5.2', 'rpm', 'family_unsupported')):
        assert code in codes(run(version=version, family=family))


def test_absent_options_file_and_absent_conf_dir():
    result = run(options_text=False)
    assert result['complete'] is True
    absent = ppp_hooks.evaluate([], directories=[{'path': '/etc/ppp', 'state': 'absent'}], version='2.5.2',
                                family='debian')
    assert absent['complete'] is True, absent['gaps']
    assert all(item['reason_code'] == 'missing' for event in absent['events'].values() for item in event['scripts'])


def test_malformed_and_over_limit_input():
    result = run([{'path': 'relative', 'type': 'file'}, {'path': '/etc/ppp/ip-up', 'type': 'file', 'mode': 0o755},
                  {'path': '/etc/ppp/net-init', 'type': 'file'}])
    assert {'input_malformed', 'duplicate_path', 'metadata_missing'} <= set(codes(result))
    big = run([{'path': f'/etc/ppp/ip-up.d/f{i}', 'type': 'file', 'mode': 0o755} for i in range(1100)])
    assert 'too_many_files' in codes(big)
    assert 'text_too_large' in codes(run(options_text='x' * (ppp_hooks.MAX_TEXT + 1)))
    many = run(peers={f'p{i}': '' for i in range(ppp_hooks.MAX_PEERS + 1)})
    assert 'too_many_peers' in codes(many)
    assert 'input_malformed' in codes(run(peers={'../x': ''}))
    assert 'directory_unreadable' in codes(run(directories=[
        {'path': p, 'state': 'unreadable' if p == '/etc/ppp/peers' else 'listed'} for p in ppp_hooks.OBSERVED_DIRS]))


def test_gap_list_is_bounded():
    result = run([{'path': f'/srv/{i}', 'type': 'symlink'} for i in range(10)],
                 peers={f'p{i}': f'ip-up-script /srv/{i}\n' for i in range(100)})
    assert len(result['gaps']) == ppp_hooks.MAX_GAPS and result['gaps'][-1]['code'] == 'gaps_truncated'


def test_nested_and_unrelated_entries_are_reported_not_run():
    result = run([{'path': '/etc/ppp/ip-up.d/sub/x', 'type': 'file', 'mode': 0o755},
                  {'path': '/etc/ppp/chap-secrets', 'type': 'file', 'mode': 0o600}])
    others = {item['path']: item['reason_code'] for item in result['other_files']}
    assert others == {'/etc/ppp/ip-up.d/sub/x': 'nested_entry', '/etc/ppp/chap-secrets': 'not_a_hook_location'}


def test_module_is_pure():
    tree = ast.parse(Path(ppp_hooks.__file__).read_text())
    imported = {alias.name.split('.')[0] for node in ast.walk(tree) if isinstance(node, ast.Import)
                for alias in node.names}
    imported |= {node.module.split('.')[0] for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
    assert imported <= {'__future__', 'posixpath', 're', 'typing', 'app'}
