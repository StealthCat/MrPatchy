"""Agent-reported rsnapshot.conf lines evaluate exactly like the full file (#1530 increment 3).

Agents cannot import the controller. They split /etc/rsnapshot.conf into rsnapshot's logical lines with
their own copy of the parse_config_file() rules and keep values only for the directives the contract
reads. The controller validates the report, rebuilds text and runs app/rsnapshot_commands. These tests
compare that path with the contract run on the full original text, over hand-written native cases and a
seeded random grammar, and check that the validator rejects reports an agent never produces.
"""
import copy
import random

import pytest

from app import persistence, rsnapshot_commands as rc, startup_inventory as si
from target import agent

CONF = persistence.RSNAPSHOT_CONF
BASE = (
    'config_version\t1.2\n'
    'snapshot_root\t/srv/snap/\n'
    'cmd_rsync\t/usr/bin/rsync\n'
    'retain\talpha\t2\n'
    'backup\t/srv/src/\tlocal/\n'
)
# Ubuntu 24.04 rsnapshot 1.4.5-2 /etc/rsnapshot.conf, abridged (comments and defaults as shipped).
PACKAGED = (
    '#################################################\n'
    '# rsnapshot.conf - rsnapshot configuration file #\n'
    '#################################################\n'
    '\n'
    'config_version\t1.2\n'
    'snapshot_root\t/var/cache/rsnapshot/\n'
    '#no_create_root\t1\n'
    'cmd_cp\t\t/bin/cp\n'
    'cmd_rm\t\t/bin/rm\n'
    'cmd_rsync\t/usr/bin/rsync\n'
    '#cmd_ssh\t/path/to/ssh\n'
    'cmd_logger\t/usr/bin/logger\n'
    '#cmd_du\t\t/usr/bin/du\n'
    '#cmd_preexec\t/path/to/preexec/script\n'
    '#linux_lvm_cmd_lvcreate\t/sbin/lvcreate\n'
    'retain\talpha\t6\n'
    'retain\tbeta\t7\n'
    'verbose\t\t2\n'
    'loglevel\t3\n'
    'lockfile\t/var/run/rsnapshot.pid\n'
    '#rsync_long_args\t--delete --numeric-ids --relative --delete-excluded\n'
    'backup\t/home/\t\tlocalhost/\n'
    'backup\t/etc/\t\tlocalhost/\n'
    'backup\t/usr/local/\tlocalhost/\n'
    '#backup_script\t/usr/local/bin/backup_pgsql.sh\tlocalhost/postgres/\n'
)


def _report(text):
    report = agent.parse_rsnapshot_conf(text.encode('utf-8') if isinstance(text, str) else text)
    persistence.validate_rsnapshot(report, CONF)
    return report


def _entry(text):
    return {'path': CONF, 'kind': 'regular', 'uid': 0, 'gid': 0, 'mode': 0o644, 'size': len(text),
            'mtime_ns': 0, 'sha256': '0' * 64, 'rsnapshot': _report(text)}


def _view(text):
    return si.rsnapshot_view(_entry(text))


def _full(text):
    return rc.assess_config([{'path': CONF, 'state': 'regular', 'text': text}])


def _bounded(items):
    return [{k: (v[:300] if isinstance(v, str) else v) for k, v in i.items()} for i in items]


def _comparable(result, kept_warnings_only=False):
    commands = [{k: v for k, v in c.items()} for c in result['commands']]
    for c in commands:
        c.setdefault('dropped_fields', [])
    programs = [{k: v for k, v in p.items() if k != 'argv_prefix'} for p in result['programs']]
    gaps = [{k: v for k, v in g.items() if k != 'blocking'} for g in result['gaps']]
    return {'commands': _bounded(commands), 'programs': _bounded(programs),
            'config_errors': _bounded(result['config_errors']), 'gaps': _bounded(gaps),
            'rejected_by_parser': result['rejected_by_parser'],
            'backup_commands_run': result['backup_commands_run'],
            'ssh': result.get('ssh_backup_points'), 'lvm': result.get('lvm_backup_points')}


def _same(text):
    view = _view(text)
    assert _comparable(view) == _comparable(_full(text))
    return view


def test_packaged_configuration_matches_the_full_file_and_drops_other_values():
    view = _same(PACKAGED)
    assert view['commands'] == [] and view['complete'] is True and view['rejected_by_parser'] is False
    assert {p['key']: p['path'] for p in view['programs'] if p['configured']} == {
        'cmd_cp': '/bin/cp', 'cmd_rm': '/bin/rm', 'cmd_rsync': '/usr/bin/rsync', 'cmd_logger': '/usr/bin/logger'}
    report = _report(PACKAGED)
    kept = {s['directive']: s['values'] for s in report['statements']}
    assert kept['lockfile'] is None and kept['retain'] is None and kept['verbose'] is None
    assert kept['backup'] == ['/usr/local/', 'localhost/']
    assert view['authorizes_response'] is False and view['origin'] == 'not_assessed'


def test_native_hooks_continuations_and_final_zero_are_reproduced():
    text = (BASE + 'cmd_preexec\t/usr/local/sbin/hook pre one\tdropped-field\n'
            '# comment\n\n'
            'cmd_postexec\t/usr/local/sbin/hook post; echo $HOME >> /tmp/log\n'
            '  # hash-led continuation\n'
            'backup_script\t/usr/local/sbin/hook script\tscr/\n'
            'backup_exec\t/bin/false\trequired\n'
            '\n'
            ' leading-space-statement\tvalue\n'
            '0')
    view = _same(text)
    assert [(c['kind'], c['line']) for c in view['commands']] == [
        ('cmd_preexec', 6), ('cmd_postexec', 9), ('backup_script', 11), ('backup_exec', 12)]
    post = view['commands'][1]
    assert post['dropped_fields'] == ['# hash-led continuation'] and post['via_shell'] is True
    assert view['config_errors'][0]['reason'] == 'unknown_directive'


def test_rejections_include_commands_and_spaces_instead_of_tabs_match():
    text = (BASE + 'include_conf\t`/usr/local/bin/gen-conf --site a`\n'
            'include_conf\t/etc/rsnapshot.d/extra.conf\n'
            'cmd_preexec /usr/local/bin/spaces\n'
            'backup\tuser@host:/srv/\tremote/\n'
            'linux_lvm_cmd_lvcreate\t/sbin/lvcreate --yes\n'
            'zero_line\n0\n')
    view = _same(text)
    assert view['rejected_by_parser'] is True and view['backup_commands_run'] is False
    assert view['commands'][0]['kind'] == 'include_conf_command'
    assert {e['reason'] for e in view['config_errors']} >= {'spaces_instead_of_tabs', 'ssh_backup_without_cmd_ssh',
                                                           'missing_value'}
    assert {g['reason'] for g in view['gaps']} == {'include_conf_command_output_not_modelled', 'file_not_observed'}
    assert all(g['blocking'] for g in view['gaps']) and view['complete'] is False


def test_credentials_in_commands_are_redacted_and_flagged_inexact():
    text = BASE + 'cmd_postexec\t/usr/bin/curl -u admin:hunter2 https://example.invalid/done\n'
    report = _report(text)
    assert 'hunter2' not in repr(report) and report['inexact'] == [6]
    view = si.rsnapshot_view({**_entry(BASE), 'rsnapshot': report})
    assert 'hunter2' not in repr(view)
    assert {'reason': 'agent_value_inexact', 'line': 6, 'blocking': True} in view['gaps'] and view['complete'] is False


def test_long_values_are_cut_and_flagged():
    text = BASE + 'cmd_preexec\t/usr/local/bin/' + 'x' * 600 + '\n'
    report = _report(text)
    assert len(report['statements'][-1]['values'][0]) == agent.CRON_COMMAND_LIMIT and report['inexact'] == [6]


def test_undecodable_files_and_older_agents_are_explained():
    for data, reason in ((b'cmd_rsync\t/usr/bin/rsync\n\x00', 'nul_byte'), (b'cmd_rsync\t/usr/bin/\xff\n', 'invalid_utf8')):
        report = agent.parse_rsnapshot_conf(data)
        assert report == {'parsed': False, 'error': reason, 'statements': [], 'inexact': [], 'truncated': False}
        persistence.validate_rsnapshot(report, CONF)
        assert si.rsnapshot_state({'path': CONF, 'kind': 'regular', 'rsnapshot': report}) == 'undecodable'
    assert si.rsnapshot_state({'path': CONF, 'kind': 'regular'}) == 'not_reported'
    assert si.rsnapshot_state({'path': CONF, 'kind': 'symlink'}) == 'not_followed'
    assert si.rsnapshot_state({'path': '/etc/other.conf', 'kind': 'regular'}) is None


def test_statement_limit_is_a_blocking_gap():
    text = BASE + 'retain\tbeta\t1\n' * (agent.RSNAPSHOT_STATEMENTS + 5)
    report = _report(text)
    assert report['truncated'] is True and len(report['statements']) == agent.RSNAPSHOT_STATEMENTS
    view = si.rsnapshot_view({**_entry(BASE), 'rsnapshot': report})
    assert {'reason': 'statement_limit_reached', 'limit': persistence.RSNAPSHOT_STATEMENTS, 'blocking': True} in view['gaps']


def test_agent_and_controller_limits_agree():
    assert agent.RSNAPSHOT_CONF == persistence.RSNAPSHOT_CONF
    assert agent.RSNAPSHOT_KEPT == persistence.RSNAPSHOT_KEPT
    assert agent.RSNAPSHOT_STATEMENTS == persistence.RSNAPSHOT_STATEMENTS
    assert agent.RSNAPSHOT_NAME_LIMIT == persistence.RSNAPSHOT_NAME_LIMIT
    assert set(persistence.RSNAPSHOT_KEPT) - {'snapshot_root', 'backup', 'include_conf', 'cmd_preexec', 'cmd_postexec',
                                             'backup_script', 'backup_exec'} == set(rc.PROGRAM_KEYS) | set(rc.LVM_KEYS)


@pytest.mark.parametrize('mutate', [
    lambda r: r.update(extra=1),
    lambda r: r.update(parsed='yes'),
    lambda r: r.update(error='nul_byte'),
    lambda r: r['statements'][0].update(values=['secret']),
    lambda r: r['statements'][1].update(values=None),
    lambda r: r['statements'][1].update(line=1),
    lambda r: r['statements'][1].update(end=0),
    lambda r: r['statements'][1].update(values=['a\tb']),
    lambda r: r['statements'][1].update(values=['', 'b']),
    lambda r: r['statements'][1].update(values=['a', 'b', 'c', 'd']),
    lambda r: r['statements'][4].update(values=['a', 'b', 'c']),
    lambda r: r['statements'][1].update(values=['a\nb']),
    lambda r: r['statements'][0].update(directive='#comment'),
    lambda r: r['statements'][0].update(directive='x' * 121),
    lambda r: r['statements'][1].update(directive=' continuation'),
    lambda r: r.update(inexact=[99]),
    lambda r: r.update(inexact=[1, 1]),
    lambda r: r.update(statements=r['statements'] * 300),
])
def test_validator_rejects_reports_agents_never_produce(mutate):
    report = _report(BASE)
    persistence.validate_rsnapshot(copy.deepcopy(report), CONF)
    bad = copy.deepcopy(report)
    mutate(bad)
    with pytest.raises(ValueError):
        persistence.validate_rsnapshot(bad, CONF)


def test_validator_rejects_other_paths_and_errors_with_statements():
    with pytest.raises(ValueError):
        persistence.validate_rsnapshot(_report(BASE), '/etc/rsnapshot.d/x.conf')
    with pytest.raises(ValueError):
        persistence.validate_rsnapshot({'parsed': False, 'error': 'other', 'statements': [], 'inexact': [], 'truncated': False}, CONF)


def test_whole_inventory_validation_accepts_the_report_and_metadata_drops_it():
    entry = _entry(PACKAGED)
    inventory = {'scope': [CONF], 'entries': [entry], 'entries_examined': 1, 'skipped': 0, 'gaps': [],
                 'missing_roots': [], 'state': 'collected'}
    persistence.validate(inventory)
    assert 'rsnapshot' not in persistence.metadata(entry)
    with pytest.raises(ValueError):
        persistence.validate({**inventory, 'entries': [{**entry, 'kind': 'symlink', 'target': '/x'}]})


_PIECES = {
    'kept': ['cmd_preexec', 'cmd_postexec', 'backup_script', 'backup_exec', 'include_conf', 'cmd_ssh', 'cmd_cp',
             'cmd_rsync', 'linux_lvm_cmd_mount', 'snapshot_root', 'backup'],
    'other': ['retain', 'interval', 'verbose', 'lockfile', 'rsync_long_args', 'exclude', 'sync_first'],
    'unknown': ['bogus', 'cmd_preexecx', 'Backup'],
    'values': ['/usr/local/bin/hook', '/usr/local/bin/hook a b', '/bin/sh -c "x; y"', 'relative/hook', '/srv/snap/',
               'local/', 'root@host:/srv/', 'lvm://vg/lv/', '`/usr/bin/gen`', '`gen`', 'required', 'optional',
               '/etc/extra.conf', ' /leading/space', 'exec /bin/x', 'A=1 /bin/x', ''],
}


def _random_config(rng):
    lines = []
    for _ in range(rng.randint(0, 14)):
        roll = rng.random()
        if roll < 0.1:
            lines.append('# ' + rng.choice(_PIECES['values']))
        elif roll < 0.15:
            lines.append(rng.choice(['', '   ', '\t']))
        elif roll < 0.25:
            lines.append(rng.choice([' ', '\t', '  \t']) + rng.choice(_PIECES['values'] + ['#x']) + 'z')
        else:
            group = rng.choice(['kept', 'kept', 'other', 'unknown'])
            fields = [rng.choice(_PIECES[group])] + [rng.choice(_PIECES['values']) for _ in range(rng.randint(0, 4))]
            sep = rng.choice(['\t', '\t\t', '\t', ' '])
            lines.append(sep.join(fields))
    text = '\n'.join(lines)
    if rng.random() < 0.7:
        text += '\n'
    if rng.random() < 0.1:
        text += '0'
    return text


def test_random_configurations_evaluate_like_the_full_file():
    rng = random.Random(1530)
    for _ in range(1500):
        text = rng.choice(['', BASE]) + _random_config(rng)
        report = _report(text)
        if report['inexact']:
            continue
        assert _comparable(si.rsnapshot_view(_entry(text))) == _comparable(_full(text)), text
