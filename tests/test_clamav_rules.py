"""Agents parse ClamAV configuration into Startup Files (#1607 increment 3).

The agent cannot import the controller, so it carries its own copy of the ClamAV 1.5.4 option
parser. These tests hold it to ``app/clamav_event_commands.parse()`` on shared fixtures and random
input, check that only the values the contract reads are kept, that nothing in the files runs,
and cover controller validation and the startup view.
"""
import copy
import random
import time

import pytest

from app import clamav_event_commands, persistence
from app.db import Host, Session
from app.incidents import Inspection
from target import agent

CLAMD = '/etc/clamav/clamd.conf'
FRESHCLAM = '/etc/clamav/freshclam.conf'

FIXTURES = [
    ('clamd', ''),
    ('clamd', 'Foreground yes # c\nUser a\n'),
    ('clamd', 'Foreground yes\t# c\nUser a\n'),
    ('clamd', 'VirusEvent "echo a#b"\n'),
    ('clamd', 'VirusEvent echo "a b"\n'),
    ('clamd', 'VirusEvent "echo a\n'),
    ('clamd', 'VirusEvent ""\n'),
    ('clamd', 'Example\nUser a\n'),
    ('clamd', 'User a\nUser b\n'),
    ('clamd', 'user a\n'),
    ('clamd', 'User\n'),
    ('clamd', 'VirusEvent #\n'),
    ('clamd', 'VirusEvent #  #\n'),
    ('clamd', 'MaxThreads 5 # c\nVirusEvent x\n'),
    ('clamd', 'MaxThreads five\nVirusEvent x\n'),
    ('clamd', 'ScanOnAccess yes\nVirusEvent /usr/local/bin/alert %v %f\n'),
    ('clamd', 'VirusEvent ' + 'a' * 1030 + '\n'),
    ('clamd', '  \tVirusEvent x\n#VirusEvent y\nab\n'),
    ('clamd', 'VirusEvent x\r\n'),
    ('freshclam', 'user bob\nDatabaseOwner carol\nOnUpdateExecute ##x\n'),
    ('freshclam', 'OnUpdateExecute EXIT_3\nOnErrorExecute /bin/err\non-error-execute /bin/alias\n'),
    ('freshclam', 'OnOutdatedExecute /bin/old %v %v\nOnUpdateExecute /bin/new\ndaemon yes\n'),
    ('freshclam', 'HTTPProxyPassword hunter2\nOnUpdateExecute /bin/ok\n'),
    ('freshclam', 'VirusEvent x\n'),
]


def agent_view(tool, text):
    result = agent.parse_clamav_conf(text.encode(), tool)
    assert result['parsed']
    return result['accepted'], result['error'], {n: (v['line'], v['value']) for n, v in result['values'].items()}


def contract_view(tool, text):
    """The contract's parse, restricted to the values agents keep, escaped and bounded as agents store them."""
    parsed = clamav_event_commands.parse(text, tool)
    def bounded(name, raw):
        shown, _ = agent.redact_cron_command(agent._tcpw_escape(raw)) if name in persistence.CLAMAV_COMMANDS else (agent._tcpw_escape(raw), False)
        return shown[:persistence.CRON_COMMAND_LIMIT if name in persistence.CLAMAV_COMMANDS else persistence.CLAMAV_VALUE_LIMIT]
    values = {n: (v['line'], bounded(n, v['value'])) for n, v in parsed['values'].items() if n in persistence.CLAMAV_KEPT[tool]}
    return parsed['accepted'], parsed['error'], values


@pytest.mark.parametrize('tool,text', FIXTURES)
def test_agent_matches_the_contract(tool, text):
    assert agent_view(tool, text) == contract_view(tool, text)


def test_agent_option_tables_match_the_contract():
    assert agent.CLAMAV_OPTIONS == clamav_event_commands.OPTIONS
    assert agent.CLAMAV_REGEX == clamav_event_commands.REGEX
    assert agent.CLAMAV_FILES == persistence.CLAMAV_FILES
    assert {t: set(v) for t, v in agent.CLAMAV_KEPT.items()} == {t: set(v) for t, v in persistence.CLAMAV_KEPT.items()}
    for tool, names in persistence.CLAMAV_KEPT.items():
        assert set(names) == {n for aliases in clamav_event_commands.ALIASES[tool].values() for n in aliases}


def test_agent_matches_the_contract_on_random_configurations():
    rng = random.Random(20261127)
    names = {'clamd': ['VirusEvent', 'User', 'MaxThreads', 'Foreground', 'ScanOnAccess', 'BytecodeSecurity', 'user',
                       'Example', 'LogFile', '#VirusEvent'],
             'freshclam': ['OnUpdateExecute', 'on-update-execute', 'OnErrorExecute', 'OnOutdatedExecute',
                           'on-outdated-execute', 'DatabaseOwner', 'user', 'daemon', 'Checks', 'SafeBrowsing',
                           'HTTPProxyPassword', 'VirusEvent']}
    args = ['x', '/bin/sh -c "a b"', 'yes', 'no # c', '12', '5\t# c', '"q"', '"unterminated', '""', '#', '##x', 'a#b',
            'EXIT_2', '%v %f', 'Paranoid', 'TrustSigned', 'true#', '', '  ', 'p' * 1100]
    for tool in ('clamd', 'freshclam'):
        for _ in range(800):
            lines = []
            for _ in range(rng.randint(0, 6)):
                line = rng.choice(['', ' ', '\t']) + rng.choice(names[tool]) + rng.choice([' ', '\t', '  ', '']) + rng.choice(args)
                lines.append(line + rng.choice(['', ' ', '\t', '\r']))
            text = '\n'.join(lines) + ('\n' if rng.random() < 0.7 else '')
            assert agent_view(tool, text) == contract_view(tool, text), (tool, text)


def test_commands_are_redacted_escaped_and_bounded_and_secrets_are_dropped():
    result = agent.parse_clamav_conf(b'HTTPProxyPassword hunter2\nOnUpdateExecute /bin/x --password=s3cret \x1b[31m\n'
                                     b'OnErrorExecute /bin/' + b'y' * 600 + b'\nDatabaseOwner ' + b'o' * 300 + b'\n', 'freshclam')
    assert 'HTTPProxyPassword' not in result['values'] and 'hunter2' not in repr(result)
    update, error, owner = (result['values'][n] for n in ('OnUpdateExecute', 'OnErrorExecute', 'DatabaseOwner'))
    assert 's3cret' not in update['value'] and update['redacted'] and result['redacted']
    assert '\x1b' not in update['value'] and '\\x1b' in update['value']
    assert len(error['value']) == 512 and error['truncated'] and not error['redacted']
    assert len(owner['value']) == 256 and owner['truncated']
    clamd = agent.parse_clamav_conf(b'LocalSocket /run/clamd.ctl\nVirusEvent /bin/v\nUser clamav\n', 'clamd')
    assert set(clamd['values']) == {'VirusEvent', 'User'}


@pytest.mark.parametrize('data', [b'VirusEvent x\x00\n', b'x' * (1024 * 1024 + 1)])
def test_nul_or_over_limit_text_yields_nothing(data):
    assert agent.parse_clamav_conf(data, 'clamd') == {'parsed': False, 'accepted': False, 'error': None, 'values': {},
                                                      'redacted': False}


def test_inventory_parses_only_the_debian_files_and_never_runs_commands(tmp_path, monkeypatch):
    marker = tmp_path / 'ran'
    root = tmp_path / 'clamav'
    root.mkdir()
    (root / 'clamd.conf').write_text(f'VirusEvent /usr/bin/touch {marker}\n')
    (root / 'freshclam.conf').write_text(f'OnUpdateExecute /usr/bin/touch {marker}\n')
    (root / 'other.conf').write_text(f'VirusEvent /usr/bin/touch {marker}\n')
    (root / 'linked.conf').symlink_to(root / 'clamd.conf')
    monkeypatch.setattr(agent, 'PERSISTENCE_ROOTS', (str(root),))
    monkeypatch.setattr(agent, 'PERSISTENCE_FILES', ())
    monkeypatch.setattr(agent, 'CLAMAV_FILES', {str(root / 'clamd.conf'): 'clamd', str(root / 'freshclam.conf'): 'freshclam'})
    plain = agent.persistence_inventory(time.monotonic() + 5)
    assert not any('clamav' in row for row in plain['entries'])
    rows = {r['path']: r for r in agent.persistence_inventory(time.monotonic() + 5, cron_jobs=True)['entries']}
    assert sorted(p for p, r in rows.items() if 'clamav' in r) == [str(root / 'clamd.conf'), str(root / 'freshclam.conf')]
    assert rows[str(root / 'clamd.conf')]['clamav']['values']['VirusEvent']['value'] == f'/usr/bin/touch {marker}'
    assert rows[str(root / 'linked.conf')]['kind'] == 'symlink'
    assert not marker.exists()


def entry(path, text, parsed=True, kind='regular'):
    row = {'path': path, 'kind': kind, 'uid': 0, 'gid': 0, 'mode': 0o644, 'size': len(text), 'mtime_ns': 1}
    if kind == 'regular':
        row['sha256'] = 'a' * 64
    else:
        row['target'] = '/x'
    if parsed:
        row['clamav'] = agent.parse_clamav_conf(text.encode(), persistence.CLAMAV_FILES[path])
    return row


def stored_inventory(files, unparsed=(), others=()):
    entries = [entry(path, text) for path, text in files.items()]
    entries += [entry(path, text, parsed=False) for path, text in unparsed]
    entries += list(others)
    return {'scope': ['/etc/clamav', '/etc/clamd.d', '/etc/freshclam.conf'], 'state': 'collected', 'entries': entries,
            'gaps': [], 'skipped': 0, 'missing_roots': []}


def valid():
    return stored_inventory({CLAMD: 'User clamav\nVirusEvent /bin/v %v --token=abc\n',
                             FRESHCLAM: 'OnUpdateExecute /bin/u\nDatabaseOwner clamav\n'})


def report(path=CLAMD):
    return lambda inventory: next(e for e in inventory['entries'] if e['path'] == path)['clamav']


def value(name, path=CLAMD):
    return lambda inventory: report(path)(inventory)['values'][name]


BAD = [
    lambda v: report()(v).update(extra=1),
    lambda v: report()(v).pop('redacted'),
    lambda v: report()(v).update(parsed=1),
    lambda v: report()(v).update(values=[]),
    lambda v: report()(v).update(redacted=False),
    lambda v: report()(v).update(accepted=False),
    lambda v: report()(v).update(error={'line': 3, 'reason': 'unknown_option'}),
    lambda v: report()(v).update(accepted=False, error={'line': 2, 'reason': 'unknown_option'}),
    lambda v: report()(v).update(accepted=False, error={'line': 9, 'reason': 'other'}),
    lambda v: report()(v).update(accepted=False, error={'line': 0, 'reason': 'unknown_option'}),
    lambda v: report()(v)['values'].update(LogFile={'line': 9, 'value': '/x', 'truncated': False, 'redacted': False}),
    lambda v: report()(v)['values'].update(OnUpdateExecute={'line': 9, 'value': '/x', 'truncated': False, 'redacted': False}),
    lambda v: report(FRESHCLAM)(v)['values'].update(VirusEvent={'line': 9, 'value': '/x', 'truncated': False, 'redacted': False}),
    lambda v: value('User')(v).update(extra=1),
    lambda v: value('User')(v).update(line=2),
    lambda v: value('User')(v).update(line=True),
    lambda v: value('User')(v).update(value='u' * 257),
    lambda v: value('User')(v).update(value=None),
    lambda v: value('User')(v).update(redacted=True),
    lambda v: value('VirusEvent')(v).update(value='x' * 513),
    lambda v: value('VirusEvent')(v).update(value='a\x00'),
    lambda v: value('VirusEvent')(v).update(truncated='no'),
    lambda v: report(FRESHCLAM)(v).update(parsed=False),
]


def test_valid_report_is_accepted():
    persistence.validate(valid())
    persistence.validate(stored_inventory({CLAMD: 'User a\nBogus x\nVirusEvent y\n'}))


@pytest.mark.parametrize('mutate', BAD)
def test_controller_rejects_malformed_reports(mutate):
    inventory = valid()
    mutate(inventory)
    with pytest.raises(ValueError):
        persistence.validate(inventory)


def test_controller_rejects_options_on_other_files_and_symlinks():
    for path in ('/etc/clamav/other.conf', '/etc/clamd.d/scan.conf', '/etc/freshclam.conf'):
        row = entry(CLAMD, 'VirusEvent x\n')
        row['path'] = path
        with pytest.raises(ValueError):
            persistence.validate(stored_inventory({}, others=[row]))
    linked = entry(CLAMD, '', parsed=False, kind='symlink')
    linked['clamav'] = agent.parse_clamav_conf(b'', 'clamd')
    with pytest.raises(ValueError):
        persistence.validate(stored_inventory({}, others=[linked]))


def test_parsed_detail_is_not_part_of_baseline_comparison():
    before = valid()
    after = copy.deepcopy(before)
    value('VirusEvent')(after)['value'] = '/different'
    assert persistence.compare(before, after)['changes'] == []
    assert 'clamav' not in persistence.metadata(after['entries'][0])


def store(inventory):
    with Session() as s:
        s.add(Host(id='one', name='one', address='192.0.2.1', fingerprint='test'))
        s.add(Inspection(id='new', host_id='one', created=time.time() - 1, report={'persistence': inventory}))
        s.commit()


def test_startup_view_shows_commands_accounts_counts_and_search(admin):
    store(stored_inventory({CLAMD: 'User clamscan\nVirusEvent /bin/v %v %f --token=abc\n',
                            FRESHCLAM: 'user bob\nOnUpdateExecute EXIT_1\nOnOutdatedExecute /bin/old %v\n'},
                           others=[entry('/etc/clamav/linked.conf', '', parsed=False, kind='symlink')],
                           unparsed=[('/etc/clamd.d/scan.conf', 'VirusEvent /bin/rpm\n')]))
    view = admin.get('/api/hosts/one/security/startup-inventory').json()
    rows = {r['path']: r for r in view['items']}
    clamd = rows[CLAMD]
    assert clamd['clamav_state'] == 'parsed' and clamd['clamav']['accepted'] and clamd['clamav']['redacted']
    [virus] = clamd['clamav']['commands']
    assert virus['directive'] == 'VirusEvent' and virus['line'] == 2 and virus['trigger'] == 'virus_found' and virus['runs']
    assert 'abc' not in virus['command'] and virus['redacted']
    assert virus['argv'][:2] == ['sh', '-c'] and clamav_event_commands.FILENAME_DISABLED_MESSAGE in virus['argv'][2]
    assert virus['account'] == {'name': 'clamscan', 'source': 'User', 'line': 1} and virus['waits'] is True
    assert clamd['clamav']['authorizes_response'] is False and clamd['clamav']['origin'] == 'not_assessed'
    fresh = {c['directive']: c for c in rows[FRESHCLAM]['clamav']['commands']}
    assert fresh['OnUpdateExecute']['account'] == {'name': 'bob', 'source': 'DatabaseOwner', 'line': 1}
    assert fresh['OnUpdateExecute']['exit_status_outside_daemon'] == 1
    assert fresh['OnOutdatedExecute']['command_source'] == 'depends_on_daemon_mode' and not fresh['OnOutdatedExecute']['runs']
    assert rows['/etc/clamd.d/scan.conf']['clamav_state'] == 'not_parsed_family'
    assert 'clamav_state' not in rows['/etc/clamav/linked.conf']
    labels = {c['id']: c['label'] for c in view['catalog']}
    assert labels['clamav'].endswith('· 3 parsed event commands')
    assert any('ClamAV 1.5.4 option-parser rules' in gap for gap in view['gaps'])
    assert [r['path'] for r in admin.get('/api/hosts/one/security/startup-inventory?q=/bin/old').json()['items']] == [FRESHCLAM]
    assert [r['path'] for r in admin.get('/api/hosts/one/security/startup-inventory?q=clamscan').json()['items']] == [CLAMD]


def test_rejected_configuration_runs_nothing_and_is_labelled(admin):
    store(stored_inventory({CLAMD: 'VirusEvent /bin/v\nExample\n'}, unparsed=[(FRESHCLAM, 'OnUpdateExecute /bin/u\n')]))
    view = admin.get('/api/hosts/one/security/startup-inventory').json()
    rows = {r['path']: r for r in view['items']}
    assert rows[CLAMD]['clamav']['error'] == {'line': 2, 'reason': 'example_config'}
    assert [c['runs'] for c in rows[CLAMD]['clamav']['commands']] == [False]
    assert rows[FRESHCLAM]['clamav_state'] == 'not_reported' and 'clamav' not in rows[FRESHCLAM]
    labels = {c['id']: c['label'] for c in view['catalog']}
    assert labels['clamav'].endswith('· rejected by the option parser · not reported by this agent version')


def test_symlinked_configuration_is_marked_not_followed(admin):
    store(stored_inventory({}, others=[entry(CLAMD, '', parsed=False, kind='symlink')]))
    rows = {r['path']: r for r in admin.get('/api/hosts/one/security/startup-inventory').json()['items']}
    assert rows[CLAMD]['clamav_state'] == 'not_followed'
