"""Agents parse request-key configuration into Startup Files (#1632 increment 3).

The agent cannot import the controller, so it carries its own per-file parser. These tests hold it
to ``app/request_key_callouts.evaluate()`` on shared fixtures and random input, check that nothing in
the files runs, and cover controller validation and the startup view.
"""
import copy
import random
import time

import pytest

from app import persistence, request_key_callouts
from app.db import Host, Session
from app.incidents import Inspection
from target import agent

CONF = '/etc/request-key.conf'
DROPIN = '/etc/request-key.d/local.conf'

FIXTURES = [
    '',
    '\n',
    '# comment\ncreate user * * /usr/bin/handler %k %d %c\n',
    'create\tuser\tmpk:*\t*\t|/usr/bin/pipe %k\n',
    'create user * * handler %d\n',
    'create user * * /bin/x %q\n',
    'create user * * /bin/x %\n',
    'create user * * /bin/x %%d\n',
    'create user * * /bin/x %{user:a}\n',
    'create user * * /bin/x %{user:}\n',
    'create user * * /bin/x %{user:a}b\n',
    'negate * * * /bin/negate\n',
    'cr*te * * * /bin/star\n',
    'create user\n',
    'create user \n',
    'create user * *\n',
    'create user * * \n',
    'create\n',
    '* * * * /bin/all\ncreate\n',
    'create user * * /bin/last',
    'create user * * /bin/x %d',
    ' create user * * /indented\n#create user * * /commented\n',
    'create user * * /bin/x\r\n',
    'create user * * /bin/x ' + 'a ' * 260 + '\n',
    'create user * * /bin/x ' + 'a' * 4100 + '\ncreate user * * /bin/y\n',
    'create user * * /bin/x ' + 'a' * 4071 + '\n',
    'create user * * /bin/x ' + 'a' * 4072 + '\n',
    'create user * * /bin/x --password=hunter2 %d\n',
    'create logon * * /bin/l\ncreate user\x0b* * /bin/v\n',
]


def contract_view(text):
    result = request_key_callouts.evaluate(conf={'exists': True, 'text': text}, dropins={'exists': False})
    rules = [(int(r['source'].rsplit(':', 1)[1]), r['op'], r['type'], r['description'], r['callout_info'], r['pipe'],
              r['requester_controlled'], r['fails_when_selected'],
              'on_matching_request' if r['code_runs'] == 'lookup_aborts' else r['code_runs'])
             for r in result['rules']]
    aborts = [(int(a['source'].rsplit(':', 1)[1]), a['reason'], a['scope'], a['universal']) for a in result['aborts']]
    dropped = any(g['code'] == 'last_byte_dropped' for g in result['gaps'])
    return rules, aborts, dropped


def agent_view(text):
    result = agent.parse_request_key(text.encode())
    assert result['parsed'] and not result['truncated']
    rules = [(r['line'], r['op'], r['type'], r['description'], r['callout_info'], r['pipe'], r['requester_controlled'],
              r['fails_when_selected'], r['code_runs']) for r in result['rules']]
    aborts = [(a['line'], a['reason'], a['scope'], a['universal']) for a in result['aborts']]
    universal = [a[0] for a in aborts if a[3]]
    assert result['universal_abort_line'] == (universal[0] if universal else None)
    return rules, aborts, result['last_byte_dropped']


@pytest.mark.parametrize('text', FIXTURES)
def test_agent_matches_the_contract(text):
    assert agent_view(text) == contract_view(text)


def test_agent_matches_the_contract_on_random_configurations():
    rng = random.Random(20261127)
    words = ['create', 'negate', 'cr*', '*', '*te', 'user', 'logon', 'us*r', 'mpk:*', 'a', '', '/bin/x', 'prog',
             '|/bin/p', '%d', '%c', '%k', '%z', '%', '%%', '%{user:a}', '%{:a}', '#x', '--password=s3cret']
    seps = [' ', '\t', '  ', '\x0b', '\r']
    checked = 0
    for _ in range(1500):
        lines = []
        for _ in range(rng.randint(0, 6)):
            line = ''.join(rng.choice(seps) + rng.choice(words) for _ in range(rng.randint(0, 8)))
            if rng.random() < 0.3:
                line = line.lstrip(' \t\x0b\r')
            if rng.random() < 0.03:
                line += 'x' * rng.choice((4070, 4095, 4100))
            lines.append(line)
        text = '\n'.join(lines) + ('\n' if rng.random() < 0.7 else '')
        assert agent_view(text) == contract_view(text), text
        checked += 1
    assert checked == 1500


def test_commands_are_redacted_escaped_and_bounded():
    result = agent.parse_request_key(b'create user * * /bin/x --password=hunter2 \x1b[31m %d\n'
                                     b'create user ' + b'p' * 300 + b' * /bin/' + b'y' * 600 + b'\n')
    first, second = result['rules']
    assert 'hunter2' not in first['command'] and first['redacted'] and result['redacted']
    assert '\x1b' not in first['command'] and '\\x1b' in first['command']
    assert first['requester_controlled'] == ['description']
    assert second['type'] == 'user' and len(second['description']) == 256 and result['truncated']
    assert len(second['command']) == 512 and second['command_truncated']


def test_rule_and_abort_limits_keep_the_first_universal_abort():
    text = ''.join(f'create user k{i} * /bin/x\n' for i in range(70)) + ''.join(f'negate user k{i}\n' for i in range(70))
    text += 'create\n'
    result = agent.parse_request_key(text.encode())
    assert len(result['rules']) == 64 and len(result['aborts']) == 64 and result['truncated']
    assert result['universal_abort_line'] == 141
    persistence.validate(stored_inventory({CONF: text}))


@pytest.mark.parametrize('data', [b'create user * * /bin/x\x00\n', b'\xff\n', b'#' * 65537])
def test_unreadable_or_over_limit_text_yields_nothing(data):
    assert agent.parse_request_key(data) == {'parsed': False, 'rules': [], 'aborts': [], 'universal_abort_line': None,
                                             'last_byte_dropped': False, 'truncated': False, 'redacted': False}


def test_reads_follow_request_key_name_rules():
    assert agent.request_key_reads(CONF) and agent.request_key_reads(DROPIN)
    for path in ('/etc/request-key.d/.hidden.conf', '/etc/request-key.d/.conf', '/etc/request-key.d/x.conf.bak',
                 '/etc/request-key.d/sub/x.conf', '/etc/request-key.conf.d', '/etc/other.conf'):
        assert not agent.request_key_reads(path) and not persistence.request_key_reads(path), path
    assert agent.request_key_reads('/etc/request-key.d/a.conf') == persistence.request_key_reads('/etc/request-key.d/a.conf')


def test_inventory_parses_only_files_request_key_reads_and_never_runs_commands(tmp_path, monkeypatch):
    marker = tmp_path / 'ran'
    rule = f'create user * * /usr/bin/touch {marker}\n'
    conf = tmp_path / 'request-key.conf'
    conf.write_text(rule)
    dropins = tmp_path / 'request-key.d'
    (dropins / 'sub').mkdir(parents=True)
    for name in ('a.conf', '.hidden.conf', 'b.conf.bak', 'sub/c.conf'):
        (dropins / name).write_text(rule)
    (dropins / 'linked.conf').symlink_to(dropins / 'a.conf')
    monkeypatch.setattr(agent, 'PERSISTENCE_ROOTS', (str(dropins),))
    monkeypatch.setattr(agent, 'PERSISTENCE_FILES', (str(conf),))
    monkeypatch.setattr(agent, 'REQUEST_KEY_CONF', str(conf))
    monkeypatch.setattr(agent, 'REQUEST_KEY_DIR', str(dropins))
    plain = agent.persistence_inventory(time.monotonic() + 5)
    assert not any('request_key' in row for row in plain['entries'])
    rows = {r['path']: r for r in agent.persistence_inventory(time.monotonic() + 5, cron_jobs=True)['entries']}
    parsed = sorted(path for path, row in rows.items() if 'request_key' in row)
    assert parsed == sorted([str(conf), str(dropins / 'a.conf')])
    assert rows[str(conf)]['request_key']['rules'][0]['command'] == f'/usr/bin/touch {marker}'
    assert rows[str(dropins / 'linked.conf')]['kind'] == 'symlink'
    assert not marker.exists()


def entry(path, text, parsed=True, kind='regular'):
    row = {'path': path, 'kind': kind, 'uid': 0, 'gid': 0, 'mode': 0o644, 'size': len(text), 'mtime_ns': 1}
    if kind == 'regular':
        row['sha256'] = 'a' * 64
    else:
        row['target'] = '/x'
    if parsed:
        row['request_key'] = agent.parse_request_key(text.encode())
    return row


def stored_inventory(files, unparsed=(), others=()):
    entries = [entry(path, text) for path, text in files.items()]
    entries += [entry(path, text, parsed=False) for path, text in unparsed]
    entries += list(others)
    return {'scope': [CONF, '/etc/request-key.d'], 'state': 'collected', 'entries': entries, 'gaps': [], 'skipped': 0,
            'missing_roots': []}


def valid():
    return stored_inventory({CONF: 'create user * * /bin/x %k %d\ncreate user \n',
                             DROPIN: 'create logon * * |/bin/p\nnegate * * * /bin/never\n'})


def rule(i, path=CONF):
    return lambda inventory: next(e for e in inventory['entries'] if e['path'] == path)['request_key']['rules'][i]


def report(path=CONF):
    return lambda inventory: next(e for e in inventory['entries'] if e['path'] == path)['request_key']


def abort(i):
    return lambda inventory: report()(inventory)['aborts'][i]


BAD = [
    lambda v: report()(v).update(extra=1),
    lambda v: report()(v).pop('redacted'),
    lambda v: report()(v).update(parsed=1),
    lambda v: report()(v).update(rules='x'),
    lambda v: report()(v).update(rules=[copy.deepcopy(report()(v)['rules'][0])] * 65),
    lambda v: report()(v).update(universal_abort_line=True),
    lambda v: report()(v).update(universal_abort_line=0),
    lambda v: report()(v).update(universal_abort_line=2),
    lambda v: report()(v).update(universal_abort_line=1),
    lambda v: rule(0)(v).update(extra=1),
    lambda v: rule(0)(v).pop('pipe'),
    lambda v: rule(0)(v).update(line=2),
    lambda v: rule(0)(v).update(line=0),
    lambda v: rule(0)(v).update(op=''),
    lambda v: rule(0)(v).update(type='t' * 257),
    lambda v: rule(0)(v).update(description='a\x00'),
    lambda v: rule(0)(v).update(command='x' * 513),
    lambda v: rule(0)(v).update(command=None),
    lambda v: rule(0)(v).update(redacted='no'),
    lambda v: rule(0)(v).update(requester_controlled=['description', 'callout_info']),
    lambda v: rule(0)(v).update(requester_controlled=['other']),
    lambda v: rule(0)(v).update(requester_controlled=['stdin_callout_info']),
    lambda v: rule(0, DROPIN)(v).update(requester_controlled=[]),
    lambda v: rule(0)(v).update(fails_when_selected='other'),
    lambda v: rule(0)(v).update(fails_when_selected='program_without_slash'),
    lambda v: rule(0)(v).update(code_runs='never'),
    lambda v: rule(0)(v).update(kernel_upcall=False),
    lambda v: rule(1, DROPIN)(v).update(code_runs='on_matching_request'),
    lambda v: abort(0)(v).update(reason='other'),
    lambda v: abort(0)(v).update(universal=True),
    lambda v: abort(0)(v).update(scope=['a'] * 5),
    lambda v: abort(0)(v).update(scope=['']),
    lambda v: abort(0)(v).update(line=1),
    lambda v: abort(0)(v).update(reason='line_too_long'),
    lambda v: abort(0)(v).pop('scope'),
]


def test_valid_report_is_accepted():
    persistence.validate(valid())


@pytest.mark.parametrize('mutate', BAD)
def test_controller_rejects_malformed_reports(mutate):
    inventory = valid()
    mutate(inventory)
    with pytest.raises(ValueError):
        persistence.validate(inventory)


def test_controller_rejects_rules_on_files_request_key_does_not_read():
    for path in ('/etc/request-key.d/.hidden.conf', '/etc/request-key.d/x.bak', '/etc/request-key.d/sub/x.conf',
                 '/etc/request-key.conf.rpmnew'):
        inventory = stored_inventory({path: 'create user * * /bin/x\n'})
        with pytest.raises(ValueError):
            persistence.validate(inventory)
    linked = entry(DROPIN, '', parsed=False, kind='symlink')
    linked['request_key'] = agent.parse_request_key(b'')
    with pytest.raises(ValueError):
        persistence.validate(stored_inventory({}, others=[linked]))
    unparsed = stored_inventory({CONF: 'create user * * /bin/x\x00'})
    persistence.validate(unparsed)
    report()(unparsed)['rules'] = report()(valid())['rules']
    with pytest.raises(ValueError):
        persistence.validate(unparsed)


def test_parsed_detail_is_not_part_of_baseline_comparison():
    before = valid()
    after = copy.deepcopy(before)
    rule(0)(after)['command'] = '/different'
    assert persistence.compare(before, after)['changes'] == []
    assert 'request_key' not in persistence.metadata(after['entries'][0])


def store(inventory):
    with Session() as s:
        s.add(Host(id='one', name='one', address='192.0.2.1', fingerprint='test'))
        s.add(Inspection(id='new', host_id='one', created=time.time() - 1, report={'persistence': inventory}))
        s.commit()


def test_startup_view_shows_rules_lookups_counts_and_search(admin):
    store(stored_inventory({CONF: 'create user * * /bin/x %k %d\n', DROPIN: 'create logon * * |/bin/p\n'},
                           others=[entry('/etc/request-key.d/notes.txt', 'x', parsed=False),
                                   entry('/etc/request-key.d/linked.conf', '', parsed=False, kind='symlink')]))
    view = admin.get('/api/hosts/one/security/startup-inventory').json()
    rows = {r['path']: r for r in view['items']}
    conf = rows[CONF]
    assert conf['request_key_state'] == 'parsed'
    assert [(r['command'], r['requester_controlled'], r['code_runs']) for r in conf['request_key']['rules']] == [
        ('/bin/x %k %d', ['description'], 'on_matching_request')]
    assert conf['request_key']['lookups'] == {'universal_aborts': [], 'complete': True}
    assert rows[DROPIN]['request_key']['rules'][0]['pipe'] is True
    assert rows['/etc/request-key.d/notes.txt']['request_key_state'] == 'skipped_name'
    assert rows['/etc/request-key.d/linked.conf']['request_key_state'] == 'skipped_kind'
    labels = {c['id']: c['label'] for c in view['catalog']}
    assert labels['request_key'].endswith('· 1 parsed rule') and labels['request_key_d'].endswith('· 1 parsed rule')
    assert any('keyutils 1.6.3 rules' in gap and 'readdir() order' in gap for gap in view['gaps'])
    assert [r['path'] for r in admin.get('/api/hosts/one/security/startup-inventory?q=/bin/p').json()['items']] == [DROPIN]
    assert admin.get('/api/hosts/one/security/startup-inventory?q=nomatch').json()['items'] == []


def test_universal_abort_in_one_file_is_shown_on_every_parsed_file(admin):
    store(stored_inventory({CONF: 'create user * * /bin/x\n', DROPIN: '* * * *\n'}))
    view = admin.get('/api/hosts/one/security/startup-inventory').json()
    rows = {r['path']: r for r in view['items']}
    for path in (CONF, DROPIN):
        assert rows[path]['request_key']['lookups'] == {'universal_aborts': [DROPIN + ':1'], 'complete': True}
    labels = {c['id']: c['label'] for c in view['catalog']}
    assert labels['request_key_d'].endswith('· 0 parsed rules · every lookup aborts')
    assert not labels['request_key'].endswith('aborts')


def test_older_agent_files_are_marked_not_reported_and_lookups_incomplete(admin):
    store(stored_inventory({DROPIN: 'create user * * /bin/x\n'}, unparsed=[(CONF, 'create user * * /bin/y\n')]))
    view = admin.get('/api/hosts/one/security/startup-inventory').json()
    rows = {r['path']: r for r in view['items']}
    assert rows[CONF]['request_key_state'] == 'not_reported' and 'request_key' not in rows[CONF]
    assert rows[DROPIN]['request_key']['lookups']['complete'] is False
    labels = {c['id']: c['label'] for c in view['catalog']}
    assert labels['request_key'].endswith('not reported by this agent version')


def test_symlinked_conf_is_marked_not_followed(admin):
    store(stored_inventory({}, others=[entry(CONF, '', parsed=False, kind='symlink')]))
    row, = admin.get('/api/hosts/one/security/startup-inventory').json()['items']
    assert row['request_key_state'] == 'not_followed'


def test_universal_abort_line_must_match_the_stored_aborts():
    inventory = stored_inventory({CONF: '* * * *\ncreate user * * /bin/x\n'})
    persistence.validate(copy.deepcopy(inventory))
    report()(inventory)['universal_abort_line'] = None
    with pytest.raises(ValueError):
        persistence.validate(inventory)
