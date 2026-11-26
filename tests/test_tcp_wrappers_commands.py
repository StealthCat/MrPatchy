"""Agents parse hosts.allow/hosts.deny spawn, twist and aclexec commands into Startup Files (#1390 increment 3).

The agent cannot import the controller, so it carries its own parser. These tests hold it to
``app/tcp_wrappers.resolve()`` on shared fixtures and random input, check that nothing in the
files runs, and cover controller validation and the startup view's reachability.
"""
import copy
import random
import time

import pytest

from app import persistence, startup_inventory, tcp_wrappers
from app.db import Host, Session
from app.incidents import Inspection
from target import agent

ALLOW, DENY = '/etc/hosts.allow', '/etc/hosts.deny'

FIXTURES = [
    ('sshd : 10.0.0.0/8 : spawn (/usr/bin/logger %h %u) &\n'
     'in.telnetd : ALL : aclexec /usr/local/bin/check %a : twist /bin/echo no\n', 'ALL: ALL: spawn /bin/deny\n'),
    ('ALL : ALL : user nobody.nogroup : group adm : spawn /tmp/x\n', None),
    ('ALL : ALL : spawn /tmp/a : bogus : spawn /tmp/b\n', 'sshd: ALL: twist /bin/t\n'),
    ('sshd: ALL\nALL: ALL: spawn /first\nALL: ALL: spawn /second\n', 'ALL: ALL: spawn /deny\n'),
    ('ALL: ALL EXCEPT 10.0.0.1: spawn /x\nALL: ALL: spawn /y\n', 'ALL: ALL: spawn /z\n'),
    ('ALL: ALL: aclexec /check\n', 'ALL: ALL: spawn /deny\n'),
    ('sshd: ALL: aclexec /a\nALL: ALL: spawn /b\n', 'ALL: ALL: spawn /deny\n'),
    ('sshd: ALL: AclExec\nAll: aLL: spawn /b\n', 'ALL: ALL: spawn /deny\n'),
    ('sshd: [::1]:spawn /v6\n# comment : spawn /no\n  # indented: ALL: spawn /yes\n', None),
    ('sshd: ALL: spawn /a \\\n  /continued\n', 'no separator here\nALL: ALL: spawn /deny'),
    ('sshd: ALL: spawn ' + 'x' * 2100 + '\nALL: ALL: spawn /never\n', 'ALL: ALL: spawn /deny\n'),
    ('sshd: ALL: spawn /a\\: literal colon : twist /b\n', None),
    ('sshd: ALL: spawn=  /eq : setenv PATH /bin : rfc931 : nice : keepalive : spawn /later\n', None),
    ('sshd: ALL: twist /t : spawn /after\n', 'ALL: ALL: allow : spawn /bad\n'),
    ('ALL: ALL: deny\n', 'ALL: ALL: spawn /deny\n'),
    ('sshd: ALL: spawn \t /tabs\t\n', None),
    ('sshd: ALL: spawn /x %z %%\n', None),
    ('sshd: ALL: severity auth.info : umask 022 : linger 5 : banners /etc/b : spawn /x\n', None),
]


def obs(text):
    return {'state': 'absent'} if text is None else {'state': 'regular', 'text': text}


def stored_inventory(allow, deny):
    entries = []
    missing = []
    for path, text in ((ALLOW, allow), (DENY, deny)):
        if text is None:
            missing.append(path)
            continue
        entries.append({'path': path, 'kind': 'regular', 'uid': 0, 'gid': 0, 'mode': 0o644, 'size': len(text),
                        'mtime_ns': 1, 'sha256': 'a' * 64, 'tcp_wrappers': agent.parse_tcp_wrappers(text.encode())})
    return {'scope': [ALLOW, DENY], 'state': 'collected', 'entries': entries, 'gaps': [], 'skipped': 0,
            'missing_roots': missing}


def viewed(allow, deny):
    inventory = stored_inventory(allow, deny)
    persistence.validate(inventory)
    out = []
    for entry in inventory['entries']:
        view = startup_inventory.tcp_wrappers_view(entry, inventory)
        assert view['reachability_unknown'] is None
        out += [(entry['path'], c['line'], c['option'], c['command'], c['daemons'], c['clients'],
                 c['matches_every_request'], c['reachability'] == 'reachable', c['shadowed_by'],
                 c['identity_options_ignored'], c['after_runtime_checks']) for c in view['commands']]
    return out


def dedupe(values):
    return list(dict.fromkeys(values))


def resolved(allow, deny):
    result = tcp_wrappers.resolve({'hosts_allow': obs(allow), 'hosts_deny': obs(deny)})
    return [(c['path'], c['line'], c['option'], c['command'], c['daemons'], c['clients'],
             c['matches_every_request'], c['reachable'], c['shadowed_by'],
             dedupe(i['option'] for i in c['identity_options_ignored']), dedupe(c['after_runtime_checks']))
            for c in result['commands']]


@pytest.mark.parametrize('allow, deny', FIXTURES)
def test_agent_commands_and_view_reachability_match_the_contract(allow, deny):
    assert viewed(allow, deny) == resolved(allow, deny)


def test_agent_matches_the_contract_on_random_rules():
    rng = random.Random(1390)
    pieces = ['ALL', 'all', 'sshd', 'EXCEPT', 'LOCAL', '10.0.0.0/8', '[::1]', ',', ' ', '\t', ':', ':', ':',
              'spawn /s', 'twist /t', 'aclexec /a', 'user root', 'group adm', 'allow', 'deny', 'keepalive',
              'bogus', '\\:', '=', '\\\n', '#', '%h', 'nice']
    for _ in range(1500):
        files = []
        for _ in range(2):
            lines = [''.join(rng.choice(pieces) for _ in range(rng.randint(0, 9))) for _ in range(rng.randint(0, 5))]
            text = '\n'.join(lines) + rng.choice(['\n', '', '\n\n'])
            files.append(rng.choice([text, text, None]))
        assert viewed(*files) == resolved(*files), files


def test_agent_reports_the_entry_and_file_facts_reachability_needs():
    parsed = agent.parse_tcp_wrappers(b'x\nsshd: ALL: aclexec /a : bogus\nALL: ALL: spawn /b\n' + b'y' * 2100 + b'\n')
    assert parsed['parsed'] and parsed['entries'] == 2 and parsed['skipped'] == 1 and parsed['option_errors'] == 1
    assert parsed['unconditional_line'] == 3 and parsed['aclexec_through_unconditional'] is True
    assert parsed['error_line'] == 4


@pytest.mark.parametrize('data', [b'ALL: ALL: spawn /x\x00\n', b'ALL: ALL: spawn \xff\n', b'#' * (1024 * 1024 + 1)])
def test_unreadable_text_yields_no_commands(data):
    parsed = agent.parse_tcp_wrappers(data)
    assert parsed['parsed'] is False and parsed['commands'] == [] and parsed['entries'] == 0
    persistence.validate_tcp_wrappers(parsed, ALLOW)


def test_commands_are_redacted_escaped_and_bounded():
    text = ('sshd: ALL: spawn curl -H "Bearer abc" https\\://u\\:pw@h/ \x1b[31m --token=sekrit\n'
            + ''.join(f'svc{i}: ALL: spawn /bin/{i}\n' for i in range(70))
            + 'sshd: ' + ' '.join(f'd{i}' for i in range(40)) + ': ALL: spawn /many\n')
    parsed = agent.parse_tcp_wrappers(text.encode())
    first = parsed['commands'][0]
    assert 'sekrit' not in first['command'] and 'pw@' not in first['command'] and 'abc' not in first['command'] and '\x1b' not in first['command']
    assert '\\x1b' in first['command'] and first['redacted'] and parsed['redacted']
    assert len(parsed['commands']) == agent.CRON_FILE_JOBS and parsed['truncated']
    long = agent.parse_tcp_wrappers(('ALL: ALL: spawn /' + 'a' * 600 + '\n').encode())['commands'][0]
    assert len(long['command']) == agent.CRON_COMMAND_LIMIT and long['command_truncated']
    many = agent.parse_tcp_wrappers(('sshd ' + ' '.join(f'd{i}' for i in range(40)) + ': ALL: spawn /x\n').encode())
    assert len(many['commands'][0]['daemons']) == 32 and many['truncated']
    persistence.validate_tcp_wrappers(parsed, ALLOW)


def test_inventory_parses_only_the_wrapper_files_and_never_runs_commands(tmp_path, monkeypatch):
    marker = tmp_path / 'ran'
    allow = tmp_path / 'hosts.allow'
    allow.write_text(f'ALL: ALL: spawn touch {marker} : aclexec touch {marker}\nsshd: ALL: twist touch {marker}\n')
    deny = tmp_path / 'hosts.deny'
    deny.write_text(f'ALL: ALL: spawn touch {marker}\n')
    other = tmp_path / 'rc.local'
    other.write_text(f'ALL: ALL: spawn touch {marker}\n')
    monkeypatch.setattr(agent, 'PERSISTENCE_ROOTS', ())
    monkeypatch.setattr(agent, 'PERSISTENCE_FILES', (str(allow), str(deny), str(other)))
    monkeypatch.setattr(agent, 'TCP_WRAPPERS_FILES', (str(allow), str(deny)))
    plain = agent.persistence_inventory(time.monotonic() + 5)
    assert not any('tcp_wrappers' in row for row in plain['entries'])
    result = agent.persistence_inventory(time.monotonic() + 5, cron_jobs=True)
    rows = {r['path']: r for r in result['entries']}
    assert [c['option'] for c in rows[str(allow)]['tcp_wrappers']['commands']] == ['spawn', 'aclexec', 'twist']
    assert rows[str(deny)]['tcp_wrappers']['unconditional_line'] == 1
    assert 'tcp_wrappers' not in rows[str(other)]
    assert not marker.exists()


def test_symlinked_wrapper_file_is_not_followed_or_parsed(tmp_path, monkeypatch):
    target = tmp_path / 'real'
    target.write_text('ALL: ALL: spawn /x\n')
    allow = tmp_path / 'hosts.allow'
    allow.symlink_to(target)
    monkeypatch.setattr(agent, 'PERSISTENCE_ROOTS', ())
    monkeypatch.setattr(agent, 'PERSISTENCE_FILES', (str(allow),))
    monkeypatch.setattr(agent, 'TCP_WRAPPERS_FILES', (str(allow),))
    row, = agent.persistence_inventory(time.monotonic() + 5, cron_jobs=True)['entries']
    assert row['kind'] == 'symlink' and 'tcp_wrappers' not in row


def valid():
    return stored_inventory('sshd: ALL: user x : spawn /a\nALL: ALL: twist /b\n', 'ALL: ALL: spawn /c\n')


@pytest.mark.parametrize('mutate', [
    lambda inv: inv['entries'][0].__setitem__('path', '/etc/hosts'),
    lambda inv: inv['entries'][0].__setitem__('kind', 'symlink') or inv['entries'][0].__setitem__('target', '/x'),
    lambda inv: inv['entries'][0]['tcp_wrappers'].__setitem__('extra', 1),
    lambda inv: inv['entries'][0]['tcp_wrappers'].__setitem__('entries', -1),
    lambda inv: inv['entries'][0]['tcp_wrappers'].__setitem__('parsed', False),
    lambda inv: inv['entries'][0]['tcp_wrappers'].__setitem__('error_line', 2),
    lambda inv: inv['entries'][0]['tcp_wrappers'].__setitem__('unconditional_line', 0),
    lambda inv: inv['entries'][1]['tcp_wrappers'].__setitem__('unconditional_line', None)
    or inv['entries'][1]['tcp_wrappers'].__setitem__('aclexec_through_unconditional', True),
    lambda inv: inv['entries'][0]['tcp_wrappers'].__setitem__('commands', inv['entries'][0]['tcp_wrappers']['commands'][::-1]),
    lambda inv: inv['entries'][0]['tcp_wrappers']['commands'][0].__setitem__('option', 'setenv'),
    lambda inv: inv['entries'][0]['tcp_wrappers']['commands'][0].__setitem__('command', ''),
    lambda inv: inv['entries'][0]['tcp_wrappers']['commands'][0].__setitem__('command', 'x' * 513),
    lambda inv: inv['entries'][0]['tcp_wrappers']['commands'][0].__setitem__('command', 'a\x00b'),
    lambda inv: inv['entries'][0]['tcp_wrappers']['commands'][0].__setitem__('daemons', ['x'] * 33),
    lambda inv: inv['entries'][0]['tcp_wrappers']['commands'][0].__setitem__('clients', ['']),
    lambda inv: inv['entries'][0]['tcp_wrappers']['commands'][0].__setitem__('identity_options_ignored', ['umask']),
    lambda inv: inv['entries'][0]['tcp_wrappers']['commands'][0].__setitem__('after_runtime_checks', ['user', 'user']),
    lambda inv: inv['entries'][0]['tcp_wrappers']['commands'][0].__setitem__('identity_options_ignored', [{'user': 1}]),
    lambda inv: inv['entries'][0]['tcp_wrappers']['commands'][0].__setitem__('identity_options_ignored', [['user']]),
    lambda inv: inv['entries'][0]['tcp_wrappers']['commands'][0].__setitem__('identity_options_ignored', ['user', {}]),
    lambda inv: inv['entries'][0]['tcp_wrappers']['commands'][0].__setitem__('identity_options_ignored', [None]),
    lambda inv: inv['entries'][0]['tcp_wrappers']['commands'][0].__setitem__('after_runtime_checks', [{'user': 1}]),
    lambda inv: inv['entries'][0]['tcp_wrappers']['commands'][0].__setitem__('after_runtime_checks', [['user']]),
    lambda inv: inv['entries'][0]['tcp_wrappers']['commands'][0].__setitem__('after_runtime_checks', ['user', []]),
    lambda inv: inv['entries'][0]['tcp_wrappers']['commands'][0].__setitem__('after_runtime_checks', [1]),
    lambda inv: inv['entries'][0]['tcp_wrappers']['commands'][0].__setitem__('redacted', 1),
    lambda inv: inv['entries'][0]['tcp_wrappers']['commands'][0].pop('line'),
])
def test_controller_rejects_malformed_reports(mutate):
    inventory = valid()
    persistence.validate(inventory)
    mutate(inventory)
    with pytest.raises(ValueError):
        persistence.validate(inventory)


@pytest.mark.parametrize('key,names', [
    ('identity_options_ignored', []),
    ('identity_options_ignored', ['user']),
    ('identity_options_ignored', ['user', 'group']),
    ('after_runtime_checks', []),
    ('after_runtime_checks', sorted(persistence.TCP_WRAPPERS_RUNTIME)),
])
def test_controller_accepts_valid_unique_option_lists(key, names):
    inventory = valid()
    inventory['entries'][0]['tcp_wrappers']['commands'][0][key] = list(names)
    persistence.validate(inventory)


def test_parsed_detail_is_not_part_of_baseline_comparison():
    before = valid()
    after = copy.deepcopy(before)
    after['entries'][0]['tcp_wrappers']['commands'][0]['command'] = '/different'
    assert persistence.compare(before, after) == {**persistence.compare(before, before)}
    assert persistence.compare(before, after)['changes'] == []


def test_deny_reachability_is_unknown_without_parsed_allow_commands():
    inventory = stored_inventory('ALL: ALL: spawn /a\n', 'ALL: ALL: spawn /c\n')
    allow, deny = inventory['entries']
    del allow['tcp_wrappers']
    view = startup_inventory.tcp_wrappers_view(deny, inventory)
    assert view['commands'][0]['reachability'] == 'unknown' and view['reachable'] == 0
    assert 'not reported' in view['reachability_unknown']
    allow['tcp_wrappers'] = agent.parse_tcp_wrappers(b'\xff')
    assert 'could not be parsed' in startup_inventory.tcp_wrappers_view(deny, inventory)['reachability_unknown']
    inventory['entries'] = [deny]
    assert 'not collected' in startup_inventory.tcp_wrappers_view(deny, inventory)['reachability_unknown']
    inventory['missing_roots'] = [ALLOW]
    assert startup_inventory.tcp_wrappers_view(deny, inventory)['commands'][0]['reachability'] == 'reachable'


def test_startup_view_shows_commands_states_counts_and_search(admin):
    inventory = stored_inventory('sshd: ALL: spawn /usr/bin/logger %h\nALL: ALL: twist /bin/echo no\n', 'ALL: ALL: spawn /deny\n')
    older = {'path': '/etc/crontab', 'kind': 'regular', 'uid': 0, 'gid': 0, 'mode': 0o644, 'size': 1, 'mtime_ns': 1, 'sha256': 'b' * 64}
    inventory['scope'].append('/etc/crontab')
    inventory['entries'].append(older)
    with Session() as s:
        s.add(Host(id='one', name='one', address='192.0.2.1', fingerprint='test'))
        s.add(Inspection(id='new', host_id='one', created=time.time() - 1, report={'persistence': inventory}))
        s.commit()
    view = admin.get('/api/hosts/one/security/startup-inventory').json()
    rows = {r['path']: r for r in view['items']}
    allow = rows[ALLOW]['tcp_wrappers']
    assert rows[ALLOW]['tcp_wrappers_state'] == 'parsed' and allow['reachable'] == 2
    assert [c['command'] for c in allow['commands']] == ['/usr/bin/logger %h', '/bin/echo no']
    deny = rows[DENY]['tcp_wrappers']['commands'][0]
    assert deny['reachability'] == 'shadowed' and deny['shadowed_by'] == {'path': ALLOW, 'line': 2}
    assert 'tcp_wrappers_state' not in rows['/etc/crontab']
    catalog = {c['id']: c['label'] for c in view['catalog']}
    assert catalog['tcp_wrappers_allow'].endswith('· 2 parsed commands') and catalog['tcp_wrappers_deny'].endswith('· 1 parsed command')
    found = admin.get('/api/hosts/one/security/startup-inventory?q=logger').json()
    assert [r['path'] for r in found['items']] == [ALLOW]


def test_older_agent_wrapper_files_are_marked_not_reported(admin):
    inventory = stored_inventory('ALL: ALL: spawn /a\n', None)
    del inventory['entries'][0]['tcp_wrappers']
    with Session() as s:
        s.add(Host(id='one', name='one', address='192.0.2.1', fingerprint='test'))
        s.add(Inspection(id='new', host_id='one', created=time.time() - 1, report={'persistence': inventory}))
        s.commit()
    view = admin.get('/api/hosts/one/security/startup-inventory').json()
    row, = view['items']
    assert row['tcp_wrappers_state'] == 'not_reported' and 'tcp_wrappers' not in row
    assert next(c for c in view['catalog'] if c['id'] == 'tcp_wrappers_allow')['label'].endswith('not reported by this agent version')
