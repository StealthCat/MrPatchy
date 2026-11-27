"""Agents parse /etc/kdump.conf hooks into Startup Files (#1538 increment 3).

The agent cannot import the controller, so it carries its own parser. These tests hold it to
``app/kdump_hooks.assess()`` on shared fixtures and random input, check that nothing in the file
runs, and cover controller validation and the startup view.
"""
import copy
import random
import time

import pytest

from app import kdump_hooks, persistence
from app.db import Host, Session
from app.incidents import Inspection
from target import agent

CONF = '/etc/kdump.conf'
ABSENT = {stage: {'state': 'absent'} for stage in kdump_hooks.HOOK_DIRS}

FIXTURES = [
    '',
    'path /var/crash\n',
    'kdump_pre /usr/local/bin/pre\nkdump_post /usr/local/bin/post\nkdump_emergency /usr/local/bin/em\n',
    'core_collector makedumpfile -l --message-level 7 -d 31\n',
    'core_collector cp\n',
    'core_collector   "scp -q"  # trailing comment\n',
    'kdump_pre "/opt/has space/pre"\n',
    'kdump_post relative-post\n',
    'kdump_pre /a\nkdump_pre /b\n',
    'bogus 1\nkdump_pre /a\n',
    'net 192.0.2.1\n',
    'kdump_pre\n',
    'nfs host:/a\nssh root@host\n',
    'dracut_args --mount a --mount b\n',
    'ext4 /dev/sda1\ndracut_args --mount x\n',
    '  # comment\n\t\nkdump_pre\t/tab/pre \t\n',
    'default reboot\nfailure_action shell\n',
    'extra_bins /bin/a /bin/b  /bin/c\nkdump_emergency /e\n',
    'core_collector \x0b\n',
    'kdump_post "/quoted"\nkdump_emergency "\n',
    'core_collector makedumpfile\t-F -c\n',
]


def agent_view(text):
    result = agent.parse_kdump_conf(text.encode())
    if not result['parsed']:
        return None
    if not result['starts']:
        return False, [(r['line'], r['option'], r['code']) for r in result['refusals']]
    return True, [(h['stage'], h['source'], h['program'], h['args'], h['on_failure'], h['observations'])
                  for h in result['hooks']], result['extra_bins']


def contract_view(text):
    result = kdump_hooks.assess(text, ABSENT)
    if any(g['code'] == 'config_too_large' for g in result['gaps']):
        return None
    if not result['starts']:
        return False, [(r['line'], r['option'], r['code']) for r in result['refusals']]
    # The agent escapes control characters for display; nothing else may differ.
    shown = agent._tcpw_escape
    return True, [(h['stage'], h['source'], shown(h['program']), [shown(a) for a in h['args']], h['on_failure'],
                   h['observations']) for h in result['sequence']], len(result['installed_not_run'])


@pytest.mark.parametrize('text', FIXTURES)
def test_agent_matches_the_contract(text):
    assert agent_view(text) == contract_view(text)
    stored = stored_inventory(text)
    persistence.validate(stored)


def test_agent_matches_the_contract_on_random_configurations():
    rng = random.Random(1538)
    options = sorted(kdump_hooks.ACCEPTED | kdump_hooks.DEPRECATED) + ['bogus', 'Kdump_pre', 'kdump_pre', 'kdump_post',
                                                                       'kdump_emergency', 'core_collector']
    values = ['', '/usr/bin/a', 'rel', '"/q q"', '"x', 'makedumpfile -l -d 31', '--mount a', '--mount a --mount b',
              'a # c', '\t/t\t', 'cp -v', 'x"', '"', '#', '/b # "c"']
    for _ in range(1500):
        lines = []
        for _ in range(rng.randrange(0, 7)):
            kind = rng.random()
            if kind < 0.1:
                lines.append(rng.choice(['', '  ', '# c', '\t# x']))
            else:
                lines.append(rng.choice(['', ' ', '\t']) + rng.choice(options) + rng.choice([' ', '\t', '  '])
                             + rng.choice(values) + rng.choice(['', ' ', '\t']))
        text = '\n'.join(lines) + rng.choice(['', '\n'])
        assert agent_view(text) == contract_view(text), text
        persistence.validate(stored_inventory(text))


def test_default_collector_and_lines_are_reported():
    result = agent.parse_kdump_conf(b'path /var/crash\nkdump_post /p\n')
    assert result['starts'] is True and result['redacted'] is False
    collector, post = result['hooks']
    assert collector['line'] is None and collector['program'] == 'makedumpfile'
    assert collector['observations'] == ['args_rewritten_at_capture']
    assert post['line'] == 2 and post['args'] == ['<dump status>']


def test_refusals_store_only_line_option_and_reason():
    result = agent.parse_kdump_conf(b'kdump_pre /secret/pre --password=hunter2\nbogus value\nkdump_pre /other\n')
    assert result['starts'] is False and result['hooks'] == []
    assert result['refusals'] == [{'line': 2, 'option': 'bogus', 'code': 'unknown_option'},
                                  {'line': 3, 'option': 'kdump_pre', 'code': 'duplicate_option'}]
    assert 'hunter2' not in repr(result)


@pytest.mark.parametrize('data', [b'kdump_pre /a\x00\n', b'\xff\n', b'#' * 65537, b'\n' * 2048])
def test_unreadable_or_over_limit_text_yields_nothing(data):
    result = agent.parse_kdump_conf(data)
    assert result == {'parsed': False, 'starts': None, 'refusals': [], 'hooks': [], 'extra_bins': 0,
                      'truncated': False, 'redacted': False}


def test_programs_are_redacted_escaped_and_bounded():
    words = ' '.join(f'w{i}' for i in range(40))
    text = ('kdump_pre /pre --password=hunter2\n'
            'kdump_emergency /em\x1b[31m\n'
            f'kdump_post /{"x" * 600}\n'
            f'core_collector /bin/c {words}\n')
    result = agent.parse_kdump_conf(text.encode())
    pre, collector, post, emergency = result['hooks']
    assert 'hunter2' not in pre['program'] and pre['redacted'] and result['redacted']
    assert emergency['program'] == '/em\\x1b[31m' and not emergency['redacted']
    assert len(post['program']) == 512 and post['program_truncated']
    assert len(collector['args']) == 32 and collector['program_truncated']
    persistence.validate(stored_inventory(text))


def test_inventory_parses_only_kdump_conf_and_never_runs_commands(tmp_path, monkeypatch):
    marker = tmp_path / 'ran'
    conf = tmp_path / 'kdump.conf'
    conf.write_text(f'kdump_pre /usr/bin/touch {marker}\nkdump_post /usr/bin/touch {marker}\n'
                    f'kdump_emergency /usr/bin/touch {marker}\ncore_collector /usr/bin/touch {marker}\n')
    other = tmp_path / 'other.conf'
    other.write_text(f'kdump_pre /usr/bin/touch {marker}\n')
    linked = tmp_path / 'linked'
    linked.symlink_to(conf)
    monkeypatch.setattr(agent, 'PERSISTENCE_ROOTS', ())
    monkeypatch.setattr(agent, 'PERSISTENCE_FILES', (str(conf), str(other), str(linked)))
    monkeypatch.setattr(agent, 'KDUMP_CONF', str(conf))
    plain = agent.persistence_inventory(time.monotonic() + 5)
    assert not any('kdump' in row for row in plain['entries'])
    rows = {r['path']: r for r in agent.persistence_inventory(time.monotonic() + 5, cron_jobs=True)['entries']}
    monkeypatch.setattr(agent, 'KDUMP_CONF', str(linked))
    linked_rows = {r['path']: r for r in agent.persistence_inventory(time.monotonic() + 5, cron_jobs=True)['entries']}
    assert [h['source'] for h in rows[str(conf)]['kdump']['hooks']] == ['kdump_pre', 'core_collector', 'kdump_post',
                                                                         'kdump_emergency']
    assert 'kdump' not in rows[str(other)] and 'kdump' not in linked_rows[str(linked)]
    assert not marker.exists()


def stored_inventory(text, parsed=True):
    entry = {'path': CONF, 'kind': 'regular', 'uid': 0, 'gid': 0, 'mode': 0o644, 'size': len(text), 'mtime_ns': 1,
             'sha256': 'a' * 64}
    if parsed:
        entry['kdump'] = agent.parse_kdump_conf(text.encode())
    return {'scope': [CONF], 'state': 'collected', 'entries': [entry], 'gaps': [], 'skipped': 0, 'missing_roots': []}


def valid():
    return stored_inventory('kdump_pre /pre\nkdump_post /post\nkdump_emergency /em\nextra_bins /a\n')


def refused():
    return stored_inventory('bogus 1\nnet x\n')


def hook(i):
    return lambda k: k['hooks'][i]


BAD = [
    lambda k: k.update(extra=1),
    lambda k: k.pop('redacted'),
    lambda k: k.update(parsed=1),
    lambda k: k.update(starts=False),
    lambda k: k.update(starts=None),
    lambda k: k.update(extra_bins=-1),
    lambda k: k.update(extra_bins=True),
    lambda k: k.update(hooks=[]),
    lambda k: k.update(hooks=k['hooks'][::-1]),
    lambda k: k.update(hooks=k['hooks'] + [copy.deepcopy(k['hooks'][0])]),
    lambda k: k['hooks'].pop(1),
    lambda k: hook(0)(k).update(stage='dump'),
    lambda k: hook(0)(k).update(on_failure='warn'),
    lambda k: hook(0)(k).update(observations=[]),
    lambda k: hook(0)(k).update(observations=['args_rewritten_at_capture', 'pre_failure_skips_dump']),
    lambda k: hook(0)(k).update(observations=['pre_failure_skips_dump', 'pre_failure_skips_dump']),
    lambda k: hook(0)(k).update(observations=[{}]),
    lambda k: hook(0)(k).update(args=['x']),
    lambda k: hook(0)(k).update(line=None),
    lambda k: hook(0)(k).update(line=0),
    lambda k: hook(0)(k).update(line=True),
    lambda k: hook(2)(k).update(line=1),
    lambda k: hook(0)(k).update(program=''),
    lambda k: hook(0)(k).update(program='a\x00'),
    lambda k: hook(0)(k).update(program='x' * 513),
    lambda k: hook(0)(k).update(program=None),
    lambda k: hook(0)(k).update(redacted='no'),
    lambda k: hook(0)(k).pop('program_truncated'),
    lambda k: hook(1)(k).update(args='x'),
    lambda k: hook(1)(k).update(args=['']),
    lambda k: hook(1)(k).update(args=['a'] * 33),
    lambda k: hook(1)(k).update(source='bogus'),
    lambda k: hook(2)(k).update(args=[]),
    lambda k: hook(3)(k).update(observations=[]),
    lambda k: k.update(refusals=[{'line': 1, 'option': 'x', 'code': 'unknown_option'}]),
]
BAD_REFUSED = [
    lambda k: k.update(starts=True),
    lambda k: k.update(hooks=[{}]),
    lambda k: k.update(extra_bins=1),
    lambda k: k['refusals'][0].update(code='other'),
    lambda k: k['refusals'][0].update(line=2),
    lambda k: k['refusals'][0].update(line=0),
    lambda k: k['refusals'][0].update(option=''),
    lambda k: k['refusals'][0].update(option='x' * 65),
    lambda k: k['refusals'][0].update(extra=1),
    lambda k: k.update(refusals=[{'line': 1, 'option': 'x', 'code': 'unknown_option'}] * 65),
    lambda k: k.update(parsed=False),
]


@pytest.mark.parametrize('mutate', BAD)
def test_controller_rejects_malformed_reports(mutate):
    inventory = valid()
    mutate(inventory['entries'][0]['kdump'])
    with pytest.raises(ValueError):
        persistence.validate(inventory)


@pytest.mark.parametrize('mutate', BAD_REFUSED)
def test_controller_rejects_malformed_refusals(mutate):
    inventory = refused()
    persistence.validate(copy.deepcopy(inventory))
    mutate(inventory['entries'][0]['kdump'])
    with pytest.raises(ValueError):
        persistence.validate(inventory)


def test_controller_rejects_kdump_detail_on_other_paths_and_symlinks():
    inventory = valid()
    inventory['entries'][0]['path'] = '/etc/kdump.conf.rpmnew'
    inventory['scope'] = ['/etc/kdump.conf.rpmnew']
    with pytest.raises(ValueError):
        persistence.validate(inventory)
    inventory = valid()
    entry = inventory['entries'][0]
    entry.update(kind='symlink', target='/x')
    del entry['sha256']
    with pytest.raises(ValueError):
        persistence.validate(inventory)
    unparsed = stored_inventory('kdump_pre /a\x00')
    persistence.validate(unparsed)
    unparsed['entries'][0]['kdump']['hooks'] = valid()['entries'][0]['kdump']['hooks']
    with pytest.raises(ValueError):
        persistence.validate(unparsed)


def test_parsed_detail_is_not_part_of_baseline_comparison():
    before = valid()
    after = copy.deepcopy(before)
    after['entries'][0]['kdump']['hooks'][0]['program'] = '/different'
    assert persistence.compare(before, after)['changes'] == []
    assert 'kdump' not in persistence.metadata(after['entries'][0])


def store(inventory):
    with Session() as s:
        s.add(Host(id='one', name='one', address='192.0.2.1', fingerprint='test'))
        s.add(Inspection(id='new', host_id='one', created=time.time() - 1, report={'persistence': inventory}))
        s.commit()


def test_startup_view_shows_hooks_counts_and_search(admin):
    store(valid())
    view = admin.get('/api/hosts/one/security/startup-inventory').json()
    row, = view['items']
    assert row['kdump_state'] == 'parsed'
    assert [(h['source'], h['program']) for h in row['kdump']['hooks']] == [
        ('kdump_pre', '/pre'), ('core_collector', 'makedumpfile'), ('kdump_post', '/post'), ('kdump_emergency', '/em')]
    assert next(c for c in view['catalog'] if c['id'] == 'kdump')['label'].endswith('· 4 parsed hooks')
    assert any('kdump-utils 7bf4714' in gap and 'not yet listed' in gap for gap in view['gaps'])
    assert [r['path'] for r in admin.get('/api/hosts/one/security/startup-inventory?q=kdump_emergency').json()['items']] == [CONF]
    assert admin.get('/api/hosts/one/security/startup-inventory?q=nomatch').json()['items'] == []


def test_startup_view_marks_refused_configuration(admin):
    store(refused())
    view = admin.get('/api/hosts/one/security/startup-inventory').json()
    row, = view['items']
    assert row['kdump']['starts'] is False and row['kdump']['hooks'] == []
    assert next(c for c in view['catalog'] if c['id'] == 'kdump')['label'].endswith('· 0 parsed hooks · refused by kdumpctl')


def test_older_agent_kdump_conf_is_marked_not_reported(admin):
    store(stored_inventory('kdump_pre /a\n', parsed=False))
    view = admin.get('/api/hosts/one/security/startup-inventory').json()
    row, = view['items']
    assert row['kdump_state'] == 'not_reported' and 'kdump' not in row
    assert next(c for c in view['catalog'] if c['id'] == 'kdump')['label'].endswith('not reported by this agent version')


@pytest.mark.parametrize('text, parsed', [
    ('\n' * 2047 + 'kdump_pre /fixture/no-execution', False),
    ('\n' * 2046 + 'kdump_pre /fixture/no-execution\n', True),
    ('\n' * 2046 + 'kdump_pre /fixture/no-execution', True),
    ('\n' * 2047 + 'bogus 1', False),
    ('\n' * 2046 + 'bogus 1', True),
    ('\n' * 2048, False),
])
def test_line_cutoff_counts_an_unterminated_final_line(text, parsed):
    """Review of a2e8f49: 2047 newlines plus a final line is 2048 lines and must not reach the controller."""
    result = agent.parse_kdump_conf(text.encode())
    assert result['parsed'] is parsed
    assert agent_view(text) == contract_view(text)
    persistence.validate(stored_inventory(text))
    if parsed:
        assert max([h['line'] or 0 for h in result['hooks']] + [r['line'] for r in result['refusals']]) == 2047
