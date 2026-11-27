"""Agent-side Dovecot statement reduction, controller validation and Startup Files evaluation (#1620 increment 3)."""
from __future__ import annotations

import copy
import random
import time

import pytest

from app import dovecot_services as ds
from app import persistence, startup_inventory
from target import agent

CONF = '/etc/dovecot/dovecot.conf'
MASTER = '/etc/dovecot/conf.d/10-master.conf'
SECRET = 'hunter2-not-real'


def rebuilt(text):
    return startup_inventory.dovecot_text(agent.parse_dovecot(text.encode()))


def comparable(result):
    return {k: result[k] for k in ('services', 'gaps', 'protocols', 'files', 'root_exec', 'complete', 'config_accepted', 'service_sha256')}


STOCK_LIKE = f'''# Ubuntu-style dovecot.conf
protocols = imap pop3 # trailing comment
!include conf.d/*.conf
!include_try local.conf
ssl_key_password = {SECRET}
passdb {{
  driver = sql
  args = /etc/dovecot/dovecot-sql.conf.ext
}}
'''
MASTER_TEXT = f'''service imap-login {{
  inet_listener imap {{
    port = 143
  }}
}}
service custom {{
  executable = /usr/local/bin/run-me --token={SECRET} \\
    extra
  user = nobody
  process_min_avail = 1
}}
service "quoted name" {{
  executable = "script /usr/local/bin/post #not-a-comment"
  user = $default_internal_user
  drop_priv_before_exec = yes
}}
service imap {{
  executable = imap /usr/local/bin/postlogin
  protocol = imap
}}
service lmtp {{
  executable = /usr/local/bin/lmtp-wrap
}}
ssl_cert = </etc/dovecot/private/dovecot.pem
'''


def files_raw(extra=None):
    files = {CONF: STOCK_LIKE, MASTER: MASTER_TEXT, '/etc/dovecot/local.conf': None}
    files.update(extra or {})
    return files


def test_rebuilt_text_evaluates_exactly_like_the_captured_text():
    raw = files_raw()
    rebuilt_files = {p: (None if t is None else rebuilt(t)) for p, t in raw.items()}
    globs = {'/etc/dovecot/conf.d/*.conf': [MASTER]}
    expected = ds.evaluate(files=raw, globs=globs)
    actual = ds.evaluate(files=rebuilt_files, globs=globs)
    assert expected['services'] and actual['root_exec']
    # The executable's credential is redacted by the agent; everything else is identical.
    custom = next(r for r in actual['services'] if r['service'] == 'custom')
    assert custom['argv'] == ['/usr/local/bin/run-me', '--token=[REDACTED]', 'extra'] and custom['exec_account'] == 'root'
    expected_custom = next(r for r in expected['services'] if r['service'] == 'custom')
    assert expected_custom['argv'][1] == f'--token={SECRET}'
    def scrub(result):
        text = repr(comparable(result)).replace(f'--token={SECRET}', '--token=[REDACTED]')
        return text.replace(ds.evaluate(files=raw, globs=globs)['service_sha256'], 'sha')
    assert scrub(actual).replace(actual['service_sha256'], 'sha') == scrub(expected)
    assert SECRET not in repr(agent.parse_dovecot(STOCK_LIKE.encode())) + repr(agent.parse_dovecot(MASTER_TEXT.encode()))


def _well_formed(rng, index):
    lines = []
    for n in range(rng.randint(1, 6)):
        lines.append(rng.choice(['', '# c', 'protocols = $protocols imap', 'protocols = lmtp pop3', 'default_internal_user = mail', 'mail_location = maildir:~/M']))
        lines.append(f'service {rng.choice(["imap", "pop3", "lmtp", "custom" + str(n), "health-check"])} {{ # open')
        for key in rng.sample(['executable', 'user', 'drop_priv_before_exec', 'process_min_avail', 'protocol', 'group', 'chroot', 'vsz_limit'], rng.randint(1, 5)):
            value = {'executable': rng.choice(['/usr/local/bin/x a b', 'script /bin/y', '"script-login /bin/z"', 'imap', "'/opt/q #1'", '/bin/c \\\n  d']),
                     'user': rng.choice(['nobody', 'root', '$default_internal_user', '$default_login_user', 'mail', '']),
                     'drop_priv_before_exec': rng.choice(['yes', 'no']), 'process_min_avail': rng.choice(['0', '1', '2', 'x']),
                     'protocol': rng.choice(['imap', 'pop3', 'lmtp', '']), 'group': rng.choice(['mail', '']), 'chroot': rng.choice(['', 'login']),
                     'vsz_limit': '256M'}[key]
            lines.append(f'  {key} = {value}' + rng.choice(['', ' # trailing']))
        if rng.random() < 0.5:
            lines += ['  unix_listener x {', '    mode = 0600', '  }']
        lines.append('}')
    return '\n'.join(lines) + '\n'


def _random_config(rng, index):
    if index % 2:
        return _well_formed(rng, index)
    keys = ['executable', 'user', 'drop_priv_before_exec', 'process_min_avail', 'protocol', 'group', 'chroot', 'args', 'port', 'mode']
    values = ['/usr/local/bin/x a', 'script /bin/y', 'imap', '"q # v"', "'single'", 'nobody', '$default_login_user', 'yes', '1', '0',
              '', '<file', 'a\\', 'x {', '"unterminated', 'v # c', '\\"esc\\"']
    lines = []
    depth = 0
    for _ in range(rng.randint(1, 30)):
        choice = rng.random()
        if choice < 0.15:
            lines.append(f'service {rng.choice(["imap", "pop3", "custom", "a" + str(index), chr(34) + "n m" + chr(34), ""])} {{')
            depth += 1
        elif choice < 0.2:
            lines.append(rng.choice(['inet_listener x {', 'protocol imap {', 'local 10.0.0.0/8 {', 'passdb {', 'bad line here', '{', 'x = y {']))
            depth += 1
        elif choice < 0.32 and depth:
            lines.append('}')
            depth -= 1
        elif choice < 0.36:
            lines.append(rng.choice(['!include_try missing.conf', '!include', '!include_x a', '!include_try "q.conf"']))
        elif choice < 0.42:
            lines.append(rng.choice(['', '# comment', '   ', '\t# x']))
        elif choice < 0.5:
            lines.append(rng.choice(['protocols = $protocols imap', 'protocols = lmtp', 'default_internal_user = mail', 'libexec_dir = /opt/dc']))
        else:
            lines.append(f'{"  " * depth}{rng.choice(keys)} = {rng.choice(values)}' + rng.choice(['', ' # c', ' \\']))
    lines += ['}'] * (depth if rng.random() < 0.8 else 0)
    return '\n'.join(lines) + rng.choice(['\n', '', '\n\n'])


@pytest.mark.parametrize('seed', range(4))
def test_seeded_differential_against_the_contract(seed):
    rng = random.Random(1620 + seed)
    for index in range(150):
        text = _random_config(rng, index)
        files = {CONF: text, '/etc/dovecot/missing.conf': None, '/etc/dovecot/q.conf': None}
        expected = ds.evaluate(files=files, passwd_text='root:x:0:0::/:/bin/sh\nnobody:x:65534:65534::/:/bin/false\nmail:x:8:8::/:/bin/false\n')
        rebuilt_files = dict(files, **{CONF: rebuilt(text)})
        actual = ds.evaluate(files=rebuilt_files, passwd_text='root:x:0:0::/:/bin/sh\nnobody:x:65534:65534::/:/bin/false\nmail:x:8:8::/:/bin/false\n')
        if '[REDACTED]' in repr(actual):
            continue
        assert comparable(actual) == comparable(expected), text


def test_values_outside_the_contract_are_dropped_and_executables_redacted():
    report = agent.parse_dovecot(f'auth_mechanisms = plain\npassdb {{\n  args = password={SECRET}\n}}\nservice x {{\n  executable = /bin/x --password {SECRET}\n}}\n'.encode())
    assert SECRET not in repr(report)
    assert report['dropped'] == 2 and report['parsed'] and not report['truncated']
    setting = [s for s in report['statements'] if s['op'] == 'set']
    assert [s['value'] for s in setting[:2]] == [None, None]
    assert setting[2]['redacted'] and setting[2]['value'] == '/bin/x --password [REDACTED]'
    persistence.validate_dovecot(report, CONF)


@pytest.mark.parametrize('data', [b'a = b\x00', b'#' * (1024 * 1024 + 1)])
def test_nul_and_over_limit_files_are_not_parsed(data):
    report = agent.parse_dovecot(data)
    assert report == {'parsed': False, 'statements': [], 'truncated': False, 'dropped': 0}
    persistence.validate_dovecot(report, CONF)


def test_statement_limit_truncates_and_view_blocks():
    report = agent.parse_dovecot(('x = 1\n' * (agent.DOVECOT_STATEMENT_LIMIT + 5)).encode())
    assert report['truncated'] and len(report['statements']) == agent.DOVECOT_STATEMENT_LIMIT
    persistence.validate_dovecot(report, CONF)


VALID = {'parsed': True, 'truncated': False, 'dropped': 0, 'statements': [
    {'line': 1, 'op': 'open', 'kind': 'service', 'name': 'x'},
    {'line': 2, 'op': 'set', 'key': 'executable', 'value': '/bin/x', 'file': False, 'redacted': False},
    {'line': 3, 'op': 'close'}]}


@pytest.mark.parametrize('mutate', [
    lambda r: r.update(extra=1),
    lambda r: r.update(parsed=False),
    lambda r: r['statements'][1].update(key='args'),
    lambda r: r['statements'][1].update(file=True),
    lambda r: r['statements'][1].update(value='a\nb'),
    lambda r: r['statements'][1].update(redacted=1),
    lambda r: r['statements'][0].update(kind='bad kind'),
    lambda r: r['statements'][2].update(line=2),
    lambda r: r['statements'][2].update(op='unknown'),
    lambda r: r['statements'][2].update(pattern='x'),
    lambda r: r['statements'].append({'line': 4, 'op': 'include', 'optional': 'no', 'pattern': 'a'}),
    lambda r: r['statements'].append({'line': 4, 'op': 'include', 'optional': True, 'pattern': ' '}),
    lambda r: r['statements'].append({'line': 4, 'op': 'set', 'key': 'user', 'value': None, 'file': False, 'redacted': True}),
    lambda r: r.update(dropped=-1),
])
def test_validation_rejects_malformed_reports(mutate):
    persistence.validate_dovecot(copy.deepcopy(VALID), CONF)
    report = copy.deepcopy(VALID)
    mutate(report)
    with pytest.raises(ValueError):
        persistence.validate_dovecot(report, CONF)


def test_validation_rejects_statements_outside_dovecot_and_on_symlinks():
    with pytest.raises(ValueError):
        persistence.validate_dovecot(copy.deepcopy(VALID), '/etc/dovecotx/a.conf')
    inventory = _inventory({CONF: 'service x {\n}\n'})
    inventory['entries'][0].update(kind='symlink', target='/x')
    inventory['entries'][0].pop('sha256')
    with pytest.raises(ValueError):
        persistence.validate(inventory)


def _row(path, text):
    return {'path': path, 'kind': 'regular', 'uid': 0, 'gid': 0, 'mode': 0o644, 'size': len(text), 'mtime_ns': 1,
            'sha256': 'a' * 64, 'dovecot': agent.parse_dovecot(text.encode())}


def _inventory(texts, state='collected'):
    return {'scope': ['/etc/dovecot'], 'state': state, 'entries': [_row(p, t) for p, t in texts.items()],
            'gaps': [] if state == 'collected' else ['/etc/dovecot/x: PermissionError'], 'skipped': 0 if state == 'collected' else 1,
            'missing_roots': []}


def test_view_evaluates_in_directory_includes_from_a_complete_collection():
    inventory = _inventory({CONF: STOCK_LIKE, MASTER: MASTER_TEXT, '/etc/dovecot/conf.d/.hidden.conf': 'service h {\n executable = /bin/h\n}\n'})
    persistence.validate(inventory)
    view = startup_inventory.dovecot_view(inventory)
    names = {s['service']: s for s in view['services']}
    assert set(names) == {'custom', 'quoted name', 'imap', 'lmtp'}
    assert names['custom']['exec_account'] == 'root' and names['custom']['starts'] == 'master_start'
    assert names['quoted name']['drop_priv_before_exec'] and names['quoted name']['wrapper'] == 'script'
    assert names['imap']['enabled'] and not names['lmtp']['enabled'] or names['lmtp']['protocol'] == 'lmtp'
    assert view['files'] == [CONF, MASTER] and view['config_accepted'] is None
    assert view['complete'] is False and view['authorizes_response'] is False and view['origin'] == 'not_assessed'
    codes = {g['code'] for g in view['gaps']}
    assert 'passwd_group_not_captured' in codes and 'file_value_not_assessed' in codes
    assert SECRET not in repr(view)


def test_includes_outside_the_directory_and_incomplete_collections_stay_unobserved():
    stock = _inventory({CONF: '!include_try /usr/share/dovecot/protocols.d/*.protocol\n!include conf.d/*.conf\n', MASTER: MASTER_TEXT})
    view = startup_inventory.dovecot_view(stock)
    assert view['config_accepted'] is False and view['services'] == []
    assert any(g['code'] == 'unobserved_glob' and g['blocking'] and g['glob'].startswith('/usr/share/dovecot') for g in view['gaps'])
    partial = _inventory({CONF: '!include_try local.conf\n', MASTER: MASTER_TEXT}, state='incomplete')
    view = startup_inventory.dovecot_view(partial)
    assert view['config_accepted'] is False and any(g['code'] == 'unobserved_file' for g in view['gaps'])
    complete = _inventory({CONF: '!include_try local.conf\n'})
    assert startup_inventory.dovecot_view(complete)['config_accepted'] is None
    required = _inventory({CONF: '!include local.conf\n'})
    assert any(g['code'] == 'include_not_found' for g in startup_inventory.dovecot_view(required)['gaps'])


def test_unparsed_truncated_and_older_agent_files_are_explained():
    inventory = _inventory({CONF: '!include a.conf\n!include b.conf\n', '/etc/dovecot/a.conf': ''})
    old = {k: v for k, v in _row('/etc/dovecot/b.conf', '').items() if k != 'dovecot'}
    inventory['entries'].append(old)
    view = startup_inventory.dovecot_view(inventory)
    assert view['config_accepted'] is False and any(g['code'] == 'unobserved_file' and g['path'] == '/etc/dovecot/b.conf' for g in view['gaps'])
    assert startup_inventory.dovecot_state(old) == 'not_reported'
    truncated = _row('/etc/dovecot/c.conf', '')
    truncated['dovecot']['truncated'] = True
    inventory['entries'].append(truncated)
    assert any(g['code'] == 'statements_truncated' for g in startup_inventory.dovecot_view(inventory)['gaps'])
    unparsed = _row('/etc/dovecot/d.conf', 'a\x00')
    assert startup_inventory.dovecot_state(unparsed) == 'unparsed'
    labels = {r['id']: r['label'] for r in startup_inventory.catalog_rows(inventory)}
    assert labels['dovecot'].endswith('· 3 parsed files · not reported by this agent version')


def test_agent_parses_the_hashed_bytes_without_running_anything(tmp_path, monkeypatch):
    marker = tmp_path / 'ran'
    root = tmp_path / 'dovecot'
    (root / 'conf.d').mkdir(parents=True)
    (root / 'dovecot.conf').write_text('!include conf.d/*.conf\n')
    (root / 'conf.d' / '10-master.conf').write_text(f'service custom {{\n  executable = /usr/bin/touch {marker}\n  process_min_avail = 1\n}}\n')
    (root / 'private.key').write_text(f'-----BEGIN PRIVATE KEY-----\n{SECRET}\n-----END PRIVATE KEY-----\n')
    (root / 'link.conf').symlink_to(root / 'dovecot.conf')
    monkeypatch.setattr(agent, 'PERSISTENCE_ROOTS', (str(root),))
    monkeypatch.setattr(agent, 'PERSISTENCE_FILES', ())
    monkeypatch.setattr(agent, 'DOVECOT_DIR', str(root))
    result = agent.persistence_inventory(time.monotonic() + 5, cron_jobs=True)
    assert not marker.exists() and SECRET not in repr(result)
    rows = {r['path']: r for r in result['entries']}
    assert 'dovecot' not in rows[str(root / 'link.conf')]
    assert all('dovecot' in rows[str(root / n)] for n in ('dovecot.conf', 'conf.d/10-master.conf', 'private.key'))
    text = repr(result).replace(str(root), '/etc/dovecot')
    inventory = eval(text)  # noqa: S307 - repr of plain literals produced above
    inventory['scope'] = ['/etc/dovecot']
    persistence.validate(inventory)
    view = startup_inventory.dovecot_view(inventory)
    assert [s['service'] for s in view['services']] == ['custom'] and view['services'][0]['exec_account'] == 'root'
    without = agent.persistence_inventory(time.monotonic() + 5, cron_jobs=False)
    assert all('dovecot' not in r for r in without['entries'])


@pytest.mark.parametrize('include', ['!include_try linked/local.conf', '!include_try linked/*.conf', '!include_try linked/sub/*.conf',
                                     '!include linked/local.conf', '!include linked/*.conf'])
def test_includes_behind_a_recorded_symlink_stay_unobserved(include):
    inventory = _inventory({CONF: include + '\n', MASTER: MASTER_TEXT})
    inventory['entries'].append({'path': '/etc/dovecot/linked', 'kind': 'symlink', 'uid': 0, 'gid': 0, 'mode': 0o777, 'size': 4,
                                 'mtime_ns': 1, 'target': '/srv/dovecot'})
    persistence.validate(inventory)
    view = startup_inventory.dovecot_view(inventory)
    assert view['config_accepted'] is False and view['services'] == []
    assert any(g['code'] in ('unobserved_file', 'unobserved_glob') and g['blocking'] for g in view['gaps'])
    # A sibling path without a symlink ancestor is still an observed absence.
    plain = _inventory({CONF: include.replace('linked/', 'other/') + '\n'})
    plain['entries'] += inventory['entries'][2:]
    result = startup_inventory.dovecot_view(plain)
    assert not any(g['code'] in ('unobserved_file', 'unobserved_glob') for g in result['gaps'])
