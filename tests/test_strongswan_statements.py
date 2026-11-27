"""Agent-side swanctl statement reduction, controller validation and Startup Files evaluation (#1624 increment 3)."""
from __future__ import annotations

import copy
import random
import time

import pytest

from app import persistence, startup_inventory
from app import strongswan_updown as su
from target import agent

CONF = '/etc/swanctl/swanctl.conf'
SITE = '/etc/swanctl/conf.d/site.conf'
RPM_CONF = '/etc/strongswan/swanctl/swanctl.conf'
SECRET = 'hunter2-not-real'

STOCK_LIKE = f'''# Ubuntu-style swanctl.conf
connections {{
  site {{
    local_addrs = 192.0.2.1
    children {{
      net {{
        updown = /usr/local/bin/up.sh "two words" ; logger $PLUTO_VERB # trailing comment
      }}
      quiet {{
        esp_proposals = aes128-sha256
      }}
    }}
  }}
}}
secrets {{
  ike-site {{
    id = site
    secret = {SECRET}
  }}
}}
include conf.d/*.conf
'''
SITE_TEXT = '''connections {
  site { children { net { updown = /usr/local/bin/override } } }
  other { children { a { updown = "multi
line" } b { updown = /bin/true } } }
}
'''


def rebuilt(text):
    return startup_inventory.swanctl_text(agent.parse_swanctl(text.encode()))


def comparable(result):
    return {k: result[k] for k in ('commands', 'gaps', 'notes', 'files', 'root_commands', 'complete', 'command_sha256')}


def test_rebuilt_text_evaluates_exactly_like_the_captured_text():
    raw = {CONF: STOCK_LIKE, SITE: SITE_TEXT}
    directories = {'/etc/swanctl/conf.d': ['site.conf']}
    expected = su.evaluate(files=raw, directories=directories)
    actual = su.evaluate(files={p: rebuilt(t) for p, t in raw.items()}, directories=directories)
    assert comparable(actual) == comparable(expected)
    commands = {(c['connection'], c['child']): c for c in actual['commands']}
    assert commands['site', 'net']['command'] == '/usr/local/bin/override' and commands['site', 'net']['file'] == SITE
    assert commands['other', 'a']['connection_discarded'] and not commands['other', 'b']['runs']
    assert SECRET not in repr(agent.parse_swanctl(STOCK_LIKE.encode()))


FRAGMENTS = ['connections', 'children', 'c1', 'c2', 'k', '"q n"', '{', '}', '{', '}', '=', 'updown', 'updown', 'updown',
             'include', 'inc/*.conf', 'inc/a.conf', '"inc/b.conf"', '/bin/x', 'a;b', '$V', '"x y"', '"a\\tb"', '"m\nn"',
             '"esc\\q"', '"open', '#c', '\n', '\n', '\n', ' ', ' ', ' ', 'secret', '"multi\nline"', 'include', '=', '"inc/c.conf"', '"include"', '"include" inc/a.conf']


def _text(rng):
    return ''.join(rng.choice(FRAGMENTS) + rng.choice(['', ' ', '\n']) for _ in range(rng.randint(0, 60)))


def _structured(rng):
    lines = ['connections {']
    for c in range(rng.randint(0, 3)):
        lines.append(f' c{c} {{ children {{')
        for k in range(rng.randint(0, 3)):
            value = rng.choice(['/bin/up', '"x y" z', 'a;b $V', '"m\nn"', '', '"q \\" r"'])
            lines.append(f'  k{k} {{ updown = {value} }}')
        lines.append(' } }')
    lines.append('}')
    if rng.random() < 0.5:
        lines.insert(rng.randrange(len(lines)), rng.choice(['include inc/*.conf', 'include inc/a.conf', '}', '{', 'x = y {']))
    return '\n'.join(lines) + '\n'


@pytest.mark.parametrize('seed', range(6))
def test_seeded_differential_against_the_contract(seed):
    rng = random.Random(seed)
    for _ in range(400):
        maker = _text if rng.random() < 0.5 else _structured
        raw = {CONF: maker(rng), '/etc/swanctl/inc/a.conf': maker(rng), '/etc/swanctl/inc/b.conf': _structured(rng),
               '/etc/swanctl/inc/c.conf': None}
        directories = {'/etc/swanctl/inc': ['a.conf', 'b.conf', '.hidden.conf']}
        raw['/etc/swanctl/inc/.hidden.conf'] = _structured(rng)
        expected = su.evaluate(files=raw, directories=directories)
        reports = {p: (None if t is None else agent.parse_swanctl(t.encode())) for p, t in raw.items()}
        for path, report in reports.items():
            if report is not None:
                persistence.validate_swanctl(report, path)
        rebuilt_files = {p: (None if r is None else startup_inventory.swanctl_text(r)) for p, r in reports.items()}
        assert comparable(su.evaluate(files=rebuilt_files, directories=directories)) == comparable(expected), raw


def test_values_outside_updown_are_dropped_and_commands_redacted():
    report = agent.parse_swanctl(f'connections {{ c {{ children {{ k {{ updown = /bin/up --password {SECRET} }} }} '
                                 f'pools = {SECRET} }} }}\nsecrets {{ eap {{ secret = "{SECRET}" }} }}\n'.encode())
    assert SECRET not in repr(report) and report['dropped'] == 2
    updown = next(s for s in report['statements'] if s.get('key') == 'updown')
    assert updown['value'] == '/bin/up --password [REDACTED]' and updown['redacted'] is True
    assert all(s['value'] is None for s in report['statements'] if s['op'] == 'set' and s['key'] != 'updown')
    persistence.validate_swanctl(report, CONF)


@pytest.mark.parametrize('data', [b'a\x00b', b'\xff\xfe connections {}', b'#' * (1024 * 1024 + 1)])
def test_nul_non_utf8_and_over_limit_files_are_not_parsed(data):
    assert agent.parse_swanctl(data) == {'parsed': False, 'statements': [], 'truncated': False, 'dropped': 0}


@pytest.mark.parametrize('text,code,line', [('a {\n "x\n', 'unterminated_quote', 2), ('a { b = "x\\q" }', 'escape_sequence', 1),
                                            ('a {\n} }\n= x\n', 'syntax', 3), ('a = b {', 'syntax', 1)])
def test_lexing_and_syntax_gaps_keep_their_code_and_line(text, code, line):
    report = agent.parse_swanctl(text.encode())
    assert report['statements'][-1] == {'line': line, 'op': 'error', 'code': code}
    persistence.validate_swanctl(report, CONF)
    gaps = su.evaluate(files={CONF: startup_inventory.swanctl_text(report)})['gaps']
    assert gaps == su.evaluate(files={CONF: text})['gaps']


def test_over_limit_values_and_statement_counts_truncate_and_the_view_blocks():
    long = agent.parse_swanctl(('connections { c { children { k { updown = /bin/' + 'x' * 600 + ' } } } }\n').encode())
    many = agent.parse_swanctl(('a {\n}\n' * 1001).encode())
    assert long['truncated'] and many['truncated'] and len(many['statements']) == 2000
    for report in (long, many):
        persistence.validate_swanctl(report, CONF)
    inventory = _inventory({CONF: 'include conf.d/*.conf\n'})
    inventory['entries'].append(dict(_row(SITE, ''), strongswan=long))
    view = startup_inventory.strongswan_view(inventory, CONF)
    assert any(g['code'] == 'statements_truncated' and g['blocking'] and g['path'] == SITE for g in view['gaps'])
    assert any(g['code'] == 'file_not_observed' and g['file'] == SITE for g in view['gaps']) and not view['config_complete']


VALID = agent.parse_swanctl(STOCK_LIKE.encode())


def _set(report, index, **change):
    report['statements'][index].update(change)


@pytest.mark.parametrize('mutate', [
    lambda r: r.update(extra=1),
    lambda r: r.update(parsed='yes'),
    lambda r: r.update(dropped=-1),
    lambda r: r.update(parsed=False),
    lambda r: r['statements'].append({'line': 1, 'op': 'close'}),
    lambda r: r['statements'].append({'line': 99, 'op': 'shell'}),
    lambda r: _set(r, 0, line=0),
    lambda r: _set(r, 1, name='x\x00'),
    lambda r: _set(r, 1, extra=True),
    lambda r: _set(r, 2, value='kept'),
    lambda r: _set(r, 2, redacted=True),
    lambda r: _set(r, 5, value=None),
    lambda r: _set(r, 5, value='x' * 513),
    lambda r: _set(r, 5, redacted='no'),
    lambda r: r['statements'].insert(3, {'line': 6, 'op': 'error', 'code': 'syntax'}),
    lambda r: r['statements'].append({'line': 99, 'op': 'error', 'code': 'unterminated_quote'}),
    lambda r: r['statements'].append({'line': 99, 'op': 'error', 'code': 'other'}),
    lambda r: r['statements'].append({'line': 99, 'op': 'include', 'pattern': None}),
    lambda r: r['statements'].append({'line': 99, 'op': 'include', 'pattern': 'x\x00'}),
    lambda r: r.update(statements=[{'line': 1, 'op': 'close'}] * 2001),
])
def test_validation_rejects_malformed_reports(mutate):
    report = copy.deepcopy(VALID)
    assert [s['op'] for s in report['statements'][:3]] == ['open', 'open', 'set'] and report['statements'][5]['key'] == 'updown'
    persistence.validate_swanctl(copy.deepcopy(report), CONF)
    mutate(report)
    with pytest.raises(ValueError):
        persistence.validate_swanctl(report, CONF)


@pytest.mark.parametrize('path', ['/etc/swanctl/x509/site.pem', '/etc/swanctlx/a.conf', '/etc/strongswan/strongswan.conf',
                                  '/etc/strongswan/strongswan.d/charon.conf'])
def test_validation_rejects_statements_outside_the_swanctl_files(path):
    with pytest.raises(ValueError):
        persistence.validate_swanctl(copy.deepcopy(VALID), path)
    inventory = _inventory({CONF: 'a {\n}\n'})
    inventory['entries'][0].update(kind='symlink', target='/x')
    inventory['entries'][0].pop('sha256')
    with pytest.raises(ValueError):
        persistence.validate(inventory)


def _row(path, text):
    row = {'path': path, 'kind': 'regular', 'uid': 0, 'gid': 0, 'mode': 0o644, 'size': len(text), 'mtime_ns': 1, 'sha256': 'a' * 64}
    if persistence.swanctl_reads(path):
        row['strongswan'] = agent.parse_swanctl(text.encode())
    return row


def _inventory(texts, state='collected'):
    return {'scope': ['/etc/swanctl', '/etc/strongswan'], 'state': state, 'entries': [_row(p, t) for p, t in texts.items()],
            'gaps': [] if state == 'collected' else ['/etc/swanctl/x: PermissionError'], 'skipped': 0 if state == 'collected' else 1,
            'missing_roots': ['/etc/strongswan']}


def test_view_evaluates_includes_from_a_complete_collection():
    inventory = _inventory({CONF: STOCK_LIKE, SITE: SITE_TEXT, '/etc/swanctl/conf.d/.hidden.conf': SITE_TEXT,
                            '/etc/swanctl/private/site.key': '-----BEGIN PRIVATE KEY-----\n'})
    persistence.validate(inventory)
    view = startup_inventory.strongswan_view(inventory, CONF)
    commands = {(c['connection'], c['child']): c for c in view['commands']}
    assert set(commands) == {('site', 'net'), ('other', 'a'), ('other', 'b')}
    assert commands['site', 'net']['argv'] == ['/bin/sh', '-c', '2>&1 /usr/local/bin/override'] and commands['site', 'net']['uid'] == 0
    assert commands['other', 'a']['connection_discarded'] and not commands['other', 'a']['runs']
    assert view['files'] == [CONF, SITE] and view['config_complete'] is True
    assert view['complete'] is False and view['authorizes_response'] is False and view['origin'] == 'not_assessed'
    assert [g['code'] for g in view['gaps']] == ['charon_uid_assumed'] and not view['gaps'][0]['blocking']
    assert {n['code'] for n in view['notes']} >= {'updown_plugin_load_not_assessed', 'connection_discarded'}
    assert SECRET not in repr(view)
    # A missing include directory in a complete collection includes nothing, as swanctl does.
    alone = startup_inventory.strongswan_view(_inventory({CONF: STOCK_LIKE}), CONF)
    assert alone['config_complete'] is True and [c['command'] for c in alone['commands']][0].startswith('/usr/local/bin/up.sh two words')


def test_incomplete_collections_outside_paths_symlinks_and_other_files_stay_unobserved():
    partial = startup_inventory.strongswan_view(_inventory({CONF: STOCK_LIKE, SITE: SITE_TEXT}, state='incomplete'), CONF)
    assert not partial['config_complete'] and any(g['code'] == 'directory_not_observed' and g['blocking'] for g in partial['gaps'])
    for include, path in (('/etc/ipsec.d/x.conf', '/etc/ipsec.d/x.conf'), ('conf.d/site.txt', '/etc/swanctl/conf.d/site.txt'),
                          ('conf.d/link.conf', '/etc/swanctl/conf.d/link.conf'), ('linked/*.conf', '/etc/swanctl/linked/a.conf')):
        inventory = _inventory({CONF: f'include {include}\n', '/etc/swanctl/conf.d/site.txt': 'connections {}\n',
                                '/etc/swanctl/linked/a.conf': 'connections {}\n'})
        inventory['entries'].append({'path': '/etc/swanctl/conf.d/link.conf', 'kind': 'symlink', 'uid': 0, 'gid': 0, 'mode': 0o777,
                                     'size': 3, 'mtime_ns': 1, 'target': '/tmp/x.conf'})
        inventory['entries'].append({'path': '/etc/swanctl/linked', 'kind': 'symlink', 'uid': 0, 'gid': 0, 'mode': 0o777,
                                     'size': 3, 'mtime_ns': 1, 'target': '/srv'})
        persistence.validate(inventory)
        view = startup_inventory.strongswan_view(inventory, CONF)
        assert not view['config_complete'], include
        assert any(g['code'] in ('file_not_observed', 'directory_not_observed') for g in view['gaps']), include
        assert path not in view['files']


def test_rpm_layout_and_older_agent_files_are_explained():
    inventory = _inventory({RPM_CONF: 'include conf.d/*.conf\n', '/etc/strongswan/swanctl/conf.d/a.conf': SITE_TEXT,
                            '/etc/strongswan/strongswan.conf': 'charon { plugins { updown { load = no } } }\n'})
    inventory['missing_roots'] = ['/etc/swanctl']
    persistence.validate(inventory)
    assert 'strongswan' not in inventory['entries'][2]
    view = startup_inventory.strongswan_view(inventory, RPM_CONF)
    assert {c['connection'] for c in view['commands']} == {'site', 'other'} and view['config_complete']
    old = {k: v for k, v in _row(SITE, '').items() if k != 'strongswan'}
    debian = _inventory({CONF: 'include conf.d/*.conf\n'})
    debian['entries'].append(old)
    assert startup_inventory.strongswan_state(old) == 'not_reported'
    assert startup_inventory.strongswan_state(_row(SITE, 'a\x00')) == 'unparsed'
    view = startup_inventory.strongswan_view(debian, CONF)
    assert any(g['code'] == 'file_not_observed' and g['file'] == SITE for g in view['gaps'])
    labels = {r['id']: r['label'] for r in startup_inventory.catalog_rows(debian)}
    assert labels['strongswan'].endswith('· 1 parsed file · not reported by this agent version')


def test_agent_parses_the_hashed_bytes_without_running_anything(tmp_path, monkeypatch):
    marker = tmp_path / 'ran'
    root = tmp_path / 'swanctl'
    (root / 'conf.d').mkdir(parents=True)
    (root / 'private').mkdir()
    (root / 'swanctl.conf').write_text(f'include conf.d/*.conf\nsecrets {{ ike {{ secret = {SECRET} }} }}\n')
    (root / 'conf.d' / 'site.conf').write_text(f'connections {{ s {{ children {{ n {{ updown = /usr/bin/touch {marker} }} }} }} }}\n')
    (root / 'private' / 'site.key').write_text(f'-----BEGIN PRIVATE KEY-----\n{SECRET}\n-----END PRIVATE KEY-----\n')
    (root / 'link.conf').symlink_to(root / 'swanctl.conf')
    monkeypatch.setattr(agent, 'PERSISTENCE_ROOTS', (str(root),))
    monkeypatch.setattr(agent, 'PERSISTENCE_FILES', ())
    monkeypatch.setattr(agent, 'SWANCTL_DIRS', (str(root),))
    result = agent.persistence_inventory(time.monotonic() + 5, cron_jobs=True)
    assert not marker.exists() and SECRET not in repr(result)
    rows = {r['path']: r for r in result['entries']}
    assert 'strongswan' not in rows[str(root / 'link.conf')] and 'strongswan' not in rows[str(root / 'private' / 'site.key')]
    assert all('strongswan' in rows[str(root / n)] for n in ('swanctl.conf', 'conf.d/site.conf'))
    inventory = eval(repr(result).replace(str(root), '/etc/swanctl'))  # noqa: S307 - repr of plain literals produced above
    inventory['scope'] = ['/etc/swanctl']
    persistence.validate(inventory)
    view = startup_inventory.strongswan_view(inventory, CONF)
    assert [(c['connection'], c['child'], c['uid']) for c in view['commands']] == [('s', 'n', 0)] and view['config_complete']
    without = agent.persistence_inventory(time.monotonic() + 5, cron_jobs=False)
    assert all('strongswan' not in r for r in without['entries'])


def test_metadata_comparisons_ignore_parsed_statements():
    row = _row(CONF, STOCK_LIKE)
    assert 'strongswan' not in persistence.metadata(row) and persistence.metadata(row)['sha256'] == row['sha256']
