"""Agent-side dhcpd.conf token reduction, controller validation and Startup Files evaluation (#1593 increment 3)."""
from __future__ import annotations

import copy
import random
import time

import pytest

from app import dhcpd_execute as de
from app import persistence, startup_inventory
from target import agent

CONF = '/etc/dhcp/dhcpd.conf'
SECRET = 'c2VjcmV0LW5vdC1yZWFs'

STOCK_LIKE = f'''# dhcpd.conf
option domain-name "example.org";
option domain-name-servers ns1.example.org, ns2.example.org;
default-lease-time 600;
key "omapi-key" {{ algorithm hmac-md5; secret "{SECRET}"; }}
key ddns {{ algorithm hmac-sha256; secret {SECRET}; }}
execute("/usr/local/sbin/boot-hook", "start");
subnet 10.5.5.0 netmask 255.255.255.224 {{
  range 10.5.5.26 10.5.5.30;
  on commit {{
    set ClientIP = binary-to-ascii(10, 8, ".", leased-address);
    execute("/usr/local/bin/lease-hook", "commit", ClientIP, pick-first-value(option host-name, "none"));
  }}
  on release or expiry {{
    if option dhcp-client-identifier = "x\\001y" {{ execute("notify", "gone"); }}
    elsif exists host-name {{ execute("/bin/true"); }}
    else {{ execute("/bin/false", "a\\"b\\\\c"); }}
  }}
}}
class "phones" {{
  match if substring(option vendor-class-identifier, 0, 4) = "MSFT";
  on commit {{ execute("/usr/local/bin/class-hook"); }}
}}
host printer {{ hardware ethernet 08:00:07:26:c0:a5; on commit {{ execute("/usr/local/bin/host-hook", "p"); }} }}
switch (option host-name) {{ case "a": execute("/bin/case-a"); default: execute("/bin/case-default"); }}
'''


def _norm(result):
    out = copy.deepcopy(result)
    out['gaps'] = sorted((g['code'], g['line'], g['blocking']) for g in out['gaps'])
    return out


def _via_agent(text):
    report = agent.parse_dhcpd(text.encode())
    row = {'path': CONF, 'kind': 'regular', 'dhcpd': report}
    persistence.validate_dhcpd(report, CONF)
    rebuilt = de.assess_config([{'path': CONF, 'state': 'regular', 'text': startup_inventory.dhcpd_text(report)}])
    lexed = [{'code': g['code'], 'line': g['line'], 'blocking': True} for g in report['lex_gaps'] if g['code'] != 'retention_bounded']
    rebuilt['gaps'] += lexed
    rebuilt['complete'] = rebuilt['complete'] and not lexed
    return report, row, rebuilt


def test_rebuilt_tokens_evaluate_exactly_like_the_captured_text():
    raw = de.assess_config([{'path': CONF, 'state': 'regular', 'text': STOCK_LIKE}])
    report, _, rebuilt = _via_agent(STOCK_LIKE)
    assert _norm(rebuilt) == _norm(raw)
    programs = {p['program']: p for p in raw['programs']}
    assert set(programs) >= {'/usr/local/sbin/boot-hook', '/usr/local/bin/lease-hook', 'notify', '/bin/false', '/usr/local/bin/class-hook',
                             '/usr/local/bin/host-hook', '/bin/case-a', '/bin/case-default'}
    assert programs['/usr/local/sbin/boot-hook']['run_as'] == ['root', 'dhcpd']
    assert programs['/bin/false']['argv_literal'] == ['/bin/false', 'a"b\\c']
    assert SECRET not in repr(report) and 'example.org' not in repr(report) and '10.5.5.26' not in repr(report)
    assert 'MSFT' in repr(report)  # a class match condition is part of the reported scope context


FRAGMENTS = [
    'option domain-name "x.org";', f'key k {{ secret "{SECRET}"; }}', 'execute("/bin/a", "b", c);', 'execute(prog);',
    'on commit {', 'on release or expiry {', 'on transmission;', '}', '{', 'if exists foo {', 'elsif a = "b" {', 'else {',
    'else if c {', 'subnet 10.0.0.0 netmask 255.0.0.0 {', 'pool {', 'group {', 'host h {', 'class "c" {', 'subclass "c" 1:2 {',
    'switch (x) {', 'case "a":', 'default:', 'include "/etc/dhcp/other.conf";', 'execute("/bin/q" ;', 'execute("/bin/\\000x");',
    '"unterminated', 'execute("/x\\q");', 'execute("/x\\0");', 'execute("/x", f(a, {));', 'failover peer "p" {', 'zone z {',
    'set v = concat("a", "b");', 'EXECUTE("/bin/upper");', 'On Commit {', '-', '-5', 'a-b_c', '# comment "x', '\n', '\n\n', ';',
    'execute("/bin/x", "' + 'y' * 1600 + '");', 'deny unknown-clients;', 'é', ' ', '(', ')', ',',
]


@pytest.mark.parametrize('seed', range(40))
def test_seeded_differential_against_the_contract(seed):
    rng = random.Random(seed)
    for _ in range(60):
        text = ' '.join(rng.choice(FRAGMENTS) for _ in range(rng.randint(1, 30)))
        raw = de.assess_config([{'path': CONF, 'state': 'regular', 'text': text}])
        report, _, rebuilt = _via_agent(text)
        if any(g['code'] == 'retention_bounded' for g in report['lex_gaps']):
            continue  # retention stopped at a brace inside parentheses; reported as a blocking gap instead
        assert _norm(rebuilt) == _norm(raw), text


def test_braces_inside_parentheses_bound_retention_and_block_the_view():
    text = f'execute("/bin/x", f(a, {{ secret "{SECRET}"; }}));\n'
    report = agent.parse_dhcpd(text.encode())
    assert [g['code'] for g in report['lex_gaps']] == ['retention_bounded'] and SECRET not in repr(report)
    view = startup_inventory.dhcpd_view({'path': CONF, 'kind': 'regular', 'dhcpd': report})
    assert any(g['code'] == 'retention_bounded' and g['blocking'] for g in view['gaps'])


@pytest.mark.parametrize('data', [b'execute("/bin/a");\x00', b'\xff\xfe', b'#' * (agent.DHCPD_TEXT_LIMIT + 1)])
def test_nul_non_utf8_and_over_limit_files_are_not_parsed(data):
    report = agent.parse_dhcpd(data)
    assert report == {'parsed': False, 'tokens': [], 'lex_gaps': [], 'truncated': False, 'redacted': False}
    persistence.validate_dhcpd(report, CONF)
    assert startup_inventory.dhcpd_state({'path': CONF, 'kind': 'regular', 'dhcpd': report}) == 'unparsed'


def test_credentials_in_kept_strings_are_redacted():
    report = agent.parse_dhcpd(b'on commit { execute("/usr/bin/curl", "https://u:hunter2pass@example.net/x"); }\n')
    assert report['redacted'] and 'hunter2pass' not in repr(report)


@pytest.mark.parametrize('value', ['--password=' + 'A' * 1600, 'A' * 1600])
def test_oversized_kept_string_stays_blocking_through_agent_and_controller(value):
    # Redaction can shorten a kept string below dhcpd's token buffer; the agent's gap must survive (#1713 review).
    text = 'on commit { execute("/bin/x", "' + value + '"); }\n'
    raw = de.assess_config([{'path': CONF, 'state': 'regular', 'text': text}])
    assert 'token_over_buffer' in {g['code'] for g in raw['gaps']}
    report = agent.parse_dhcpd(text.encode())
    persistence.validate_dhcpd(report, CONF)
    assert report['redacted'] == value.startswith('--password')
    assert report['redacted'] is False or 'A' * 1600 not in repr(report)
    view = startup_inventory.dhcpd_view({'path': CONF, 'kind': 'regular', 'dhcpd': report})
    over = [g for g in view['gaps'] if g['code'] == 'token_over_buffer']
    assert len(over) == 1 and over[0]['blocking'] and over[0]['code'] in de.BLOCKING
    assert [p['program'] for p in view['programs']] == ['/bin/x']


def test_token_and_value_limits_truncate_and_the_view_blocks(monkeypatch):
    monkeypatch.setattr(agent, 'DHCPD_TOKEN_LIMIT', 5)
    report = agent.parse_dhcpd(b'on commit { execute("/bin/a", "b"); }\n')
    assert report['truncated'] and len(report['tokens']) == 5
    persistence.validate_dhcpd(report, CONF)
    view = startup_inventory.dhcpd_view({'path': CONF, 'kind': 'regular', 'dhcpd': report})
    assert any(g['code'] == 'tokens_truncated' and g['blocking'] for g in view['gaps'])


def _report():
    return agent.parse_dhcpd(STOCK_LIKE.encode())


@pytest.mark.parametrize('mutate', [
    lambda r: r.pop('redacted'),
    lambda r: r.update(extra=1),
    lambda r: r.update(parsed='yes'),
    lambda r: r['tokens'].append([1, 'name', 'x']),  # lines must not decrease
    lambda r: r['tokens'].__setitem__(0, [r['tokens'][0][0], 'dropped', 'leak']),
    lambda r: r['tokens'].__setitem__(1, [r['tokens'][1][0], 'string', SECRET]),  # a value outside the reported statements
    lambda r: r['tokens'].__setitem__(1, [r['tokens'][1][0], 'name', 'secret']),
    lambda r: r['tokens'].__setitem__(0, [r['tokens'][0][0], 'punct', 'ab']),
    lambda r: r['tokens'].__setitem__(0, [r['tokens'][0][0], 'punct', '"']),
    lambda r: r['tokens'].__setitem__(0, [r['tokens'][0][0], 'number', 'abc']),
    lambda r: r['tokens'].__setitem__(0, [r['tokens'][0][0], 'mystery', '']),
    lambda r: r['lex_gaps'].append({'code': 'other', 'line': 1}),
    lambda r: r.update(parsed=False),
    lambda r: r['tokens'].extend([[10**6, 'punct', ';']]),
])
def test_validation_rejects_malformed_reports(mutate):
    report = _report()
    persistence.validate_dhcpd(report, CONF)
    mutate(report)
    with pytest.raises(ValueError):
        persistence.validate_dhcpd(report, CONF)


def test_validation_rejects_tokens_outside_dhcpd_conf():
    for path in ('/etc/dhcp/dhcpd6.conf', '/etc/default/isc-dhcp-server', '/etc/dhcp/dhclient.conf'):
        with pytest.raises(ValueError):
            persistence.validate_dhcpd(_report(), path)
    inventory = {'scope': ['/etc/dhcp'], 'state': 'collected', 'gaps': [], 'skipped': 0, 'missing_roots': [],
                 'entries': [{'path': CONF, 'kind': 'symlink', 'uid': 0, 'gid': 0, 'mode': 0o777, 'size': 1, 'mtime_ns': 1,
                              'target': '/x', 'dhcpd': _report()}]}
    with pytest.raises(ValueError):
        persistence.validate(inventory)


def test_view_reports_programs_accounts_and_gaps_without_safety_verdict():
    view = startup_inventory.dhcpd_view({'path': CONF, 'kind': 'regular', 'dhcpd': _report()})
    assert view['authorizes_response'] is False and view['origin'] == 'not_assessed' and view['complete'] is False
    assert view['process_user']['source'] == 'packaged_unit_default'
    assert any(g['code'] == 'process_user_unobserved' and not g['blocking'] for g in view['gaps'])
    assert view['root_programs'] == 3 and not view['rejected_by_parser']  # boot-hook and both global switch branches
    hook = next(p for p in view['programs'] if p['program'] == '/usr/local/bin/lease-hook')
    assert hook['events'] == ['commit'] and hook['scope'] == ['subnet 10.5.5.0 netmask 255.255.255.224'] and hook['run_as'] == ['dhcpd']
    assert SECRET not in repr(view)
    included = startup_inventory.dhcpd_view({'path': CONF, 'kind': 'regular', 'dhcpd': agent.parse_dhcpd(b'include "/etc/dhcp/x.conf";\n')})
    assert any(g['code'] == 'include' and g['blocking'] and g['detail'] == '/etc/dhcp/x.conf' for g in included['gaps'])


def test_older_agents_and_catalog_labels_are_explained():
    old = {'path': CONF, 'kind': 'regular', 'uid': 0, 'gid': 0, 'mode': 0o644, 'size': 1, 'mtime_ns': 1, 'sha256': 'a' * 64}
    assert startup_inventory.dhcpd_state(old) == 'not_reported'
    assert startup_inventory.dhcpd_state({**old, 'path': '/etc/dhcp/dhcpd6.conf'}) is None
    inventory = {'scope': ['/etc/dhcp/dhcpd.conf'], 'state': 'collected', 'gaps': [], 'skipped': 0, 'missing_roots': [], 'entries': [old]}
    labels = {r['id']: r['label'] for r in startup_inventory.catalog_rows(inventory)}
    assert labels['dhcpd'].endswith('· not reported by this agent version')
    inventory['entries'] = [{**old, 'dhcpd': _report()}]
    persistence.validate(inventory)
    labels = {r['id']: r['label'] for r in startup_inventory.catalog_rows(inventory)}
    assert labels['dhcpd'].endswith('· execute() programs parsed')
    assert 'dhcpd' not in persistence.metadata(inventory['entries'][0])


def test_agent_parses_the_hashed_bytes_without_running_anything(tmp_path, monkeypatch):
    marker = tmp_path / 'ran'
    root = tmp_path / 'dhcp'
    root.mkdir()
    conf = root / 'dhcpd.conf'
    conf.write_text(f'key k {{ secret "{SECRET}"; }}\nexecute("/usr/bin/touch", "{marker}");\n')
    (root / 'dhcpd6.conf').write_text('execute("/bin/v6");\n')
    monkeypatch.setattr(agent, 'PERSISTENCE_ROOTS', (str(root),))
    monkeypatch.setattr(agent, 'PERSISTENCE_FILES', ())
    monkeypatch.setattr(agent, 'DHCPD_CONF', str(conf))
    result = agent.persistence_inventory(time.monotonic() + 5, cron_jobs=True)
    assert not marker.exists() and SECRET not in repr(result)
    rows = {r['path']: r for r in result['entries']}
    assert 'dhcpd' in rows[str(conf)] and 'dhcpd' not in rows[str(root / 'dhcpd6.conf')]
    view = startup_inventory.dhcpd_view({'path': CONF, 'kind': 'regular', 'dhcpd': rows[str(conf)]['dhcpd']})
    assert [(p['program'], p['run_as']) for p in view['programs']] == [('/usr/bin/touch', ['root', 'dhcpd'])]
    without = agent.persistence_inventory(time.monotonic() + 5, cron_jobs=False)
    assert all('dhcpd' not in r for r in without['entries'])
