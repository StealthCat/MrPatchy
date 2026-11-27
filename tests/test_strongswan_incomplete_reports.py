"""strongSwan reports that agents produce for empty includes and capped files keep the host's startup inventory (#1680)."""
import copy
import random
import time

import pytest

from app import persistence, startup_inventory
from app import strongswan_updown as su
from app.db import Host, Session
from app.incidents import Inspection
from target import agent

CONF = '/etc/swanctl/swanctl.conf'
SITE = '/etc/swanctl/conf.d/site.conf'
BIG = '/etc/swanctl/conf.d/big.conf'
CHILD = 'connections {\n  site {\n    children { net { updown = /usr/local/bin/up.sh marker } }\n  }\n}\n'
# Native Ubuntu 24.04 strongswan 5.9.13 (charon-systemd + swanctl --load-conns) on this text logged
# "swanctl.conf:1: no include pattern specified, ignored", then "loaded connection 'site'".
EMPTY_INCLUDE = 'include ""\n' + CHILD
CAPPED = ''.join(f'k{n} = v{n}\n' for n in range(2001))


def row(path, text, report=None):
    out = {'path': path, 'kind': 'regular', 'uid': 0, 'gid': 0, 'mode': 0o644, 'size': len(text), 'mtime_ns': 1, 'sha256': 'a' * 64}
    if persistence.swanctl_reads(path):
        out['strongswan'] = agent.parse_swanctl(text.encode()) if report is None else report
    return out


def inventory(*rows):
    return {'scope': ['/etc/cron.d', '/etc/swanctl', '/etc/strongswan'], 'state': 'collected',
            'entries': [row('/etc/cron.d/backup', '0 1 * * * root /usr/local/bin/backup\n'), *rows],
            'gaps': [], 'skipped': 0, 'missing_roots': ['/etc/strongswan']}


def legacy_capped():
    """The report an agent before #1680 produced for CAPPED: the capped setting's value was also counted."""
    report = agent.parse_swanctl(CAPPED.encode())
    return dict(report, dropped=report['dropped'] + 1)


def test_empty_include_is_ignored_like_native_strongswan():
    result = su.evaluate(files={CONF: EMPTY_INCLUDE}, directories={})
    assert result['complete'] and not result['gaps']
    assert [(c['connection'], c['child'], c['command']) for c in result['commands']] == [('site', 'net', '/usr/local/bin/up.sh marker')]
    assert {'code': 'include_pattern_empty', 'file': CONF, 'line': 1} in result['notes']
    assert result['contract_version'] == 2


def test_agent_reports_an_empty_include_and_the_controller_accepts_it():
    report = agent.parse_swanctl(EMPTY_INCLUDE.encode())
    assert report['statements'][0] == {'line': 1, 'op': 'include', 'pattern': ''}
    persistence.validate_swanctl(report, CONF)
    inv = inventory(row(CONF, EMPTY_INCLUDE))
    persistence.validate(inv)
    view = startup_inventory.strongswan_view(inv, CONF)
    assert view['config_complete'] and [g['code'] for g in view['gaps']] == ['charon_uid_assumed']
    assert [c['command'] for c in view['commands']] == ['/usr/local/bin/up.sh marker']
    assert su.evaluate(files={CONF: startup_inventory.swanctl_text(report)})['commands'] == su.evaluate(files={CONF: EMPTY_INCLUDE})['commands']


def test_capped_file_counts_only_emitted_values():
    report = agent.parse_swanctl(CAPPED.encode())
    assert report['truncated'] and len(report['statements']) == 2000 and report['dropped'] == 2000
    persistence.validate_swanctl(report, BIG)
    # The cap reached exactly: every setting emitted, nothing truncated, every value counted.
    exact = agent.parse_swanctl(''.join(f'k{n} = v{n}\n' for n in range(2000)).encode())
    assert not exact['truncated'] and exact['dropped'] == 2000
    persistence.validate_swanctl(exact, BIG)


def test_already_queued_over_counted_report_is_accepted_only_when_truncated():
    legacy = legacy_capped()
    assert legacy['dropped'] == 2001
    persistence.validate_swanctl(copy.deepcopy(legacy), BIG)
    for bad in (dict(legacy, truncated=False, statements=legacy['statements']), dict(legacy, dropped=2002)):
        with pytest.raises(ValueError):
            persistence.validate_swanctl(bad, BIG)


def test_truncated_file_is_a_file_level_gap_and_unrelated_entries_stay_valid():
    inv = inventory(row(CONF, 'include conf.d/*.conf\n'), row(SITE, CHILD), row(BIG, CAPPED, legacy_capped()))
    persistence.validate(inv)
    view = startup_inventory.strongswan_view(inv, CONF)
    assert any(g['code'] == 'statements_truncated' and g['blocking'] and g['path'] == BIG for g in view['gaps'])
    assert any(g['code'] == 'file_not_observed' and g['file'] == BIG for g in view['gaps']) and not view['config_complete']
    assert [c['command'] for c in view['commands']] == ['/usr/local/bin/up.sh marker']


@pytest.mark.parametrize('seed', range(3))
def test_seeded_differential_with_empty_includes(seed):
    rng = random.Random(seed)
    pieces = ['include ""', 'include "" ', 'include conf.d/*.conf', 'connections {', '}', 'c { children { k { updown = /bin/x } } }',
              'k = v', 'updown = "a b"', '{', '=', '"x"']
    for _ in range(300):
        text = '\n'.join(rng.choice(pieces) for _ in range(rng.randint(0, 25))) + '\n'
        files = {CONF: text, SITE: CHILD}
        directories = {'/etc/swanctl/conf.d': ['site.conf']}
        expected = su.evaluate(files=files, directories=directories)
        report = agent.parse_swanctl(text.encode())
        persistence.validate_swanctl(report, CONF)
        actual = su.evaluate(files={CONF: startup_inventory.swanctl_text(report), SITE: CHILD}, directories=directories)
        assert {k: actual[k] for k in ('commands', 'gaps', 'notes', 'files', 'complete')} == \
               {k: expected[k] for k in ('commands', 'gaps', 'notes', 'files', 'complete')}, text


def test_startup_inventory_page_serves_both_shapes_end_to_end(admin):
    inv = inventory(row(CONF, EMPTY_INCLUDE + 'include conf.d/*.conf\n'), row(SITE, CHILD), row(BIG, CAPPED, legacy_capped()))
    with Session() as s:
        s.add(Host(id='one', name='one', address='192.0.2.1', fingerprint='test'))
        s.add(Inspection(id='new', host_id='one', created=time.time() - 1, report={'persistence': inv}))
        s.commit()
    response = admin.get('/api/hosts/one/security/startup-inventory')
    assert response.status_code == 200, response.text
    rows = {r['path']: r for r in response.json()['items']}
    assert {'/etc/cron.d/backup', CONF, SITE, BIG} <= set(rows)
    view = rows[CONF]['strongswan']
    assert any(g['code'] == 'statements_truncated' and g['path'] == BIG for g in view['gaps'])
    assert [c['command'] for c in view['commands']] == ['/usr/local/bin/up.sh marker']
    assert any(n['code'] == 'include_pattern_empty' for n in view['notes'])
