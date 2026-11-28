"""Agent-reported collectd items evaluate exactly like the full files (#1551 increment 3).

Agents cannot import the controller. They parse each hashed collectd file with their own port of the
liboconfig scanner and parser in app/collectd_exec and keep values only for the items the exec-plugin
contract reads. The controller validates the report and runs app/collectd_exec over those items. These
tests compare that path with the contract run on the full original text, over hand-written native cases
and a seeded random grammar, and check that the validator rejects reports an agent never produces.
"""
import copy
import random

import pytest

from app import collectd_exec as ce, persistence, startup_inventory as si
from target import agent

DEB = ce.DEFAULT_CONFIG
RPM = persistence.COLLECTD_FILE
PROG = '/usr/local/lib/collectd/prog.sh'

# Ubuntu 24.04 collectd-core 5.12.0-17.1build2 /etc/collectd/collectd.conf, abridged (as shipped, plus an exec block).
PACKAGED = (
    '# Config file for collectd(1).\n'
    '#Hostname "localhost"\n'
    'FQDNLookup true\n'
    '#BaseDir "/var/lib/collectd"\n'
    '#PluginDir "/usr/lib/collectd"\n'
    '#TypesDB "/usr/share/collectd/types.db" "/etc/collectd/my_types.db"\n'
    '#AutoLoadPlugin false\n'
    '#Interval 10\n'
    'LoadPlugin syslog\n'
    '<Plugin syslog>\n'
    '\tLogLevel info\n'
    '</Plugin>\n'
    'LoadPlugin battery\n'
    'LoadPlugin cpu\n'
    'LoadPlugin exec\n'
    'LoadPlugin network\n'
    '<Plugin network>\n'
    '\t<Server "192.168.0.42" "25826">\n'
    '\t\tSecurityLevel Encrypt\n'
    '\t\tUsername "user"\n'
    '\t\tPassword "s3cretNetworkPw"\n'
    '\t</Server>\n'
    '</Plugin>\n'
    '<Plugin exec>\n'
    f'\tExec "nobody:nogroup" "{PROG}" "a b" 5 0755 0x10 true On 1.5\n'
    '\tNotificationExec "daemon" "notify.sh"\n'
    '\tFoo "x"\n'
    '</Plugin>\n'
    '<Include "/etc/collectd/collectd.conf.d">\n'
    '\tFilter "*.conf"\n'
    '</Include>\n'
)
DROPIN = '<Plugin "exec">\n  Exec "nobody" "/opt/dropin.sh" "--flag"\n</Plugin>\n'


def report(text):
    data = text.encode('utf-8') if isinstance(text, str) else text
    result = agent.parse_collectd(data)
    persistence.validate_collectd(result, DEB)
    return result


def inventory(files, missing=(), state='collected', links=()):
    entries = [{'path': p, 'kind': 'regular', 'uid': 0, 'gid': 0, 'mode': 0o644, 'size': len(t), 'sha256': '0' * 64,
                'collectd': agent.parse_collectd(t.encode('utf-8') if isinstance(t, str) else t)} for p, t in files.items()]
    entries += [{'path': p, 'kind': 'symlink', 'uid': 0, 'gid': 0, 'mode': 0o777, 'size': 1, 'target': 'x'} for p in links]
    for e in entries:
        if 'collectd' in e:
            persistence.validate_collectd(e['collectd'], e['path'])
    return {'state': state, 'entries': sorted(entries, key=lambda e: e['path']), 'missing_roots': list(missing)}


def listings(paths):
    found = {}
    for path in paths:
        parts = path.split('/')
        for depth in range(2, len(parts)):
            directory = '/'.join(parts[:depth])
            if si._collectd_within(directory):
                found.setdefault(directory, set()).add(parts[depth])
    for root in ('/etc/collectd', '/etc/collectd.d'):
        found.setdefault(root, set())
    return {k: sorted(v) for k, v in found.items()}


def direct(files, config=DEB, absent=(), absent_dirs=()):
    captured = dict(files)
    captured.update({p: None for p in absent})
    directories = listings(files)
    directories.update({p: None for p in absent_dirs})
    return ce.evaluate(files=captured, directories=directories, config_path=config)


def same(view, expected):
    assert view['config_accepted'] == expected['config_accepted']
    assert view['exec_plugin_loaded'] == expected['exec_plugin_loaded']
    assert view['files'] == expected['files']
    keys = ('kind', 'file', 'line', 'option', 'user', 'group', 'executable', 'path_search', 'argv', 'starts')
    assert [{k: p[k] for k in keys} for p in view['programs']] == [{k: p[k] for k in keys} for p in expected['programs']]
    assert view['notes'] == expected['notes']
    view_gaps = [g for g in view['gaps'] if g['code'] not in ('passwd_group_not_captured',)]
    assert view_gaps == [g for g in expected['gaps'] if g['code'] not in ('passwd_not_supplied', 'group_not_supplied')]
    assert view['authorizes_response'] is False and view['complete'] is False


def test_packaged_config_with_dropin_matches_the_full_text():
    files = {DEB: PACKAGED, '/etc/collectd/collectd.conf.d/extra.conf': DROPIN,
             '/etc/collectd/collectd.conf.d/skip.txt': 'Exec "nobody" "/never"\n'}
    view = si.collectd_view(inventory(files), DEB)
    same(view, direct(files))
    argv = [p['argv'] for p in view['programs']]
    assert argv == [['prog.sh', 'a b', '5.000000', '755.000000', '16.000000', 'true', 'On', '1.500000'],
                    ['notify.sh'], ['dropin.sh', '--flag']]
    assert [p['user'] for p in view['programs']] == ['nobody', 'daemon', 'nobody']
    assert all(p['starts'] is None for p in view['programs'])  # accounts are not captured
    assert view['config_accepted'] is True
    assert any(g['code'] == 'passwd_group_not_captured' and g['blocking'] for g in view['gaps'])


def test_agent_withholds_unrelated_values_such_as_network_passwords():
    result = report(PACKAGED)
    flat = repr(result)
    assert 's3cretNetworkPw' not in flat and '192.168.0.42' not in flat and 'LogLevel' not in flat
    assert result['dropped'] >= 3
    keys = [i['key'] for i in result['items']]
    assert keys == ['LoadPlugin', 'LoadPlugin', 'LoadPlugin', 'LoadPlugin', 'LoadPlugin', 'Plugin', 'Include']
    exec_block = result['items'][5]
    assert [c['key'] for c in exec_block['children']] == ['Exec', 'NotificationExec', 'Foo']
    assert exec_block['children'][2]['values'] is None


def test_exec_arguments_are_redacted_like_cron_commands():
    text = 'LoadPlugin exec\n<Plugin exec>\n Exec "nobody" "/bin/tool" "--password=hunter2"\n</Plugin>\n'
    result = report(text)
    assert result['redacted'] is True and 'hunter2' not in repr(result)
    view = si.collectd_view(inventory({DEB: text}), DEB)
    assert view['redacted'] is True and 'hunter2' not in repr(view)


@pytest.mark.parametrize('text', [
    'LoadPlugin exec\n<Plugin exec>\n Exec "nobody" "/x"\n</plugin>\n',   # case-mismatched close
    'LoadPlugin exec',                                                        # no final newline
    'LoadPlugin\n',                                                           # option without value
    '</Plugin>\n',
    '<Plugin exec\n',
])
def test_parse_errors_reject_the_file_like_the_contract(text):
    result = report(text)
    assert result['syntax_error'] is not None and result['items'] == []
    files = {DEB: text}
    view = si.collectd_view(inventory(files), DEB)
    same(view, direct(files))
    assert view['config_accepted'] is False


def test_rejected_direct_include_rejects_the_main_file():
    files = {DEB: 'LoadPlugin exec\nInclude "/etc/collectd/bad.conf"\n<Plugin exec>\n Exec "nobody" "/x"\n</Plugin>\n',
             '/etc/collectd/bad.conf': 'Interval\n'}
    view = si.collectd_view(inventory(files), DEB)
    same(view, direct(files))
    assert view['config_accepted'] is False


def test_absent_include_is_observed_only_from_a_complete_collection():
    text = 'LoadPlugin exec\nInclude "/etc/collectd/missing.conf"\nInclude "/etc/collectd/none/*.conf"\n<Plugin exec>\n Exec "nobody" "/x"\n</Plugin>\n'
    files = {DEB: text}
    view = si.collectd_view(inventory(files), DEB)
    same(view, direct(files, absent=('/etc/collectd/missing.conf', '/etc/collectd/none/*.conf'), absent_dirs=('/etc/collectd/none',)))
    assert not any(g['code'] == 'path_unobserved' for g in view['gaps'])
    partial = si.collectd_view(inventory(files, state='incomplete'), DEB)
    assert any(g['code'] == 'path_unobserved' for g in partial['gaps'])


def test_include_outside_collectd_scope_is_a_blocking_gap():
    files = {DEB: 'Include "/usr/share/collectd/extra.conf"\nLoadPlugin exec\n'}
    view = si.collectd_view(inventory(files), DEB)
    assert {'code': 'path_unobserved', 'blocking': True, 'path': '/usr/share/collectd/extra.conf'} in view['gaps']


def test_symlinked_dropin_and_undecodable_file_stay_unobserved():
    files = {DEB: PACKAGED, '/etc/collectd/collectd.conf.d/bad.conf': b'Exec \xff\n'}
    view = si.collectd_view(inventory(files, links=('/etc/collectd/collectd.conf.d/link.conf',)), DEB)
    codes = [g['code'] for g in view['gaps']]
    assert 'file_invalid' in codes and 'path_unobserved' in codes
    assert agent.parse_collectd(b'Exec \x00\n')['error'] == 'nul_byte'


def test_rpm_family_layout_reads_collectd_d():
    files = {RPM: 'LoadPlugin exec\nInclude "/etc/collectd.d"\n',
             '/etc/collectd.d/exec.conf': DROPIN}
    view = si.collectd_view(inventory(files, missing=('/etc/collectd',)), RPM)
    same(view, direct(files, config=RPM))
    assert [p['executable'] for p in view['programs']] == ['/opt/dropin.sh']


def test_older_agents_are_reported_as_not_reported():
    inv = inventory({DEB: PACKAGED})
    for e in inv['entries']:
        e.pop('collectd')
    assert si.collectd_state(inv['entries'][0]) == 'not_reported'
    view = si.collectd_view(inv, DEB)
    assert view['programs'] == [] and any(g['code'] == 'not_reported_by_agent' for g in view['gaps'])


WORDS = ['LoadPlugin', 'Plugin', 'Include', 'Exec', 'NotificationExec', 'AutoLoadPlugin', 'PluginDir', 'Filter',
         'Interval', 'exec', 'Exec', 'cpu', 'nobody', 'daemon', 'true', 'false', 'On', 'no']
PIECES = ['"exec"', '"nobody:daemon"', '"/opt/p.sh"', '"a b"', '"x\\"y"', '"/etc/collectd/d"', '"/etc/collectd/d/*.conf"',
          '"*.conf"', '"multi\\\n   line"', '0755', '0x1f', '-3', '1.5e+3', '.5', '10.0.0.1', '::1', '[fe80::1]:80',
          'foo-bar', '#c', '\\\n', '"/usr/lib/collectd"', '"/opt/plugins"']


def random_config(rng):
    lines = []
    depth = 0
    for _ in range(rng.randint(1, 18)):
        roll = rng.random()
        if roll < 0.18:
            name = rng.choice(['Plugin', 'Include', 'Plugin', 'Foo'])
            lines.append('<' + name + ' ' + rng.choice(['exec', '"exec"', '"/etc/collectd/d"', 'cpu', '"EXEC"']) + '>')
            depth += 1
        elif roll < 0.3 and depth:
            lines.append('</' + rng.choice(['Plugin', 'Include', 'Plugin', 'plugin']) + '>')
            depth -= 1
        else:
            lines.append(rng.choice(WORDS) + ' ' + ' '.join(rng.choice(PIECES + WORDS) for _ in range(rng.randint(0, 5))))
    while depth and rng.random() < 0.9:
        lines.append('</Plugin>')
        depth -= 1
    text = rng.choice(['\n', '\r\n']).join(lines)
    return text + ('\n' if rng.random() < 0.95 else '')


def test_seeded_random_configs_evaluate_the_same():
    rng = random.Random(1551)
    for _ in range(1500):
        files = {DEB: random_config(rng)}
        if rng.random() < 0.6:
            files['/etc/collectd/d/a.conf'] = random_config(rng)
        if rng.random() < 0.3:
            files['/etc/collectd/d/b.txt'] = random_config(rng)
        for path, text in files.items():
            try:
                expected = ce.parse(text)
            except ce.ParseError as error:
                expected = ('error', error.line, error.reason)
            try:
                got = [{**i, 'values': [tuple(v) for v in i['values']]} for i in agent._cd_parse(text)]
            except agent.CollectdSyntax as error:
                got = ('error', error.line, error.reason)
            if isinstance(expected, list):
                def norm(items):
                    return [{'key': i['key'], 'line': i['line'],
                             'values': [(k, ce._strtod(v) if k == 'number' and isinstance(v, str) else v) for k, v in i['values']],
                             'children': norm(i['children'])} for i in items]
                assert norm(got) == norm(expected), text
            else:
                assert got == expected, text
        same(si.collectd_view(inventory(files), DEB), direct(files))


def test_validator_rejects_reports_agents_never_produce():
    good = report(PACKAGED)
    bad = []
    for mutate in (
        lambda r: r.pop('dropped'),
        lambda r: r.update(parsed='yes'),
        lambda r: r.update(error='nul_byte'),
        lambda r: r['items'].append({'key': 'Hostname', 'line': 99, 'values': [['string', 'x']], 'children': [], 'block': False}),
        lambda r: r['items'][5]['values'].__setitem__(0, ['string', 'network']),
        lambda r: r['items'][5]['children'][2].update(values=[['string', 'leak']]),
        lambda r: r['items'][0]['values'].__setitem__(0, ['number', 'abc']),
        lambda r: r['items'][0].update(line=0),
        lambda r: r['items'][0].update(key='Load Plugin'),
        lambda r: r['items'][0].update(children=[{'key': 'Globals', 'line': 10, 'values': None, 'children': [], 'block': False}], block=True),
        lambda r: r['items'][5]['children'][0].update(line=1),
        lambda r: r.update(syntax_error={'line': 1, 'reason': 'made_up'}),
        lambda r: r['items'].reverse(),
    ):
        candidate = copy.deepcopy(good)
        mutate(candidate)
        bad.append(candidate)
    for candidate in bad:
        with pytest.raises(ValueError):
            persistence.validate_collectd(candidate, DEB)
    with pytest.raises(ValueError):
        persistence.validate_collectd(good, '/etc/collectd-web.conf')
    persistence.validate_collectd(good, '/etc/collectd.d/x.conf')


def test_metadata_excludes_parsed_items():
    row = inventory({DEB: PACKAGED})['entries'][0]
    assert 'collectd' not in persistence.metadata(row)
