"""Agent-reduced LVM trees evaluate exactly like the full files (#1599 increment 3).

Agents cannot import the controller. They parse /etc/lvm/lvm.conf and lvmlocal.conf with their own copy
of the app/lvm_commands libdm-config parser and report only a reduced tree. The controller validates it,
rebuilds canonical text and runs the contract. These tests compare that path with the contract run on
the full original text, over hand-written cases and a seeded random grammar with corruptions.
"""
import copy
import random

import pytest

from app import lvm_commands as lc
from app import persistence, startup_inventory as si
from target import agent

LVM, LOCAL = persistence.LVM_FILES

PACKAGED_LVM_CONF = (
    '# This is an example configuration file for the LVM2 system.\n'
    'config {\n}\ndevices {\n\t# issue_discards = 0\n\tissue_discards = 1\n}\n'
    'allocation {\n}\nlog {\n}\nbackup {\n}\nshell {\n}\nglobal {\n'
    '\t# thin_check_executable = "/usr/sbin/thin_check"\n}\nactivation {\n}\n'
    'dmeventd {\n\t# thin_command = "lvm lvextend --use-policies"\n}\n'
    '# tags {\n\t# hosttags = 0\n# }\n'
)


def _report(text, nodename='vm'):
    report = agent.parse_lvm_conf(text.encode('utf-8') if isinstance(text, str) else text)
    report['nodename'] = nodename
    persistence.validate_lvm(report, LVM)
    return report


def _inventory(main, local=None, nodename='vm', state='collected'):
    entries = []
    for path, text in ((LVM, main), (LOCAL, local)):
        if text is None:
            continue
        entries.append({'path': path, 'kind': 'regular', 'uid': 0, 'gid': 0, 'mode': 0o644, 'size': len(text),
                        'mtime_ns': 0, 'sha256': '0' * 64, 'lvm': _report(text, nodename)})
    return {'state': state, 'entries': entries, 'missing_roots': [], 'scope': list(persistence.LVM_FILES),
            'gaps': [], 'skipped': 0}


def _full(main, local=None, nodename='vm'):
    records = [{'path': LVM, 'state': 'regular', 'text': main}]
    records.append({'path': LOCAL, 'state': 'absent'} if local is None else
                   {'path': LOCAL, 'state': 'regular', 'text': local})
    return lc.assess(records, hostname=nodename)


def _comparable(result):
    gaps = [{k: v for k, v in g.items() if k != 'blocking'} for g in result['gaps']
            if g['reason'] not in ('agent_value_inexact',)]
    return {'settings': result['settings'], 'tags': result['tags'], 'lvm_starts': result['lvm_starts'],
            'warnings': result['warnings'], 'gaps': gaps,
            'files': [{k: f[k] for k in ('path', 'state', 'parse_error') if k in f} for f in result['files']]}


def _same(main, local=None, nodename='vm'):
    full = _comparable(_full(main, local, nodename))
    view = si.lvm_view(_inventory(main, local, nodename))
    assert view['authorizes_response'] is False and view['origin'] == 'not_assessed'
    assert _comparable(view) == full
    return view


CASES = [
    PACKAGED_LVM_CONF,
    'global { thin_check_executable = "/opt/check" fsadm_executable = "" }\n',
    'global/thin_check_executable = "/a"\n"global"/"cache_check_executable" = \'/b c\'\n',
    'global { fsadm_executable = "/a"\n fsadm_executable = "/b" }\nglobal { thin_dump_executable = "/c" }\n',
    'global { thin_check_executable = "/a\\"b\\\\c\\n" # comment "x"\n }\n',
    'global { thin_check_executable = [ "/first", "/second" ] vdo_format_executable = 7 }\n',
    'global { thin_repair_executable = [] cache_repair_executable = 1.5 cache_dump_executable = -08 }\n',
    'global { tags { } thin_check_executable = "/skipped" }\n',
    'global { tags = [ "@db" ] thin_check_executable = "/x" }\ntags { db { } }\n',
    'global { tags = [ "@other" ] thin_check_executable = "/x" }\ntags { db { } }\n',
    'tags { hosttags = 1 }\nglobal { tags = "@vm" lvmlockctl_kill_command = "/usr/sbin/kill-vg --force" }\n',
    'tags { hosttags = "yes" web { host_list = [ "web1", 7 ] } }\n',
    'tags { db { host_list = [ "other" "vm" ] } bad! { } }\n',
    'tags { db { host_filter = "x" } }\n',
    'tags { db { host_list = [] secret = "s3cr3t" } }\ndmeventd { thin_command = "/usr/local/bin/grow pool" }\n',
    'dmeventd { executable = "/opt/dmeventd" thin_library = "/opt/thin.so" vdo_command = "lvm lvextend -l+10%FREE" }\n',
    'dmeventd { thin_command = "relative" raid_library = "" snapshot_library { x = 1 } }\n',
    'devices { filter = [ "a|.*|" ] }\nactivation { auto_activation_volume_list = [ "vg" ] }\n',
    'global { executable = 1 } local { system_id = "x" } global { thin_check_executable = 0x10 }\n',
    'global { thin_check_executable = "/a" ',
    'global { thin_check_executable = "/a }\n',
    'global { = 1 }\n',
    '"" { }\n',
    'global { fsadm_executable = }\n',
]


@pytest.mark.parametrize('text', CASES)
def test_reduced_tree_matches_full_text(text):
    _same(text)
    _same(PACKAGED_LVM_CONF, local=text)
    _same(text, nodename=None)


def test_packaged_configuration_shows_build_defaults_and_drops_other_values():
    view = _same(PACKAGED_LVM_CONF, local='local {\n\tsystem_id = "host-7"\n}\n')
    assert view['complete'] is True and view['lvm_starts'] is True and view['gaps'] == []
    assert {s['source'] for s in view['settings']} == {'build_default'}
    report = _report('devices { filter = [ "secret" ] }\nlocal { system_id = "x" }\n'
                     'tags { db { other = "hidden" host_list = [ "vm" ] } }\n')
    flat = repr(report)
    assert 'secret' not in flat and 'hidden' not in flat and 'system_id' not in flat
    assert report['sections'] == [{'key': 'tags', 'values': [], 'tags': [
        {'key': 'db', 'values': [{'key': 'host_list', 'values': [['string', 'vm']]}]}]}]


def test_parse_errors_keep_only_reason_and_line():
    report = _report('global { thin_check_executable = "/a" }\n\n devices { x = "secret\n')
    assert report == {'parsed': False, 'error': {'reason': 'unterminated_string', 'line': 3}, 'sections': [],
                      'inexact': [], 'nodename': 'vm'}
    view = si.lvm_view(_inventory('global { x = "secret\n'))
    assert view['lvm_starts'] is False and view['complete'] is False
    assert all(s['runs_only_if_config_loads'] for s in view['settings'])
    for data, reason in ((b'global { }\x00', 'nul_byte'), (b'global { x = "\xff" }', 'invalid_utf8')):
        report = agent.parse_lvm_conf(data)
        assert report['error'] == {'reason': reason, 'line': None} and report['parsed'] is False
        persistence.validate_lvm(report, LVM)


def test_redacted_or_truncated_commands_are_inexact_gaps():
    long = '/opt/' + 'x' * 600
    view = si.lvm_view(_inventory('global { lvmlockctl_kill_command = "/bin/kill --password=hunter2" '
                                  f'thin_check_executable = "{long}" }}\n'))
    reasons = [(g['reason'], g.get('setting')) for g in view['gaps']]
    assert ('agent_value_inexact', 'global/lvmlockctl_kill_command') in reasons
    assert ('agent_value_inexact', 'global/thin_check_executable') in reasons
    assert 'hunter2' not in repr(view) and view['complete'] is False


def test_older_agent_symlink_and_incomplete_collection_are_gaps():
    inventory = _inventory(PACKAGED_LVM_CONF)
    del inventory['entries'][0]['lvm']
    view = si.lvm_view(inventory)
    assert {'reason': 'not_reported_by_agent', 'path': LVM, 'blocking': True} in view['gaps']
    assert view['complete'] is False
    inventory = _inventory(PACKAGED_LVM_CONF)
    inventory['entries'][0] = {**inventory['entries'][0], 'kind': 'symlink', 'target': '/x'}
    del inventory['entries'][0]['lvm']
    assert {'reason': 'symlink_not_followed', 'path': LVM, 'blocking': True} in si.lvm_view(inventory)['gaps']
    partial = si.lvm_view(_inventory(PACKAGED_LVM_CONF, state='incomplete'))
    assert any(g['reason'] == 'file_unknown' and g['path'] == LOCAL for g in partial['gaps'])


@pytest.mark.parametrize('mutate', [
    lambda r: r.update(extra=1),
    lambda r: r['sections'].append({'key': 'devices', 'values': []}),
    lambda r: r['sections'][0]['values'].append({'key': 'filter', 'values': [['string', 'x']]}),
    lambda r: r['sections'][0]['values'][0].update(values=[['string', 'x' * 513]]),
    lambda r: r['sections'][0]['values'][0].update(values=[['bytes', 'x']]),
    lambda r: r['sections'][0]['values'][0].update(values=None),
    lambda r: r['sections'][0]['values'][0].update(values=[['string', 'a\x00b']]),
    lambda r: r['sections'].append(copy.deepcopy(r['sections'][0])),
    lambda r: r.update(parsed=False),
    lambda r: r.update(nodename=''),
])
def test_validation_rejects_values_agents_do_not_retain(mutate):
    report = _report('global { thin_check_executable = "/a" }\n')
    mutate(report)
    with pytest.raises(ValueError):
        persistence.validate_lvm(report, LVM)
    with pytest.raises(ValueError):
        persistence.validate_lvm(_report('global { }\n'), '/etc/lvm/lvm_x.conf')


ATOMS = ['global', 'dmeventd', 'tags', 'devices', 'local', 'activation', '"global"', 'global/tags',
         'thin_check_executable', 'fsadm_executable', 'lvmlockctl_kill_command', 'executable', 'thin_command',
         'thin_library', 'vdo_command', 'hosttags', 'host_list', 'host_filter', 'db', '@db', 'vm', 'web',
         'global/thin_dump_executable', 'dmeventd/vdo_library', 'x']
VALUES = ['"/opt/a"', '"lvm lvextend"', "'/raw\\path'", '""', '1', '0', '-3', '010', '1.5', '.', '+',
          '[ "/a", "/b" ]', '[]', '[ 1 "vm" ]', '[ "@db" ]', '"@vm"', '"y"', 'bare/path', '"a\\"q"']


def _random_text(rng, depth=0):
    out = []
    for _ in range(rng.randint(0, 5 if depth == 0 else 3)):
        key = rng.choice(ATOMS)
        if depth < 3 and rng.random() < 0.45:
            out.append(f'{key} {{\n{_random_text(rng, depth + 1)}}}\n')
        else:
            out.append(f'{key} = {rng.choice(VALUES)}' + rng.choice(['\n', ' ', ' # c\n']))
    return ''.join(out)


def test_seeded_random_grammar_matches_full_text():
    rng = random.Random(1599)
    errors = 0
    for _ in range(600):
        main = _random_text(rng)
        if rng.random() < 0.2 and main:
            cut = rng.randrange(len(main))
            main = main[:cut] + rng.choice(['', '{', '}', '"', '=', '[']) + main[cut + 1:]
        local = _random_text(rng) if rng.random() < 0.5 else None
        errors += not agent.parse_lvm_conf(main.encode())['parsed']
        _same(main, local, rng.choice(['vm', 'web', None]))
    assert errors > 20


@pytest.mark.parametrize('value', [
    '9' * 400, '-' + '9' * 400, '+' + '9' * 30, '0' + '7' * 200, '9223372036854775808', '-9223372036854775809',
    '18446744073709551616', '1.' + '5' * 500, '.' + '0' * 300, '-.' + '1' * 100, '0' * 300 + '9',
])
def test_numeric_bounds_hold_from_reducer_to_inventory_validation(value):
    texts = [f'global {{ thin_check_executable = {value} fsadm_executable = [ "/f", {value} ] }}\n',
             f'tags {{ hosttags = {value} db {{ host_list = [ "vm", {value} ] }} }}\n',
             f'tags {{ web {{ host_list = [ {value} ] }} }}\ndmeventd {{ tags = [ {value} ] thin_command = "/x" }}\n']
    for text in texts:
        report = agent.parse_lvm_conf(text.encode())
        assert report['parsed'] is True
        persistence.validate_lvm(report, LVM)
        persistence.validate({'state': 'collected', 'scope': ['/etc/lvm/lvm.conf'], 'missing_roots': [], 'gaps': [],
                              'skipped': 0, 'entries': [{'path': LVM, 'kind': 'regular', 'uid': 0, 'gid': 0,
                                                         'mode': 0o644, 'size': len(text), 'mtime_ns': 0,
                                                         'sha256': '0' * 64, 'lvm': report}]})
        _same(text)
        _same(PACKAGED_LVM_CONF, local=text, nodename=None)


def test_long_tag_names_that_collide_after_cutting_keep_the_inventory():
    long = 'a' * 300
    text = f'tags {{ {long}1 {{ }} {long}2 {{ host_list = [ "vm" ] }} {"a" * 255} {{ }} ok {{ }} }}\n'
    report = agent.parse_lvm_conf(text.encode())
    persistence.validate_lvm(report, LVM)
    assert [t['key'] for t in report['sections'][0]['tags']] == ['a' * 255, 'ok']
    assert report['inexact'] == ['tags']
    view = si.lvm_view(_inventory(text))
    assert {'reason': 'agent_value_inexact', 'path': LVM, 'setting': 'tags', 'blocking': True} in view['gaps']
    assert view['complete'] is False
    many = 'tags { ' + ' '.join(f't{i} {{ }}' for i in range(80)) + ' }\n'
    report = agent.parse_lvm_conf(many.encode())
    persistence.validate_lvm(report, LVM)
    assert len(report['sections'][0]['tags']) == 64 and report['inexact'] == ['tags']
