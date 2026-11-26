"""Tests for the pure LVM2 program contract (#1599).

Expected values were recorded from native lvm2 2.03.16 (Ubuntu 24.04 package
2.03.16-3ubuntu3.2) ``lvm lvmconfig --typeconfig full`` runs with
``LVM_SYSTEM_DIR`` set to a scratch directory holding each case's files and
node name ``vm``. The exception is the wrong-type and empty-value cases:
``lvmconfig`` prints the raw value there, while the runtime lookup
``_find_config_str()`` uses the build default.
"""
from app import lvm_commands as lc

# Effective (non-comment) content of the packaged files. The full files have
# sha256 ef4955e4...6c91b (lvm.conf) and 6034be4f...6f88 (lvmlocal.conf).
PACKAGED_LVM_CONF = (
    '# This is an example configuration file for the LVM2 system.\n'
    'config {\n}\ndevices {\n\t# issue_discards = 0\n\tissue_discards = 1\n}\n'
    'allocation {\n}\nlog {\n}\nbackup {\n}\nshell {\n}\nglobal {\n'
    '\t# thin_check_executable = "/usr/sbin/thin_check"\n}\nactivation {\n}\n'
    'dmeventd {\n\t# thin_command = "lvm lvextend --use-policies"\n}\n'
    '# tags {\n\t# hosttags = 0\n# }\n'
)
PACKAGED_LVMLOCAL_CONF = '# This is a local configuration file template for the LVM2 system\nlocal {\n}\n'


def _assess(files, hostname='vm', **kw):
    records = [{'path': '/etc/lvm/' + name, 'state': 'regular', 'text': text}
               for name, text in files.items()]
    for name in ('lvm.conf', 'lvmlocal.conf'):
        if name not in files:
            records.append({'path': '/etc/lvm/' + name, 'state': 'absent'})
    while True:
        result = lc.assess(records, hostname=hostname, **kw)
        unknown = [f['path'] for f in result['files'] if f['state'] == 'unknown']
        if not unknown:
            return result
        records += [{'path': path, 'state': 'absent'} for path in unknown]


def _values(result):
    return {s['setting']: s['value'] for s in result['settings']}


def _setting(result, name):
    return next(s for s in result['settings'] if s['setting'] == name)


def test_packaged_configuration_uses_build_defaults():
    result = _assess({'lvm.conf': PACKAGED_LVM_CONF, 'lvmlocal.conf': PACKAGED_LVMLOCAL_CONF})
    assert result['complete'] is True and result['lvm_starts'] is True
    assert result['origin'] == 'not_assessed' and result['run_as'] == 'root'
    assert _values(result) == {key: spec[0] for key, spec in lc.SETTINGS.items()}
    assert all(s['source'] == 'build_default' for s in result['settings'])
    thin = _setting(result, 'dmeventd/thin_command')
    assert thin['mode'] == 'internal_lvm_command'
    assert thin['argv'] == ['lvm', 'lvextend', '--use-policies', '<vg>/<lv>']
    assert _setting(result, 'global/lvmlockctl_kill_command')['disabled'] is True
    assert _setting(result, 'dmeventd/thin_library')['path_resolution'] == 'dlopen_search'


def test_section_values_path_keys_and_bare_and_quoted_strings():
    result = _assess({'lvm.conf': (
        'global { thin_check_executable = "/opt/x/check" }\n'
        'dmeventd { thin_command = "/usr/local/sbin/grow" executable="/opt/dm" }\n'
        "global/cache_check_executable = '/opt/cc'\n"
        'dmeventd/thin_library="/opt/lib.so"\n'
        '"global" { thin_dump_executable = /bare/path }\n')})
    values = _values(result)
    assert values['global/thin_check_executable'] == '/opt/x/check'
    assert values['global/cache_check_executable'] == '/opt/cc'
    assert values['global/thin_dump_executable'] == '/bare/path'
    assert values['dmeventd/executable'] == '/opt/dm'
    assert values['dmeventd/thin_library'] == '/opt/lib.so'
    assert _setting(result, 'dmeventd/thin_library')['path_resolution'] == 'absolute'
    thin = _setting(result, 'dmeventd/thin_command')
    assert thin['mode'] == 'external_program' and thin['argv'] == ['/usr/local/sbin/grow', '<vg>/<lv>']
    assert thin['source'] == '/etc/lvm/lvm.conf' and thin['changed_from_default'] is True


def test_repeated_value_last_wins_and_repeated_section_merges():
    result = _assess({'lvm.conf': 'global { fsadm_executable = "/a"\n fsadm_executable = "/b" }\n'
                                  'global { thin_dump_executable = "/c" }\n'})
    values = _values(result)
    assert values['global/fsadm_executable'] == '/b'
    assert values['global/thin_dump_executable'] == '/c'


def test_escapes_and_comment_characters_inside_strings():
    result = _assess({'lvm.conf': 'global { thin_check_executable = "/a\\"b\\\\c\\n" '
                                  'thin_dump_executable = "/a#b" # c\n}\n'})
    values = _values(result)
    assert values['global/thin_check_executable'] == '/a"b\\c\\n'
    assert values['global/thin_dump_executable'] == '/a#b'


def test_lvmlocal_then_tag_files_override_in_load_order():
    result = _assess({'lvm.conf': 'tags { t {} }\nglobal { thin_check_executable = "/a" }\n',
                      'lvmlocal.conf': 'global { thin_check_executable = "/local" }\n',
                      'lvm_t.conf': 'global { thin_check_executable = "/tag" }\n'})
    assert [f['path'] for f in result['files']] == [
        '/etc/lvm/lvm.conf', '/etc/lvm/lvmlocal.conf', '/etc/lvm/lvm_t.conf']
    assert _setting(result, 'global/thin_check_executable')['source'] == '/etc/lvm/lvm_t.conf'
    assert _values(result)['global/thin_check_executable'] == '/tag'


def test_tags_keep_file_order_chain_and_deduplicate():
    ordered = _assess({'lvm.conf': 'tags { first {} second {} }\n',
                       'lvm_first.conf': 'global { thin_check_executable = "/first" }\n',
                       'lvm_second.conf': 'global { thin_check_executable = "/second" }\n'})
    assert [t['tag'] for t in ordered['tags']] == ['first', 'second']
    assert _values(ordered)['global/thin_check_executable'] == '/second'
    chained = _assess({'lvm.conf': 'tags { a {} }\n',
                       'lvmlocal.conf': 'tags { a {} }\n',
                       'lvm_a.conf': 'tags { b {} }\nglobal { thin_repair_executable = "/a" }\n',
                       'lvm_b.conf': 'global { thin_repair_executable = "/b" }\n'})
    assert [t['tag'] for t in chained['tags']] == ['a', 'b']
    assert _values(chained)['global/thin_repair_executable'] == '/b'


def test_host_list_and_hosttags_use_the_node_name():
    files = {'lvm.conf': 'tags { db { host_list = ["other" "vm"] } }\n',
             'lvm_db.conf': 'dmeventd { vdo_command = "/opt/vdo" }\n'}
    assert _values(_assess(files))['dmeventd/vdo_command'] == '/opt/vdo'
    other = _assess(files, hostname='elsewhere')
    assert other['tags'] == [] and other['complete'] is True
    assert _values(other)['dmeventd/vdo_command'] == 'lvm lvextend --use-policies'
    for flag in ('1', '"yes"'):
        result = _assess({'lvm.conf': f'tags {{ hosttags = {flag} }}\n',
                          'lvm_vm.conf': 'global { cache_repair_executable = "/opt/cr" }\n'})
        assert result['tags'] == [{'tag': 'vm', 'source': '/etc/lvm/lvm.conf'}]
        assert _values(result)['global/cache_repair_executable'] == '/opt/cr'


def test_host_list_values_are_checked_in_order_like_check_host_filters():
    # lvm2 _check_host_filters passes on the first matching string and only
    # fails on a non-string value reached before any match.
    files = {'lvm.conf': 'tags { web { host_list = [ "web1", 7 ] } }\n',
             'lvm_web.conf': 'global { thin_check_executable = "/tmp/x" }\n'}
    matched = _assess(files, hostname='web1')
    assert matched['lvm_starts'] is True
    assert [t['tag'] for t in matched['tags']] == ['web']
    assert _values(matched)['global/thin_check_executable'] == '/tmp/x'
    assert 'invalid_host_list_lvm_commands_fail' not in {g['reason'] for g in matched['gaps']}
    for host_list in ('[ 7 ]', '[ "other", 7 ]', '[ 7, "web1" ]'):
        failed = _assess({'lvm.conf': f'tags {{ web {{ host_list = {host_list} }} }}\n'},
                         hostname='web1')
        assert failed['lvm_starts'] is False, host_list
        assert 'invalid_host_list_lvm_commands_fail' in {g['reason'] for g in failed['gaps']}
        assert failed['tags'] == []
    unknown = _assess({'lvm.conf': 'tags { web { host_list = [ "a", 7 ] } }\n'}, hostname=None)
    reasons = {g['reason'] for g in unknown['gaps']}
    assert 'hostname_unknown_for_host_list' in reasons
    assert 'invalid_host_list_lvm_commands_fail' not in reasons
    assert unknown['lvm_starts'] is not False and unknown['complete'] is False
    definite = _assess({'lvm.conf': 'tags { web { host_list = [ 7, "a" ] } }\n'}, hostname=None)
    assert definite['lvm_starts'] is False


def test_unknown_hostname_is_a_gap_not_a_silent_miss():
    result = lc.assess([{'path': '/etc/lvm/lvm.conf', 'state': 'regular',
                         'text': 'tags { hosttags = 1 db { host_list = ["vm"] } }\n'},
                        {'path': '/etc/lvm/lvmlocal.conf', 'state': 'absent'}])
    reasons = {g['reason'] for g in result['gaps']}
    assert {'hostname_unknown_for_hosttags', 'hostname_unknown_for_host_list'} <= reasons
    assert result['complete'] is False


def test_section_tags_filter_skips_or_keeps_a_section():
    skipped = _assess({'lvm.conf': 'global { tags = ["@nope"] thin_check_executable = "/skipped" }\n'})
    assert _values(skipped)['global/thin_check_executable'] == '/usr/sbin/thin_check'
    kept = _assess({'lvm.conf': 'tags { yes {} }\nglobal { tags = ["@yes"] thin_check_executable = "/kept" }\n'})
    assert _values(kept)['global/thin_check_executable'] == '/kept'


def test_later_subsections_are_ignored_but_values_merge():
    result = _assess({'lvm.conf': 'global { x = 1 }\n',
                      'lvmlocal.conf': 'global { sub { y = 2 } thin_check_executable = "/l" }\n'})
    assert _values(result)['global/thin_check_executable'] == '/l'


def test_wrong_type_and_forbidden_empty_values_fall_back_to_defaults():
    result = _assess({'lvm.conf': 'global { thin_check_executable = 5 fsadm_executable = ["/x"] '
                                  'thin_dump_executable = ["/y", "/z"] thin_repair_executable = [] '
                                  'cache_check_executable = "" }\n'
                                  'dmeventd { thin_command = "" executable = "" }\n'})
    values = _values(result)
    assert values['global/thin_check_executable'] == '/usr/sbin/thin_check'
    assert values['global/fsadm_executable'] == '/x'
    assert values['global/thin_dump_executable'] == '/y'
    assert values['global/thin_repair_executable'] == '/usr/sbin/thin_repair'
    assert values['dmeventd/thin_command'] == 'lvm lvextend --use-policies'
    assert values['dmeventd/executable'] == '/usr/sbin/dmeventd'
    assert values['global/cache_check_executable'] == ''
    assert _setting(result, 'global/cache_check_executable')['disabled'] is True
    reasons = sorted((w['reason'], w['setting']) for w in result['warnings'])
    assert ('invalid_type_default_used', 'global/thin_check_executable') in reasons
    assert ('empty_not_allowed_default_used', 'dmeventd/thin_command') in reasons
    assert ('array_first_value_used', 'global/thin_dump_executable') in reasons
    assert ('invalid_type_default_used', 'global/thin_repair_executable') in reasons


def test_dmeventd_command_modes_follow_the_thin_plugin():
    spaced = _assess({'lvm.conf': 'dmeventd { thin_command = "/usr/local/bin/grow --fast" '
                                  'vdo_command = "lvextend" }\n'})
    thin = _setting(spaced, 'dmeventd/thin_command')
    assert thin['argv'] == ['/usr/local/bin/grow --fast', '<vg>/<lv>']
    assert {'reason': 'whole_value_is_program_path', 'setting': 'dmeventd/thin_command'} in spaced['warnings']
    assert _setting(spaced, 'dmeventd/vdo_command')['mode'] == 'invalid_monitoring_fails'


def test_lvmlockctl_kill_command_gets_the_vg_name():
    result = _assess({'lvm.conf': 'global { lvmlockctl_kill_command = "/usr/sbin/blkdeactivate -r wait" }\n'})
    kill = _setting(result, 'global/lvmlockctl_kill_command')
    assert kill['program'] == '/usr/sbin/blkdeactivate'
    assert kill['argv'] == ['/usr/sbin/blkdeactivate', '-r', 'wait', '<vg>']


def test_parse_errors_and_lvm_refusals_are_blocking():
    for text, reason in (('global { thin_check_executable = }\n', 'expected_value'),
                         ('global { thin_check_executable = "/x"\n', 'unexpected_token'),
                         ('global { x = "open\n', 'unterminated_string')):
        result = _assess({'lvm.conf': text})
        assert result['lvm_starts'] is False and result['complete'] is False
        assert result['gaps'][0]['reason'] == 'parse_error_lvm_commands_fail'
        assert result['gaps'][0]['detail'] == reason
        assert all(s['runs_only_if_config_loads'] for s in result['settings'])
    for text, reason in (('tags { a { host_filter = "x" } }\n', 'host_filter_unsupported_lvm_commands_fail'),
                         ('tags { "a b" {} }\n', 'invalid_tag_lvm_commands_fail')):
        result = _assess({'lvm.conf': text})
        assert result['lvm_starts'] is False and reason in {g['reason'] for g in result['gaps']}


def test_unobserved_unreadable_and_hostile_input_are_gaps():
    result = lc.assess([{'path': '/etc/lvm/lvm.conf', 'state': 'unreadable'}], hostname='vm')
    reasons = [g['reason'] for g in result['gaps']]
    assert reasons == ['file_unreadable', 'file_unknown'] and result['complete'] is False
    for text, reason in (('global {\x00}', 'nul_byte'), (b'\xff', 'invalid_utf8'),
                         ('#' * (lc.MAX_TEXT + 1), 'file_too_large'), (None, 'file_text_missing')):
        result = lc.assess([{'path': '/etc/lvm/lvm.conf', 'state': 'regular', 'text': text},
                            {'path': '/etc/lvm/lvmlocal.conf', 'state': 'absent'}])
        assert [g['reason'] for g in result['gaps']] == [reason]
    deep = 'a {' * (lc.MAX_DEPTH + 2) + '}' * (lc.MAX_DEPTH + 2)
    assert _assess({'lvm.conf': deep})['gaps'][0]['detail'] == 'nesting_limit'


def test_contract_reports_not_modelled_inputs_and_never_authorizes():
    result = _assess({'lvm.conf': PACKAGED_LVM_CONF})
    assert 'lvm_command_line_config_and_LVM_SYSTEM_DIR' in result['not_modelled']
    assert 'initramfs_copy_of_lvm_conf' in result['not_modelled']
    assert not any(k in result for k in ('authorized', 'action', 'response'))
