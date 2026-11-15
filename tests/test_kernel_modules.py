from app import kernel_modules as km


def f(path, text='', **extra):
    return {'path': path, 'text': text, **extra}


def codes(result):
    return [g['code'] for g in result['gaps']]


def status(result):
    return {r['path']: r['status'] for r in result['files']}


def test_effective_files_follow_directory_priority_and_name_order():
    result = km.resolve_modprobe([
        f('/usr/lib/modprobe.d/50-b.conf', 'blacklist lower\n'),
        f('/etc/modprobe.d/50-b.conf', 'blacklist upper\n'),
        f('/run/modprobe.d/10-a.conf', 'blacklist first\n'),
        f('/lib/modprobe.d/10-a.conf', 'blacklist hidden\n'),
        f('/etc/modprobe.d/notes.txt', 'install x /bin/evil\n'),
        f('/etc/modprobe.d/.hidden.conf', 'install x /bin/evil\n'),
        f('/etc/modprobe.d/sub.conf', None, type='directory'),
        f('/opt/modprobe.d/x.conf', 'install x /bin/evil\n'),
    ])
    assert [b['module'] for b in result['blacklist']] == ['first', 'upper']
    assert status(result) == {
        '/usr/lib/modprobe.d/50-b.conf': 'overridden', '/etc/modprobe.d/50-b.conf': 'effective',
        '/run/modprobe.d/10-a.conf': 'effective', '/lib/modprobe.d/10-a.conf': 'overridden',
        '/etc/modprobe.d/notes.txt': 'ignored', '/etc/modprobe.d/.hidden.conf': 'ignored',
        '/etc/modprobe.d/sub.conf': 'ignored', '/opt/modprobe.d/x.conf': 'ignored'}
    reasons = {r['path']: r.get('reason') for r in result['files']}
    assert reasons['/etc/modprobe.d/notes.txt'] == 'not_conf_suffix'
    assert reasons['/etc/modprobe.d/.hidden.conf'] == 'hidden'
    assert reasons['/etc/modprobe.d/sub.conf'] == 'not_regular_file'
    assert reasons['/opt/modprobe.d/x.conf'] == 'outside_known_directories'
    overridden = next(r for r in result['files'] if r['path'] == '/usr/lib/modprobe.d/50-b.conf')
    assert overridden['overridden_by'] == '/etc/modprobe.d/50-b.conf'
    assert result['install'] == [] and result['complete'] is True
    assert result['origin'] == 'not_assessed' and 'not a safety verdict' in result['note']
    assert {u['code'] for u in result['unobserved']} >= {'kernel_command_line', 'initramfs_copy'}


def test_directives_comments_continuations_and_name_normalization():
    text = ('# install commented /bin/evil\n'
            '   \t# indented comment\n'
            'install snd-usb-audio /usr/local/bin/hook --flag \\\n'
            '   && /sbin/modprobe --ignore-install snd-usb-audio # not a comment\n'
            'remove snd-usb-audio /usr/local/bin/unhook\n'
            'alias net-pf-10 my-ipv6\n'
            'blacklist nouveau\n'
            'options loop max_loop=64 max_part=8\n'
            'softdep nf-conntrack pre: nf-defrag-ipv4 a post: b\n'
            'weakdep foo bar-baz\n')
    result = km.resolve_modprobe([f('/etc/modprobe.d/a.conf', text.encode())])
    install, = result['install']
    assert install['module'] == 'snd_usb_audio' and install['line'] == 3 and install['kind'] == 'command'
    assert install['command'] == ('/usr/local/bin/hook --flag    && /sbin/modprobe --ignore-install '
                                  'snd-usb-audio # not a comment')
    assert install['command_sha256'] == km._sha(install['command']) and install['command_truncated'] is False
    assert result['remove'][0]['line'] == 5 and result['remove'][0]['command'] == '/usr/local/bin/unhook'
    assert result['aliases'] == [{'alias': 'net_pf_10', 'module': 'my_ipv6', 'path': '/etc/modprobe.d/a.conf',
                                  'line': 6}]
    assert result['blacklist'][0]['module'] == 'nouveau'
    assert result['options'][0]['options'] == 'max_loop=64 max_part=8'
    assert result['softdeps'][0]['pre'] == ['nf_defrag_ipv4', 'a'] and result['softdeps'][0]['post'] == ['b']
    assert result['softdeps'][0]['module'] == 'nf_conntrack'
    assert result['weakdeps'][0]['modules'] == ['bar_baz']
    assert result['gaps'] == [] and result['complete'] is True
    assert km.normalize('a-b[x-z]-c') == 'a_b[x-z]_c'


def test_reported_but_non_blocking_line_problems():
    text = ('include /etc/other.conf\nconfig binary_indexes yes\nfrobnicate x y\ninstall onlyname\n'
            'blacklist\noptions loop\nsoftdep a b pre: c\n')
    result = km.resolve_modprobe([f('/etc/modprobe.d/a.conf', text)])
    assert codes(result) == ['deprecated_directive_ignored', 'deprecated_directive_ignored', 'unknown_directive',
                             'malformed_directive', 'malformed_directive', 'malformed_directive',
                             'malformed_directive']
    assert [g['line'] for g in result['gaps']] == [1, 2, 3, 4, 5, 6, 7]
    assert all(g['path'] == '/etc/modprobe.d/a.conf' for g in result['gaps'])
    assert result['install'] == [] and result['complete'] is True
    assert result['softdeps'][0]['pre'] == ['c']


def test_disable_idiom_shadowing_and_first_match_selection():
    result = km.resolve_modprobe([
        f('/etc/modprobe.d/10-cis.conf', 'install cramfs /bin/false\ninstall usb-storage /bin/true\n'
                                         'install dccp /bin/false; /tmp/x\n'),
        f('/etc/modprobe.d/20-late.conf', 'install cramfs /opt/evil.sh\ninstall usb_* /opt/wild.sh\n'),
    ])
    kinds = [(e['module'], e['kind'], e['shadowed_by'], e['wildcard']) for e in result['install']]
    assert kinds == [('cramfs', 'disable', None, False), ('usb_storage', 'disable', None, False),
                     ('dccp', 'command', None, False), ('cramfs', 'command', 0, False),
                     ('usb_*', 'command', None, True)]
    found = km.commands_for(result, 'usb-storage')
    assert found['selected']['command'] == '/bin/true'
    assert [e['command'] for e in found['shadowed']] == ['/opt/wild.sh']
    assert km.commands_for(result, 'usb_hid')['selected']['command'] == '/opt/wild.sh'
    assert km.commands_for(result, 'ext4') == {'selected': None, 'shadowed': []}
    assert km.commands_for(result, 'cramfs', 'remove')['selected'] is None
    assert km.commands_for(result, 'cramfs', 'other') == {'selected': None, 'shadowed': []}


def test_unreadable_winner_shadows_lower_file_and_marks_incomplete():
    lower = f('/usr/lib/modprobe.d/x.conf', 'install lower /bin/lower\n')
    for winner, code in ((f('/etc/modprobe.d/x.conf', None), 'file_unreadable'),
                         (f('/etc/modprobe.d/x.conf', None, type='symlink', link_target='../other'),
                          'symlink_not_followed'),
                         (f('/etc/modprobe.d/x.conf', b'install \xff /bin/x\n'), 'invalid_utf8'),
                         (f('/etc/modprobe.d/x.conf', 'install a /bin/x\x00\n'), 'nul_byte'),
                         (f('/etc/modprobe.d/x.conf', 'x' * (km.MAX_TEXT + 1)), 'text_over_limit'),
                         (f('/etc/modprobe.d/x.conf', b'x' * (km.MAX_TEXT + 1)), 'text_over_limit')):
        result = km.resolve_modprobe([winner, lower])
        assert codes(result) == [code]
        assert result['complete'] is False and result['install'] == []
        assert status(result) == {'/etc/modprobe.d/x.conf': 'unreadable', '/usr/lib/modprobe.d/x.conf': 'overridden'}


def test_dev_null_symlink_masks_without_a_gap():
    result = km.resolve_modprobe([
        f('/etc/modprobe.d/x.conf', None, type='symlink', link_target='/dev/null'),
        f('/usr/lib/modprobe.d/x.conf', 'install lower /bin/lower\n')])
    assert status(result)['/etc/modprobe.d/x.conf'] == 'masked'
    assert result['install'] == [] and result['gaps'] == [] and result['complete'] is True


def test_bounds_and_malformed_input_fail_closed():
    many = [f(f'/etc/modprobe.d/{i}.conf', 'install a /bin/x\n') for i in range(km.MAX_FILES + 1)]
    result = km.resolve_modprobe(many)
    assert codes(result) == ['too_many_files'] and result['files'] == [] and result['install'] == []
    assert result['complete'] is False
    assert codes(km.resolve_modprobe(None)) == ['input_malformed']
    bad = km.resolve_modprobe(['x', {'path': 'relative.conf'}, {'path': '/etc/modprobe.d/../a.conf'},
                               f('/etc/modprobe.d/a.conf', 'blacklist a\n'), f('/etc/modprobe.d/a.conf', '')])
    assert codes(bad) == ['input_malformed'] * 3 + ['duplicate_path'] and bad['complete'] is False
    assert [b['module'] for b in bad['blacklist']] == ['a']
    big = km.resolve_modprobe([f('/etc/modprobe.d/a.conf', 'blacklist m\n' * (km.MAX_ENTRIES + 5)),
                               f('/etc/modprobe.d/b.conf', 'install late /bin/late\n')])
    assert codes(big) == ['too_many_entries'] and len(big['blacklist']) == km.MAX_ENTRIES
    assert big['install'] == [] and big['complete'] is False
    long = km.resolve_modprobe([f('/etc/modprobe.d/a.conf', 'install ' + 'm' * 300 + ' /bin/x\n'
                                  'install ok /bin/' + 'y' * 3000 + '\n')])
    assert codes(long) == ['field_over_limit'] and long['complete'] is False
    entry, = long['install']
    assert len(entry['command']) == km.MAX_COMMAND and entry['command_truncated'] is True
    assert entry['command_sha256'] == km._sha('/bin/' + 'y' * 3000)
    noisy = km.resolve_modprobe([f('/etc/modprobe.d/a.conf', 'bogus\n' * 200)])
    assert len(noisy['gaps']) == km.MAX_GAPS and noisy['gaps'][-1]['code'] == 'gaps_truncated'
    assert noisy['complete'] is False


def test_modules_load_files_comments_and_etc_modules_link():
    result = km.resolve_modules_load([
        f('/usr/lib/modules-load.d/20-virt.conf', 'virtio-net\n'),
        f('/etc/modules-load.d/20-virt.conf', '# override\n; other comment\n\nvhost_net\n'),
        f('/etc/modules-load.d/modules.conf', None, type='symlink', link_target='../modules'),
        f('/etc/modules', '# /etc/modules\nloop max_loop=8\n'),
        f('/etc/modules-load.d/readme', 'evil\n'),
    ])
    assert [(m['module'], m['path'], m['line'], m['extra_tokens']) for m in result['modules']] == [
        ('vhost_net', '/etc/modules-load.d/20-virt.conf', 4, 0), ('loop', '/etc/modules', 2, 1)]
    assert codes(result) == ['extra_tokens_not_interpreted'] and result['complete'] is True
    states = status(result)
    assert states['/usr/lib/modules-load.d/20-virt.conf'] == 'overridden'
    assert states['/etc/modules-load.d/modules.conf'] == 'effective' and states['/etc/modules'] == 'effective'
    record = next(r for r in result['files'] if r['path'] == '/etc/modules')
    assert record['linked_from'] == '/etc/modules-load.d/modules.conf' and len(record['sha256']) == 64
    assert {u['code'] for u in result['unobserved']} == {'kernel_command_line', 'other_boot_requests'}


def test_etc_modules_without_link_is_still_reported_and_bad_link_is_a_gap():
    alone = km.resolve_modules_load([f('/etc/modules', 'dummy\n')])
    assert [m['module'] for m in alone['modules']] == ['dummy']
    assert alone['files'][0]['reason'] == 'not_linked_from_modules_load_d'
    broken = km.resolve_modules_load([
        f('/etc/modules-load.d/modules.conf', None, type='symlink', link_target='../modules')])
    assert codes(broken) == ['symlink_not_followed'] and broken['complete'] is False
    unread = km.resolve_modules_load([f('/etc/modules', None)])
    assert codes(unread) == ['file_unreadable'] and unread['files'][0]['status'] == 'unreadable'


def test_boot_chains_follow_aliases_and_softdeps_in_order():
    modprobe = km.resolve_modprobe([f('/etc/modprobe.d/p.conf', (
        'alias persist real-mod\n'
        'softdep real-mod pre: helper post: after\n'
        'install helper /opt/pre.sh\n'
        'install real_mod /opt/main.sh\n'
        'install helper /opt/pre-second.sh\n'
        'install after /bin/false\n'
        'install unused /opt/never.sh\n'
        'blacklist helper\n'))])
    load = km.resolve_modules_load([f('/etc/modules-load.d/p.conf', 'persist\nplain\n')])
    result = km.boot_commands(modprobe, load)
    # Matches `modprobe -n -v persist` from kmod 31: a module with softdeps skips its own command.
    assert [(c['module'], c['kind'], c['command']) for c in result['chains']] == [
        ('helper', 'command', '/opt/pre.sh'), ('after', 'disable', '/bin/false')]
    first, last = result['chains']
    assert first['via'] == [{'relation': 'alias', 'module': 'real_mod'},
                            {'relation': 'softdep_pre', 'module': 'helper'}]
    assert first['blacklisted'] is True and last['blacklisted'] is False
    assert first['shadowed_definitions'] == 1 and first['source'] == {'path': '/etc/modprobe.d/p.conf', 'line': 3}
    assert first['boot_module'] == 'persist' and 'reason' not in first
    assert first['requested_by'] == {'path': '/etc/modules-load.d/p.conf', 'line': 1}
    assert last['via'][-1] == {'relation': 'softdep_post', 'module': 'after'}
    skipped, = result['ignored']
    assert (skipped['module'], skipped['command'], skipped['reason']) == (
        'real_mod', '/opt/main.sh', 'module_has_softdep')
    assert result['commands'] == 1 and result['disabled'] == 1 and result['complete'] is True
    assert 'not a safety verdict' in result['note']


def test_boot_chains_bound_loops_depth_and_incomplete_inputs():
    loop = km.resolve_modprobe([f('/etc/modprobe.d/l.conf',
                                  'softdep a pre: b\nsoftdep b pre: a c post: c\ninstall c /opt/c.sh\n'
                                  'softdep empty pre:\ninstall empty /opt/empty.sh\n')])
    load = km.resolve_modules_load([f('/etc/modules-load.d/l.conf', 'a\nempty\n')])
    result = km.boot_commands(loop, load)
    # c is requested once per probe even though it is both a pre and a post dependency;
    # an empty softdep does not suppress the module's own command.
    assert [c['module'] for c in result['chains']] == ['c', 'empty'] and result['ignored'] == []
    assert loop['gaps'] == [] and result['complete'] is True
    deep_text = ''.join(f'softdep m{i} pre: m{i + 1}\n' for i in range(12)) + 'install m12 /opt/deep.sh\n'
    deep = km.boot_commands(km.resolve_modprobe([f('/etc/modprobe.d/d.conf', deep_text)]),
                            km.resolve_modules_load([f('/etc/modules-load.d/d.conf', 'm0\n')]))
    assert deep['chains'] == [] and codes(deep) == ['chain_depth_exceeded'] and deep['complete'] is False
    partial = km.boot_commands(km.resolve_modprobe([f('/etc/modprobe.d/x.conf', None)]), load)
    assert codes(partial) == ['dependency_incomplete'] and partial['complete'] is False
    wrong = km.boot_commands({'mechanism': 'modules_load'}, None)
    assert codes(wrong) == ['input_malformed', 'input_malformed'] and wrong['chains'] == []
    wide = km.resolve_modprobe([f('/etc/modprobe.d/w.conf', 'install * /opt/all.sh\n')])
    many = km.resolve_modules_load([f('/etc/modules-load.d/w.conf',
                                      ''.join(f'mod{i}\n' for i in range(km.MAX_CHAINS + 3)))])
    capped = km.boot_commands(wide, many)
    assert len(capped['chains']) == km.MAX_CHAINS and codes(capped) == ['too_many_chains']
    assert capped['complete'] is False
    names = [f'n{i}' for i in range(40)]
    fan = km.resolve_modprobe([f('/etc/modprobe.d/f.conf',
                                 ''.join(f'softdep {n} pre: {" ".join(names)}\n' for n in names))])
    budget = km.boot_commands(fan, km.resolve_modules_load([f('/etc/modules-load.d/f.conf', 'n0\n')]))
    assert 'resolution_budget_exceeded' in codes(budget) and budget['complete'] is False


def test_results_never_execute_or_import_io():
    source = open(km.__file__, encoding='utf-8').read()
    for forbidden in ('subprocess', 'os.system', 'import os', 'open(', 'socket'):
        assert forbidden not in source


def _boot(text, module):
    modprobe = km.resolve_modprobe([f('/etc/modprobe.d/p.conf', text)])
    load = km.resolve_modules_load([f('/etc/modules-load.d/p.conf', module + '\n')])
    return modprobe, km.boot_commands(modprobe, load)


def test_alias_target_is_not_resolved_as_an_alias_again():
    # `modprobe -n -v a` (kmod 31) prints EVIL-b here; review of #954.
    text = 'alias a b\nalias b c\ninstall b /bin/echo EVIL-b\ninstall c /bin/echo cmd-c\n'
    assert [c['command'] for c in _boot(text, 'a')[1]['chains']] == ['/bin/echo EVIL-b']
    assert [c['command'] for c in _boot(text, 'b')[1]['chains']] == ['/bin/echo cmd-c']
    both = 'alias a b\nalias a c\ninstall b /bin/echo cb\ninstall c /bin/echo cc\n'
    assert [c['command'] for c in _boot(both, 'a')[1]['chains']] == ['/bin/echo cb', '/bin/echo cc']
    own = 'alias a a\ninstall a /bin/echo self\n'
    assert [c['command'] for c in _boot(own, 'a')[1]['chains']] == ['/bin/echo self']


def test_only_the_first_matching_softdep_is_used():
    empty_first = 'softdep m pre:\nsoftdep m pre: p\ninstall m /bin/echo own-m\ninstall p /bin/echo cmd-p\n'
    result = _boot(empty_first, 'm')[1]
    assert [c['command'] for c in result['chains']] == ['/bin/echo own-m'] and result['ignored'] == []
    split = ('softdep m pre: p\nsoftdep m post: q\ninstall m /bin/echo own-m\ninstall p /bin/echo cmd-p\n'
             'install q /bin/echo cmd-q\n')
    result = _boot(split, 'm')[1]
    assert [c['command'] for c in result['chains']] == ['/bin/echo cmd-p']
    assert [c['command'] for c in result['ignored']] == ['/bin/echo own-m']


def test_backslash_pattern_is_a_blocking_gap():
    modprobe, result = _boot('install b\\* /bin/echo esc\nblacklist c\\d\n', 'b*')
    assert codes(modprobe) == ['pattern_escape_not_interpreted'] and modprobe['complete'] is False
    assert codes(result) == ['dependency_incomplete'] and result['complete'] is False
