from app import polkit_rules as pr

ETC = '/etc/polkit-1/rules.d'
SHARE = '/usr/share/polkit-1/rules.d'
POLKITD = 998


def f(name, mode=0o644, uid=0, gid=0, **extra):
    return {'name': name, 'type': 'file', 'mode': mode, 'uid': uid, 'gid': gid, **extra}


def link(name, target=..., text='/opt/x.rules'):
    item = {'name': name, 'type': 'symlink', 'link_target': text}
    if target is not ...:
        item['target'] = target
    return item


def listed(*entries, mode=0o755, uid=0, gid=0, complete=True):
    return {'state': 'listed', 'complete': complete, 'mode': mode, 'uid': uid, 'gid': gid,
            'entries': list(entries)}


EMPTY = listed()


def run(etc=EMPTY, share=EMPTY, version='124-2ubuntu1', uid=POLKITD, gids=(POLKITD,), **kwargs):
    return pr.evaluate(polkit_version=version, polkitd_uid=uid, polkitd_gids=list(gids) if gids else gids,
                       etc_rules=etc, share_rules=share, **kwargs)


def entries(result):
    return {entry['path']: entry for entry in result['entries']}


def codes(result):
    return [gap['code'] for gap in result['gaps']]


def order(result):
    return [item['path'] for item in result['load_order']]


def test_both_directories_load_without_shadowing_sorted_by_basename_then_path():
    result = run(etc=listed(f('50-local.rules'), f('10-admin.rules')),
                 share=listed(f('50-local.rules'), f('49-vendor.rules'), f('10-admin.rules')))
    assert result['complete'] is True
    assert order(result) == [f'{ETC}/10-admin.rules', f'{SHARE}/10-admin.rules', f'{SHARE}/49-vendor.rules',
                             f'{ETC}/50-local.rules', f'{SHARE}/50-local.rules']
    twice = [item for item in result['load_order'] if 'loaded_twice' in item['observations']]
    assert len(twice) == 4
    assert result['runs_as'] == 'polkitd'


def test_only_rules_suffix_is_loaded_and_hidden_or_backup_names_are_not_skipped():
    result = run(etc=listed(f('.hidden.rules'), f('a.rules.bak'), f('a.rules~'), f('b.rules.dpkg-old'),
                            f('.rules'), f('notes.txt'), f('c.RULES')))
    assert order(result) == [f'{ETC}/.hidden.rules', f'{ETC}/.rules']
    found = entries(result)
    for name in ('a.rules.bak', 'a.rules~', 'b.rules.dpkg-old', 'notes.txt', 'c.RULES'):
        assert found[f'{ETC}/{name}']['reason_code'] == 'not_rules_suffix'


def test_sort_is_bytewise_strcmp_not_locale_or_natural():
    result = run(share=listed(f('b.rules'), f('B.rules'), f('10.rules'), f('9.rules'), f('é.rules'), f('_.rules')))
    assert [item['name'] for item in result['load_order']] == \
        ['10.rules', '9.rules', 'B.rules', '_.rules', 'b.rules', 'é.rules']


def test_non_regular_entries_named_rules():
    result = run(etc=listed({'name': 'd.rules', 'type': 'directory'}, {'name': 'p.rules', 'type': 'fifo'},
                            link('null.rules', {'type': 'char_device'}, text='/dev/null'),
                            link('dangling.rules', None)))
    found = entries(result)
    assert found[f'{ETC}/d.rules']['reason_code'] == 'directory'
    assert found[f'{ETC}/null.rules']['reason_code'] == 'empty_device'
    assert found[f'{ETC}/dangling.rules']['reason_code'] == 'unresolvable'
    assert found[f'{ETC}/p.rules']['status'] == 'unresolved'
    assert 'open_behavior_unmodelled' in codes(result)
    assert result['complete'] is False
    assert result['load_order'] == []


def test_symlink_to_file_is_conditional_and_target_owner_is_checked():
    result = run(etc=listed(link('60-x.rules', {'type': 'file', 'mode': 0o666, 'uid': 1000, 'gid': 1000})))
    assert result['complete'] is True
    item = result['load_order'][0]
    assert item['status'] == 'conditional'
    assert item['link_target'] == '/opt/x.rules'
    assert set(item['observations']) == {'not_root_owned', 'group_or_world_writable'}


def test_readability_follows_polkitd_identity():
    result = run(etc=listed(f('a.rules', mode=0o600), f('b.rules', mode=0o640, gid=POLKITD),
                            f('c.rules', mode=0o600, uid=POLKITD), f('d.rules', mode=0o604),
                            f('e.rules', mode=0o040, gid=POLKITD)))
    found = entries(result)
    assert found[f'{ETC}/a.rules']['reason_code'] == 'not_readable'
    assert order(result) == [f'{ETC}/b.rules', f'{ETC}/c.rules', f'{ETC}/d.rules', f'{ETC}/e.rules']
    # The owner class wins even when it grants less than the group class.
    owned = run(etc=listed(f('o.rules', mode=0o044, uid=POLKITD, gid=POLKITD)))
    assert entries(owned)[f'{ETC}/o.rules']['reason_code'] == 'not_readable'


def test_directory_polkitd_cannot_list_skips_its_files():
    result = run(etc=listed(f('a.rules'), mode=0o700, uid=0, gid=0), share=listed(f('b.rules')))
    assert entries(result)[f'{ETC}/a.rules']['reason_code'] == 'directory_not_readable'
    assert order(result) == [f'{SHARE}/b.rules']
    assert result['directories'][0]['polkitd_can_list'] is False
    # Debian and Fedora ship /etc/polkit-1/rules.d as 0700 polkitd.
    shipped = run(etc=listed(f('a.rules'), mode=0o700, uid=POLKITD))
    assert order(shipped) == [f'{ETC}/a.rules']


def test_missing_identity_is_blocking_unless_every_class_grants_read():
    result = run(etc=listed(f('a.rules', mode=0o644), f('b.rules', mode=0o640)), uid=None, gids=None)
    assert 'reader_identity_unobserved' in codes(result)
    assert result['complete'] is False
    assert order(result) == [f'{ETC}/a.rules']
    assert entries(result)[f'{ETC}/b.rules']['status'] == 'unresolved'


def test_absent_directories_are_covered_but_unobserved_or_unreadable_are_gaps():
    absent = run(etc={'state': 'absent', 'entries': []}, share=listed(f('a.rules')))
    assert absent['complete'] is True and order(absent) == [f'{SHARE}/a.rules']
    missing = pr.evaluate(polkit_version=124, polkitd_uid=1, polkitd_gids=[1], share_rules=EMPTY)
    assert 'directory_not_observed' in codes(missing) and missing['complete'] is False
    unreadable = run(etc={'state': 'unreadable', 'entries': [f('a.rules')]})
    assert 'directory_unreadable' in codes(unreadable)
    assert entries(unreadable)[f'{ETC}/a.rules']['status'] == 'unresolved'
    partial = run(etc=listed(f('a.rules'), complete=False))
    assert 'listing_incomplete' in codes(partial) and partial['complete'] is False


def test_versions():
    assert pr.parse_version('0.120-3') == 120
    assert pr.parse_version('124-2ubuntu1') == 124
    assert pr.parse_version(125) == 125
    assert pr.parse_version('x') is None
    assert 'legacy_pkla_backend' in codes(run(version='0.105-33'))
    assert 'version_unsupported' in codes(run(version='0.116'))
    assert 'version_unsupported' in codes(run(version='126'))
    assert 'version_not_observed' in codes(run(version=None))
    assert run(version='0.120')['complete'] is True


def test_acl_and_malformed_and_duplicate_input_fail_closed():
    acl = run(etc=listed(f('a.rules', acl=True)))
    assert 'acl_not_modelled' in codes(acl) and acl['complete'] is False and acl['load_order'] == []
    bad = run(etc=listed({'name': 'a/b.rules', 'type': 'file'}, {'name': 'x.rules', 'type': 'file', 'mode': 0o644}))
    assert codes(bad).count('input_malformed') == 1
    assert 'metadata_missing' in codes(bad)
    dup = run(etc=listed(f('a.rules'), f('a.rules', mode=0o600)))
    assert 'duplicate_name' in codes(dup) and order(dup) == [f'{ETC}/a.rules']
    unobserved_link = run(etc=listed(link('l.rules')))
    assert 'symlink_target_unobserved' in codes(unobserved_link)
    assert 'input_malformed' in codes(run(uid='polkitd', gids=[1]))
    assert 'input_malformed' in codes(run(etc={'state': 'listed', 'entries': []}))


def test_limits():
    many = run(etc=listed(*[f(f'{n:05d}.rules') for n in range(pr.MAX_ENTRIES + 5)]))
    assert 'too_many_entries' in codes(many)
    assert len(many['load_order']) == pr.MAX_ENTRIES
    noisy = run(etc=listed(*[{'name': f'{n}.rules', 'type': 'fifo'} for n in range(pr.MAX_GAPS + 10)]))
    assert len(noisy['gaps']) == pr.MAX_GAPS
    assert noisy['gaps'][-1]['code'] == 'gaps_truncated'


def test_result_never_claims_a_verdict():
    result = run(etc=listed(f('a.rules')))
    assert result['origin'] == 'not_assessed'
    assert 'not a safety verdict' in result['note']
    assert any('polkit.spawn' in line for line in result['unobserved'])
