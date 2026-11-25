from app import kdump_hooks as kd

EXE = {'type': 'file', 'mode': 0o755}


def _listing(*entries, state='listed'):
    return {'state': state, 'entries': list(entries)}


def _dirs(pre=None, post=None, emergency=None):
    absent = {'state': 'absent'}
    return {'pre': pre or absent, 'post': post or absent, 'emergency': emergency or absent}


def _seq(result):
    return [(step['stage'], step['source'], step['program'], step['args']) for step in result['sequence']]


def test_parse_config_comments_quotes_and_whitespace():
    text = ('# header\n   # indented comment\n\n \t\n'
            'kdump_pre   "/usr/local/bin/pre.sh"  # trailing\n'
            '\tcore_collector makedumpfile -l --message-level 7 -d 31\n'
            'kdump_post /usr/bin/post#cut\n')
    assert kd.parse_config(text) == [
        (5, 'kdump_pre', '/usr/local/bin/pre.sh'),
        (6, 'core_collector', 'makedumpfile -l --message-level 7 -d 31'),
        (7, 'kdump_post', '/usr/bin/post'),
    ]


def test_order_is_kdump_pre_before_pre_d_and_post_d_before_kdump_post():
    text = 'xfs /dev/sda1\nkdump_pre /bin/pre\nkdump_post /bin/post\nkdump_emergency /bin/emerg\n'
    dirs = _dirs(pre=_listing(dict(EXE, name='20-b'), dict(EXE, name='10-a')),
                 post=_listing(dict(EXE, name='p1')), emergency=_listing(dict(EXE, name='e1')))
    result = kd.assess(text, dirs)
    assert result['starts'] is True and result['covered'] is True
    assert _seq(result) == [
        ('pre', 'kdump_pre', '/bin/pre', []),
        ('pre', 'pre.d', '/etc/kdump/pre.d/10-a', []),
        ('pre', 'pre.d', '/etc/kdump/pre.d/20-b', []),
        ('dump', 'core_collector', 'makedumpfile', []),
        ('post', 'post.d', '/etc/kdump/post.d/p1', ['<dump status>']),
        ('post', 'kdump_post', '/bin/post', ['<dump status>']),
        ('emergency', 'emergency.d', '/etc/kdump/emergency.d/e1', []),
        ('emergency', 'kdump_emergency', '/bin/emerg', []),
    ]
    first = result['sequence'][0]
    assert first['on_failure'] == 'skip_dump_and_run_final_action'
    assert 'pre_failure_skips_dump' in first['observations']
    assert all(step['on_failure'] == 'warn' for step in result['sequence'][1:] if step['stage'] != 'dump')
    assert all('runs_on_capture_failure' in step['observations']
               for step in result['sequence'] if step['stage'] == 'emergency')


def test_hook_value_with_arguments_is_one_word_and_core_collector_is_split():
    result = kd.assess('kdump_pre /usr/bin/notify --crash\ncore_collector cp --sparse=always\n', _dirs())
    pre, dump = result['sequence']
    assert pre['program'] == '/usr/bin/notify --crash' and pre['args'] == []
    assert 'value_has_whitespace' in pre['observations']
    assert (dump['program'], dump['args']) == ('cp', ['--sparse=always'])


def test_relative_hook_and_extra_bins_are_reported():
    result = kd.assess('kdump_post logger\nextra_bins /usr/bin/a /usr/bin/b\n', _dirs())
    post = [step for step in result['sequence'] if step['source'] == 'kdump_post'][0]
    assert 'relative_path' in post['observations']
    assert result['installed_not_run'] == ['/usr/bin/a', '/usr/bin/b']


def test_directory_filtering():
    dirs = _dirs(pre=_listing(
        dict(EXE, name='.hidden'), dict(EXE, name='run'), {'name': 'noexec', 'type': 'file', 'mode': 0o644},
        {'name': 'sub', 'type': 'directory', 'mode': 0o755}, {'name': 'broken', 'type': 'dangling', 'mode': None},
        dict(EXE, name='old.rpmsave')))
    result = kd.assess('', dirs)
    reasons = {item['name']: (item['runs'], item['reason']) for item in result['directory_entries']['pre']}
    assert reasons == {'.hidden': (False, 'hidden'), 'run': (True, 'installed'),
                       'noexec': (False, 'not_executable'), 'sub': (False, 'not_regular'),
                       'broken': (False, 'unresolvable'), 'old.rpmsave': (True, 'installed')}
    assert [step['program'] for step in result['sequence'] if step['stage'] == 'pre'] == [
        '/etc/kdump/pre.d/old.rpmsave', '/etc/kdump/pre.d/run']
    assert result['covered'] is True


def test_refusals_stop_everything():
    cases = {
        'bogus x\n': 'unknown_option',
        'net 10.0.0.1\n': 'deprecated_option',
        'kdump_pre\n': 'empty_value',
        'kdump_pre # only a comment\n': 'empty_value',
        'kdump_pre /a\nkdump_pre /b\n': 'duplicate_option',
        'default reboot\nfailure_action halt\n': 'duplicate_option',
        'xfs /dev/a\nnfs host:/x\n': 'multiple_targets',
        'ssh u@h\ndracut_args --mount "h:/x /m nfs defaults"\n': 'multiple_targets',
    }
    for text, code in cases.items():
        result = kd.assess(text + 'kdump_post /bin/post\n', _dirs(post=_listing(dict(EXE, name='p'))))
        assert result['starts'] is False, text
        assert result['sequence'] == [], text
        assert [r['code'] for r in result['refusals']] == [code], text


def test_blocking_gaps_are_never_covered():
    assert kd.assess(None, _dirs())['covered'] is False
    assert kd.assess('x' * (kd.MAX_CONFIG_BYTES + 1), _dirs())['covered'] is False
    assert kd.assess('a\x00', _dirs())['covered'] is False
    missing = kd.assess('', {'pre': {'state': 'absent'}, 'post': {'state': 'absent'}})
    assert missing['covered'] is False
    assert [gap['code'] for gap in missing['gaps']] == ['directory_not_observed']
    unreadable = kd.assess('', _dirs(post={'state': 'unreadable'}))
    assert unreadable['covered'] is False
    dup = kd.assess('', _dirs(pre=_listing(dict(EXE, name='a'), dict(EXE, name='a'))))
    assert dup['covered'] is False
    unresolved = kd.assess('', _dirs(pre=_listing({'name': 'a', 'type': 'file'})))
    assert unresolved['covered'] is False
    assert unresolved['sequence'][0]['observations'] == ['unresolved']
    many = kd.assess('', _dirs(pre=_listing(*[dict(EXE, name=f'n{i}') for i in range(kd.MAX_ENTRIES + 1)])))
    assert many['covered'] is False and many['directory_entries']['pre'] == []
    bad = kd.assess('', _dirs(pre=_listing({'name': 'a/b', 'type': 'file', 'mode': 0o755})))
    assert bad['covered'] is False


def test_gaps_are_bounded():
    entries = [{'name': f'n{i}', 'type': 'file'} for i in range(kd.MAX_GAPS + 10)]
    result = kd.assess('', _dirs(pre=_listing(*entries)))
    assert len(result['gaps']) == kd.MAX_GAPS
    assert result['gaps'][-1]['code'] == 'gaps_truncated'


def test_contract_metadata():
    result = kd.assess('', _dirs())
    assert result['runs_as'] == 'root'
    assert result['not_a_verdict'] and result['unobserved']
    assert _seq(result) == [('dump', 'core_collector', 'makedumpfile', [])]
