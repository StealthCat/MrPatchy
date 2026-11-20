from app import tuned_profiles as tp

ETC, LIB = '/etc/tuned', '/usr/lib/tuned'


def _present(text):
    return {'state': 'present', 'text': text}


ABSENT = {'state': 'absent'}


def _capture(profiles, active='custom\n', mode='manual\n', post=None, **kw):
    """profiles: {'/etc/tuned/custom': 'ini text', ...} keyed by profile directory."""
    files, listings = {}, {ETC: [], LIB: []}
    for directory, text in profiles.items():
        parent, name = directory.rsplit('/', 1)
        listings[parent].append(name)
        files[f'{directory}/tuned.conf'] = {'type': 'file', 'text': text}
    for parent in (ETC, LIB):
        for other in (ETC, LIB):
            for name in listings[other]:
                files.setdefault(f'{parent}/{name}/tuned.conf', {'type': 'absent'})
    capture = {
        'family': 'rpm', 'installed': True,
        'active_profile': _present(active) if active is not None else ABSENT,
        'profile_mode': _present(mode) if mode is not None else ABSENT,
        'post_loaded_profile': _present(post) if post is not None else ABSENT,
        'files': files, 'listings': listings,
    }
    capture.update(kw)
    return capture


def _runs(result):
    return [(i['kind'], i['path']) for i in result['invocations']]


def _gaps(result):
    return {g['kind'] for g in result['gaps']}


def test_script_unit_runs_as_root_with_profile_dir_expanded_and_relative_path_resolved():
    result = tp.evaluate(_capture({
        f'{ETC}/custom': '[main]\nsummary=x\n[script]\nscript=${i:PROFILE_DIR}/tune.sh\n',
    }))
    assert result['status'] == 'resolved' and result['complete'] is True
    assert result['runs_as'] == 'root'
    assert _runs(result) == [('script', '/etc/tuned/custom/tune.sh')]
    inv = result['invocations'][0]
    assert inv['arguments']['apply'] == ('start',) and inv['arguments']['unapply'] == ('stop',)
    assert inv['cwd'] == '/etc/tuned/custom'

    relative = tp.evaluate(_capture({f'{ETC}/custom': '[script]\nscript=../other/x.sh\n'}))
    assert _runs(relative) == [('script', '/etc/tuned/other/x.sh')]


def test_etc_profile_shadows_stock_profile_and_include_loads_first():
    result = tp.evaluate(_capture({
        f'{LIB}/balanced': '[script]\nscript=stock.sh\n',
        f'{ETC}/balanced': '[main]\ninclude=base\n[script]\nscript=custom.sh\n',
        f'{LIB}/base': '[cpu]\ngovernor=performance\n',
    }, active='balanced'))
    assert result['loaded_files'] == ['/etc/tuned/balanced/tuned.conf', '/usr/lib/tuned/base/tuned.conf']
    assert _runs(result) == [('script', '/etc/tuned/balanced/custom.sh')]


def test_same_name_include_falls_through_to_the_stock_profile_and_scripts_concatenate():
    # A custom profile that includes its own name loads the stock copy first.
    result = tp.evaluate(_capture({
        f'{LIB}/throughput-performance': '[script]\nscript=stock.sh\n',
        f'{ETC}/throughput-performance': '[main]\ninclude=throughput-performance\n[script]\nscript=extra.sh\n',
    }, active='throughput-performance'))
    assert result['loaded_files'] == ['/etc/tuned/throughput-performance/tuned.conf',
                                      '/usr/lib/tuned/throughput-performance/tuned.conf']
    assert _runs(result) == [('script', '/usr/lib/tuned/throughput-performance/stock.sh'),
                             ('script', '/etc/tuned/throughput-performance/extra.sh')]


def test_merge_without_a_later_script_repeats_earlier_scripts_like_tuned():
    result = tp.evaluate(_capture({
        f'{LIB}/base': '[script]\nscript=a.sh\n',
        f'{ETC}/custom': '[main]\ninclude=base\n[script]\nenabled=true\n',
    }))
    assert _runs(result) == [('script', '/usr/lib/tuned/base/a.sh')] * 2


def test_replace_disable_and_drop_follow_merge_rules():
    replaced = tp.evaluate(_capture({
        f'{LIB}/base': '[script]\nscript=a.sh\n',
        f'{ETC}/custom': '[main]\ninclude=base\n[script]\nreplace=true\nscript=b.sh\n',
    }))
    assert _runs(replaced) == [('script', '/etc/tuned/custom/b.sh')]
    disabled = tp.evaluate(_capture({
        f'{LIB}/base': '[script]\nscript=a.sh\n',
        f'{ETC}/custom': '[main]\ninclude=base\n[script]\nenabled=false\n',
    }))
    assert _runs(disabled) == []
    dropped = tp.evaluate(_capture({
        f'{LIB}/base': '[script]\nscript=a.sh\n',
        f'{ETC}/custom': '[main]\ninclude=base\n[script]\ndrop=script\n',
    }))
    # drop removes the earlier option before the concatenation check.
    assert _runs(dropped) == []


def test_script_pre_and_post_are_conditional_per_device_and_relative_paths_never_run():
    result = tp.evaluate(_capture({
        f'{ETC}/custom': ('[disk]\nscript_pre=${i:PROFILE_DIR}/pre.sh\nscript_post=post.sh\n'
                          '[script]\nscript=s.sh\n'),
    }))
    assert _runs(result) == [('script_pre', '/etc/tuned/custom/pre.sh'), ('script_post', 'post.sh'),
                             ('script', '/etc/tuned/custom/s.sh')]
    pre, post, _ = result['invocations']
    assert pre['runs'] is True and 'assigns at least one device' in pre['conditions'][0]
    assert pre['arguments']['apply'] == ('apply', 'DEVICE')
    assert post['runs'] is False and post['reason'] == 'relative_path_never_runs'


def test_priority_orders_units_and_regexes_are_conditions():
    result = tp.evaluate(_capture({
        f'{ETC}/custom': ('[late]\ntype=script\npriority=10\nscript=late.sh\n'
                          '[script]\nscript=early.sh\nuname_regex=el9\n'),
    }))
    assert _runs(result) == [('script', '/etc/tuned/custom/early.sh'), ('script', '/etc/tuned/custom/late.sh')]
    assert result['invocations'][0]['conditions'] == ['uname_regex matches the kernel identity']
    bad = tp.evaluate(_capture({f'{ETC}/custom': '[script]\npriority=high\nscript=x\n'}))
    assert bad['status'] == 'load_refused' and bad['detail']['reason'] == 'priority_invalid'
    assert bad['invocations'] == []


def test_apply_checks_follow_unit_manager_order_regex_then_uname_then_priority():
    # units/manager.py create(): disabled units are skipped first, then cpuinfo_regex,
    # then uname_regex, then int(priority); any raise aborts before a unit is created.
    disabled = tp.evaluate(_capture({f'{ETC}/custom': '[a]\nenabled=false\npriority=x\n[script]\nscript=s\n'}))
    assert disabled['status'] == 'resolved' and _runs(disabled) == [('script', '/etc/tuned/custom/s')]
    conditional = tp.evaluate(_capture({
        f'{ETC}/custom': '[a]\ntype=script\nscript=a.sh\ncpuinfo_regex=GenuineIntel\npriority=x\n[script]\nscript=s\n',
    }))
    assert conditional['status'] == 'incomplete' and conditional['complete'] is False
    assert _gaps(conditional) == {'apply_refusal_conditional'} and conditional['invocations'] == []
    bad_cpuinfo = tp.evaluate(_capture({f'{ETC}/custom': '[a]\ncpuinfo_regex=(\n[script]\nscript=s\n'}))
    assert bad_cpuinfo['status'] == 'load_refused' and bad_cpuinfo['detail']['reason'] == 'regex_invalid'
    bad_uname_after_cpuinfo = tp.evaluate(_capture({
        f'{ETC}/custom': '[a]\ncpuinfo_regex=Intel\nuname_regex=[\n[script]\nscript=s\n'}))
    assert _gaps(bad_uname_after_cpuinfo) == {'apply_refusal_conditional'}
    # A definite refusal anywhere wins over a host-dependent one, whatever the order.
    both = tp.evaluate(_capture({
        f'{ETC}/custom': '[a]\nuname_regex=el9\npriority=x\n[b]\npriority=y\n[script]\nscript=s\n'}))
    assert both['status'] == 'load_refused' and both['detail'] == {'reason': 'priority_invalid', 'subject': 'b'}
    # TuneD expands variables in regexes before matching, so a $-value is never judged uncompilable.
    expanded = tp.evaluate(_capture({
        f'{ETC}/custom': '[variables]\nx=)\n[script]\nscript=s\nuname_regex=(${x}\n'}))
    assert expanded['status'] == 'resolved' and _runs(expanded) == [('script', '/etc/tuned/custom/s')]


def test_post_loaded_profile_is_appended_and_must_be_one_name():
    profiles = {f'{ETC}/custom': '[script]\nscript=a.sh\n', f'{ETC}/extra': '[x]\ntype=script\nscript=b.sh\n'}
    result = tp.evaluate(_capture(profiles, post='extra\n'))
    assert result['requested_profiles'] == ['custom', 'extra']
    assert _runs(result) == [('script', '/etc/tuned/custom/a.sh'), ('script', '/etc/tuned/extra/b.sh')]
    bad = tp.evaluate(_capture(profiles, post='extra custom'))
    assert bad['status'] == 'load_refused' and bad['detail']['reason'] == 'post_loaded_profile_invalid'


def test_unknown_profile_missing_include_and_parse_error_refuse_the_whole_load():
    unknown = tp.evaluate(_capture({f'{ETC}/custom': '[script]\nscript=a\n'}, active='custom missing'))
    assert unknown['status'] == 'load_refused' and unknown['detail']['subject'] == 'missing'
    files = _capture({f'{ETC}/custom': '[main]\ninclude=nope\n[script]\nscript=a\n'})
    nope = {f'{ETC}/nope/tuned.conf': {'type': 'absent'}, f'{LIB}/nope/tuned.conf': {'type': 'absent'}}
    files['files'].update(nope)
    missing = tp.evaluate(files)
    assert missing['status'] == 'load_refused' and missing['detail']['reason'] == 'profile_not_found'
    optional = _capture({f'{ETC}/custom': '[main]\ninclude=-nope\n[script]\nscript=a\n'})
    optional['files'].update(nope)
    assert _runs(tp.evaluate(optional)) == [('script', '/etc/tuned/custom/a')]
    broken = tp.evaluate(_capture({f'{ETC}/custom': 'no section header\n'}))
    assert broken['status'] == 'load_refused' and broken['detail']['reason'] == 'profile_parse_error'


def test_mode_handling():
    profiles = {f'{ETC}/custom': '[script]\nscript=a\n'}
    implicit_manual = tp.evaluate(_capture(profiles, mode=None))
    assert implicit_manual['mode'] == 'manual' and implicit_manual['status'] == 'resolved'
    auto = tp.evaluate(_capture(profiles, mode='auto'))
    assert auto['status'] == 'incomplete' and 'recommended_profile_not_modeled' in _gaps(auto)
    no_active = tp.evaluate(_capture(profiles, active=None, mode=None))
    assert no_active['complete'] is False and 'recommended_profile_not_modeled' in _gaps(no_active)
    none = tp.evaluate(_capture(profiles, active='', mode='manual'))
    assert none['status'] == 'no_profile' and none['complete'] is True and none['invocations'] == []
    invalid = tp.evaluate(_capture(profiles, mode='sometimes'))
    assert invalid['status'] == 'load_refused' and invalid['detail']['reason'] == 'profile_mode_invalid'


def test_unsafe_names_are_dropped_after_the_known_check():
    profiles = {f'{ETC}/custom': '[script]\nscript=a\n', f'{ETC}/we!rd': '[script]\nscript=b\n'}
    result = tp.evaluate(_capture(profiles, active='custom we!rd'))
    assert _runs(result) == [('script', '/etc/tuned/custom/a')]
    only = tp.evaluate(_capture(profiles, active='we!rd'))
    assert only['status'] == 'load_refused' and only['detail']['reason'] == 'profile_name_invalid'


def test_exec_functions_variables_files_and_include_variables_are_blocking_gaps():
    exec_call = tp.evaluate(_capture({f'{ETC}/custom': '[variables]\nx=${f:exec:/tmp/evil}\n'}))
    assert exec_call['complete'] is False and 'function_exec' in _gaps(exec_call)
    assert exec_call['function_exec'][0]['unit'] == 'variables'
    in_option = tp.evaluate(_capture({f'{ETC}/custom': '[sysctl]\nvm.x=${f:exec:id}\n'}))
    assert 'function_exec' in _gaps(in_option)
    var_file = tp.evaluate(_capture({f'{ETC}/custom': '[variables]\ninclude=/etc/tuned/v.conf\n'}))
    assert 'variables_file_not_modeled' in _gaps(var_file)
    inc = tp.evaluate(_capture({f'{ETC}/custom': '[main]\ninclude=${base}\n'}))
    assert 'include_expansion_not_modeled' in _gaps(inc)
    benign = tp.evaluate(_capture({f'{ETC}/custom': '[variables]\ncores=${f:cpulist_online:0-3}\n'}))
    assert benign['status'] == 'resolved' and benign['complete'] is True


def test_unobserved_and_out_of_scope_inputs_fail_closed():
    assert tp.evaluate(None)['complete'] is False
    assert 'family_unobserved' in _gaps(tp.evaluate({'installed': True}))
    assert tp.evaluate({'family': 'windows'})['status'] == 'not_applicable'
    assert 'installation_unobserved' in _gaps(tp.evaluate({'family': 'rpm'}))
    assert tp.evaluate({'family': 'rpm', 'installed': False})['status'] == 'not_installed'
    missing_file = _capture({f'{ETC}/custom': '[script]\nscript=a\n'})
    del missing_file['files'][f'{ETC}/custom/tuned.conf']
    result = tp.evaluate(missing_file)
    assert result['complete'] is False and 'path_unobserved' in _gaps(result)
    no_listing = _capture({f'{ETC}/custom': '[script]\nscript=a\n'})
    del no_listing['listings'][LIB]
    assert 'listing_unobserved' in _gaps(tp.evaluate(no_listing))
    unread = _capture({f'{ETC}/custom': '[script]\nscript=a\n'}, active=None)
    unread['active_profile'] = None
    assert 'state_file_unobserved' in _gaps(tp.evaluate(unread))
    big = _capture({f'{ETC}/custom': 'x' * (tp.MAX_TEXT + 1)})
    assert tp.evaluate(big)['complete'] is False


def test_include_cycle_is_bounded_by_processed_file_skipping():
    result = tp.evaluate(_capture({
        f'{ETC}/a': '[main]\ninclude=b\n[script]\nscript=a.sh\n',
        f'{ETC}/b': '[main]\ninclude=a\n[x]\ntype=script\nscript=b.sh\n',
    }, active='a'))
    assert result['status'] == 'resolved'
    assert result['loaded_files'] == ['/etc/tuned/a/tuned.conf', '/etc/tuned/b/tuned.conf']


def test_exec_assembled_by_variables_or_nested_functions_is_never_missed():
    # TuneD expands ${VAR} statically before functions, and nested function results
    # feed the outer call, so the literal text need not contain "${f:exec:".
    cases = {
        'variable_supplies_name': '[variables]\nX=exec\n[sysctl]\nk=${f:${X}:/tmp/evil}\n',
        'variable_supplies_dollar': '[variables]\nD=$\n[sysctl]\nk=${D}{f:exec:/tmp/evil}\n',
        'stored_function_result': '[variables]\nD=${f:strip:$}{f\n[sysctl]\nk=${D}:exec:/tmp/evil}\n',
        'nested_name': '[sysctl]\nk=${f:${f:strip:exec}:/tmp/evil}\n',
        'split_name': '[variables]\nE=e\n[sysctl]\nk=${f:${E}xec:/tmp/evil}\n',
    }
    for label, text in cases.items():
        result = tp.evaluate(_capture({f'{ETC}/custom': text}))
        assert result['complete'] is False, label
        assert _gaps(result) & {'function_exec', 'function_expansion_not_modeled'}, label
        assert result['invocations'] == [], label


def test_static_variables_and_ordinary_functions_stay_complete():
    result = tp.evaluate(_capture({
        f'{ETC}/custom': '[variables]\ncores=1-3\nmask=${f:cpulist2hex:${cores}}\n'
                         '[sysctl]\nk=${mask} \\${literal}\n[script]\nscript=s.sh\n',
    }))
    assert result['complete'] is True and _runs(result) == [('script', '/etc/tuned/custom/s.sh')]


def test_undefined_variable_reference_is_a_blocking_gap():
    # TuneD keeps one Variables store for the daemon's lifetime, so an undefined
    # name may resolve to a value left by a previously loaded profile.
    result = tp.evaluate(_capture({f'{ETC}/custom': '[sysctl]\nk=${leftover}\n[script]\nscript=s.sh\n'}))
    assert result['complete'] is False and 'variable_undefined' in _gaps(result)


def test_profile_dir_with_backslash_is_not_substituted_literally():
    # re.sub treats the profile directory as a replacement template, so a backslash
    # in an included directory name changes or breaks the expansion.
    capture = _capture({
        f'{ETC}/custom': '[main]\ninclude=we\\1ird\n',
        f'{ETC}/we\\1ird': '[script]\nscript=${i:PROFILE_DIR}/s.sh\n',
    })
    result = tp.evaluate(capture)
    assert result['complete'] is False and 'profile_dir_escape_not_modeled' in _gaps(result)
