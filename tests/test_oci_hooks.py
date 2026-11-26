"""Pure OCI hooks.d contract (#1471)."""
import json

from app import oci_hooks as oh

D = oh.DEFAULT_DIR
O = oh.OVERRIDE_DIR
PROG = '/usr/libexec/oci/hooks.d/trace'


def hook(path=PROG, stages=('prestart',), when=None, **extra):
    body = {'version': '1.0.0', 'hook': {'path': path, **extra}, 'when': when or {'always': True},
            'stages': list(stages)}
    return json.dumps(body)


def f(name, text, kind='file'):
    return {'name': name, 'kind': kind, 'text': text}


def run(dirs, listings, paths=None, rootful=True, ext=('precreate', 'poststop')):
    return oh.evaluate(hooks_dirs=dirs, extension_stages=ext, rootful=rootful, directories=listings,
                       hook_paths={PROG: 'exists', '/bin/other': 'exists', **(paths or {})})


def test_always_hook_runs_as_root_at_runtime_stage():
    r = run([D], {D: [f('10-trace.json', hook(args=[PROG, '-v'], env=['A=1'], timeout=5)), f('README', 'x')]})
    assert r['status'] == 'loads' and r['complete'] and r['origin'] == 'not_assessed'
    [h] = r['hooks']
    assert (h['path'], h['args'], h['env'], h['timeout']) == (PROG, [PROG, '-v'], ['A=1'], 5)
    assert h['matches'] == 'always' and h['runs_as'] == 'root'
    assert h['stages'] == [{'stage': 'prestart', 'executor': 'runtime', 'runtime_stage': 'createRuntime'}]
    assert [x['name'] for x in r['files']] == ['10-trace.json']


def test_extension_stage_runs_in_engine_and_rootless_runs_as_engine_user():
    r = run([D], {D: [f('a.json', hook(stages=['precreate', 'poststop', 'poststart']))]}, rootful=False)
    [h] = r['hooks']
    assert [(s['stage'], s['executor']) for s in h['stages']] == [
        ('precreate', 'engine'), ('poststop', 'engine'), ('poststart', 'runtime')]
    assert h['runs_as'] == 'engine user' and r['complete']


def test_later_directory_masks_same_name_and_failed_file_masks_nothing():
    r = run([D, O], {D: [f('a.json', hook()), f('b.json', hook())],
                     O: [f('a.json', hook(path='/bin/other')), f('b.json', hook(path='/gone'))]},
            paths={'/gone': 'missing'})
    got = {h['name']: h for h in r['hooks']}
    assert got['a.json']['path'] == '/bin/other' and got['a.json']['masks'] == [D + '/a.json']
    assert got['b.json']['source'] == D + '/b.json' and got['b.json']['masks'] == []
    outcomes = {x['path']: x['outcome'] for x in r['files']}
    assert outcomes[D + '/a.json'] == 'masked' and outcomes[O + '/b.json'] == 'error'
    assert r['status'] == 'loads' and r['complete']


def test_missing_hook_path_first_is_ignored_but_later_parse_error_still_loads_rest():
    # The first failure in byte order decides: a missing hook.path is ignorable even with later failures.
    r = run([D], {D: [f('a.json', hook(path='/gone')), f('b.json', '{not json'), f('c.json', hook())]},
            paths={'/gone': 'missing'})
    assert r['status'] == 'loads' and [h['name'] for h in r['hooks']] == ['c.json']


def test_parse_error_first_aborts_the_whole_hook_set_across_directories():
    r = run([D, O], {D: [f('z.json', hook())], O: [f('a.json', '{not json'), f('b.json', hook(path='/gone'))]},
            paths={'/gone': 'missing'})
    assert r['status'] == 'aborts' and r['hooks'] == [] and O + '/a.json' in r['detail']


def test_validation_failures_abort():
    cases = [
        hook(stages=['bogus']),
        json.dumps({'version': '1.0.0', 'hook': {'path': PROG}, 'when': {'always': True}}),
        json.dumps({'version': '2.0.0', 'hook': {'path': PROG}, 'stages': ['prestart']}),
        hook(timeout=1.5),
        json.dumps({'version': '1.0.0', 'hook': {'path': PROG}, 'when': {'always': 'yes'},
                    'stages': ['prestart']}),
        json.dumps({'version': '1.0.0', 'hook': {}, 'stages': ['prestart']}),
        '[]',
        '{"version": "1.0.0", "hook": {"path": "%s", "timeout": NaN}, "stages": []}' % PROG,
    ]
    for text in cases:
        assert run([D], {D: [f('a.json', text)]})['status'] == 'aborts', text
    assert run([D], {D: [f('a.json', hook(path='/denied'))]}, paths={'/denied': 'permission denied'})[
        'status'] == 'aborts'


def test_directory_and_unreadable_entries_abort_but_dangling_and_missing_dirs_are_skipped():
    assert run([D], {D: [f('a.json', None, kind='directory')]})['status'] == 'aborts'
    assert run([D], {D: [f('a.json', None, kind='unreadable')]})['status'] == 'aborts'
    r = run([D, O], {D: 'missing', O: [f('a.json', None, kind='dangling'), f('b.json', hook())]})
    assert r['status'] == 'loads' and r['complete'] and [h['name'] for h in r['hooks']] == ['b.json']
    assert {x['outcome'] for x in r['files']} == {'directory_missing', 'skipped', 'loaded'}


def test_current_when_semantics():
    def matches(when):
        return run([D], {D: [f('a.json', hook(when=when))]})['hooks'][0]['matches']
    assert matches({'always': False, 'commands': ['^/bin/sh$']}) == 'never'
    assert matches({'hasBindMounts': False}) == 'never'
    assert matches({'annotations': {}}) == 'never'
    assert matches({'commands': ['^/bin/sh$']}) == 'conditional'
    assert matches({'always': True, 'annotations': {'^io\\.x$': 'true'}}) == 'conditional'
    assert matches({'hasBindMounts': True}) == 'conditional'
    body = json.dumps({'version': '1.0.0', 'hook': {'path': PROG}, 'stages': ['poststop']})
    assert run([D], {D: [f('a.json', body)]})['hooks'][0]['matches'] == 'never'


def test_legacy_format_is_an_or_and_prepends_the_hook_to_arguments():
    legacy = {'hook': PROG, 'arguments': ['x'], 'stage': ['prestart'], 'cmd': ['.*'], 'annotation': ['a', 'b']}
    [h] = run([D], {D: [f('a.json', json.dumps(legacy))]})['hooks']
    assert h['format'] == '0.1.0' and h['args'] == [PROG, 'x'] and h['matches'] == 'conditional'
    assert h['conditions']['combine'] == 'any' and h['conditions']['annotations'] == {'.*': 'a|b'}
    bare = run([D], {D: [f('a.json', json.dumps({'version': '0.1.0', 'hook': PROG, 'stages': ['poststart'],
                                                 'hasbindmounts': False}))]})
    assert bare['hooks'][0]['matches'] == 'never'
    both = json.dumps({'hook': PROG, 'stage': ['prestart'], 'stages': ['prestart']})
    assert run([D], {D: [f('a.json', both)]})['status'] == 'aborts'


def test_injection_order_is_by_lower_cased_name():
    r = run([D], {D: [f('B.json', hook()), f('a.json', hook()), f('C.json', hook())]})
    assert [h['name'] for h in r['hooks']] == ['a.json', 'B.json', 'C.json'] and r['complete']
    tie = run([D], {D: [f('A.json', hook()), f('a.json', hook())]})
    assert any(g['code'] == 'order_unverified' and not g['blocking'] for g in tie['gaps'])


def test_json_go_differences_are_blocking_gaps():
    cased = '{"Version": "1.0.0", "hook": {"path": "%s"}, "when": {"always": true}, "stages": ["prestart"]}' % PROG
    dup = ('{"version": "1.0.0", "hook": {"path": "/bin/other"}, "hook": {"path": "%s"}, '
           '"when": {"always": true}, "stages": ["prestart"]}' % PROG)
    surrogate = '{"version": "1.0.0", "hook": {"path": "%s", "args": ["\\ud800"]}, "stages": ["prestart"]}' % PROG
    for text, code in ((cased, 'json_key_unverified'), (dup, 'json_duplicate_key'),
                       (surrogate, 'json_string_unverified')):
        r = run([D], {D: [f('a.json', text)]})
        assert not r['complete'] and any(g['code'] == code for g in r['gaps']), code
        assert r['files'][0]['outcome'] == 'unverified'


def test_regex_that_re2_may_reject_is_a_blocking_gap():
    r = run([D], {D: [f('a.json', hook(when={'commands': ['(?=x)sh']}))]})
    assert not r['complete'] and r['gaps'][0]['code'] == 'regex_unverified' and r['hooks'] == []


def test_fail_closed_inputs():
    unobserved = run([D, O], {D: None, O: [f('a.json', None)]})
    assert {g['code'] for g in unobserved['gaps']} == {'directory_not_observed', 'file_not_observed'}
    assert not unobserved['complete']
    rel = run([D], {D: [f('a.json', hook(path='bin/x'))]})
    assert rel['gaps'][0]['code'] == 'relative_path' and not rel['complete']
    unknown = run([D], {D: [f('a.json', hook(path='/opt/x'))]})
    assert unknown['gaps'][0]['code'] == 'hook_path_not_observed'
    noroot = run([D], {D: [f('a.json', hook())]}, rootful=None)
    assert noroot['hooks'][0]['runs_as'] is None and not noroot['complete']
    for raw, code in ((b'{"a":"\xff"}', 'invalid_utf8'), ('{"a":"\0"}', 'binary'), ('x' * (oh.MAX_TEXT + 1), 'over_limit')):
        r = run([D], {D: [f('a.json', raw)]})
        assert r['gaps'][0]['code'] == code and not r['complete']
    fifo = run([D], {D: [f('a.json', None, kind='other')]})
    assert fifo['gaps'][0]['code'] == 'entry_unverified'
    assert run([], {})['status'] == 'unresolved'


def test_non_record_listing_entries_are_blocking_gaps_and_rest_still_resolve():
    for bad in ('a.json', None, 7, ['a.json'], {'name': 5, 'kind': 'file', 'text': '{}'}):
        r = run([D], {D: [bad, f('b.json', hook())]})
        assert not r['complete'], bad
        assert any(g['code'] == 'invalid_input' and g['name'] == D and g['blocking'] for g in r['gaps'])
        assert [h['name'] for h in r['hooks']] == ['b.json']
        assert [x['name'] for x in r['files']] == ['b.json']


def test_non_boolean_rootful_is_a_blocking_gap_and_never_claims_root():
    for bad in (1, 'yes', 0, '', []):
        empty = run([D], {D: []}, rootful=bad)
        assert empty['status'] == 'no_hooks' and not empty['complete'], bad
        assert any(g['code'] == 'invalid_input' and g['name'] == 'rootful' for g in empty['gaps'])
        r = run([D], {D: [f('a.json', hook())]}, rootful=bad)
        assert not r['complete'] and [h['runs_as'] for h in r['hooks']] == [None]
