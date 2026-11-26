"""Docker daemon.json program contract (#1521).

Cases marked "native" were started with a real dockerd 29.9.3 and its
``docker info`` runtimes, default runtime, init binary, generated runtime
wrapper or start error were compared with the contract.
"""
import json

from app import docker_daemon as dd


def _by(result, kind, name=None):
    return [p for p in result['programs'] if p['kind'] == kind and (name is None or p.get('name') == name)]


def test_empty_file_uses_stock_programs():  # native
    for text in ('', '  \n', '{}', '﻿{}'):
        r = dd.analyze(text)
        assert r['starts'] and r['complete'] and r['default_runtime'] == 'runc'
        assert _by(r, 'runtime', 'runc')[0]['stock'] is True
        assert _by(r, 'init')[0] == {'kind': 'init', 'path': 'docker-init', 'configured': False,
                                     'every_container': False, 'argv': ['docker-init']}
        assert _by(r, 'userland_proxy')[0]['enabled'] is True
        assert _by(r, 'userland_proxy')[0]['path'] == 'docker-proxy'


def test_custom_default_runtime_and_init():  # native
    r = dd.analyze(json.dumps({'runtimes': {'evil': {'path': '/opt/x/evil'}}, 'default-runtime': 'evil',
                               'init': True, 'init-path': '/opt/x/init'}))
    assert r['complete'] and r['starts']
    [evil] = _by(r, 'runtime', 'evil')
    assert evil['default'] and evil['argv'] == ['/opt/x/evil'] and not evil['via_shell']
    assert not _by(r, 'runtime', 'runc')
    init = _by(r, 'init')[0]
    assert init['path'] == '/opt/x/init' and init['configured'] and init['every_container']


def test_duplicate_keys_keep_the_last_value():  # native
    text = ('{"runtimes":{"evil":{"path":"/a","runtimeArgs":["--a"]},"evil":{"path":"/usr/bin/runc",'
            '"runtimeArgs":["--b"]}},"default-runtime":"evil","init-path":"/x/a","init-path":"/x/b"}')
    r = dd.analyze(text)
    [evil] = _by(r, 'runtime', 'evil')
    assert evil['argv'] == ['/usr/bin/runc', '--b'] and evil['default']
    assert _by(r, 'init')[0]['path'] == '/x/b'


def test_runtime_args_run_through_unquoted_shell_wrapper():  # native
    r = dd.analyze(json.dumps({'runtimes': {'x': {'path': '/usr/bin/runc', 'runtimeArgs': ['--systemd-cgroup']}}}))
    [x] = _by(r, 'runtime', 'x')
    assert x['via_shell'] and x['shell_wrapper'] == '#!/bin/sh\n/usr/bin/runc --systemd-cgroup $@\n'
    assert x['argv'] == ['/usr/bin/runc', '--systemd-cgroup'] and not x['default'] and r['complete']


def test_empty_runtime_args_use_the_binary_directly():  # native
    r = dd.analyze(json.dumps({'runtimes': {'x': {'path': '/usr/bin/runc', 'runtimeArgs': []}}}))
    [x] = _by(r, 'runtime', 'x')
    assert not x['via_shell'] and x['argv'] == ['/usr/bin/runc'] and 'shell_wrapper' not in x


def test_shell_metacharacters_block_completion():  # native wrapper: /usr/bin/runc --log=/tmp/a;id $HOME $@
    r = dd.analyze(json.dumps({'runtimes': {'x': {'path': '/usr/bin/runc', 'runtimeArgs': ['--log=/tmp/a;id', '$HOME']}}}))
    [x] = _by(r, 'runtime', 'x')
    assert x['argv'] is None and x['shell_wrapper'] == '#!/bin/sh\n/usr/bin/runc --log=/tmp/a;id $HOME $@\n'
    assert not r['complete'] and r['gaps'][0]['code'] == 'shell_metacharacters'
    spaced = dd.analyze(json.dumps({'runtimes': {'x': {'path': '/opt/my runtime', 'runtimeArgs': ['-a']}}}))
    assert not spaced['complete']


def test_path_with_space_and_no_args_is_not_shell_parsed():
    r = dd.analyze(json.dumps({'runtimes': {'x': {'path': '/opt/my runtime'}}}))
    assert r['complete'] and _by(r, 'runtime', 'x')[0]['argv'] == ['/opt/my runtime']


def test_start_refusals_report_no_programs():  # native
    cases = {
        '{"runtimes":{"runc":{"path":"/bin/true"}}}': "runtime name 'runc' is reserved",
        '{"default-runtime":"nope"}': "specified default runtime 'nope' does not exist",
        '{"runtimes":{"x":{"path":"/usr/bin/runc","runtimeType":"io.containerd.runc.v2"}}}':
            'cannot configure both path and runtimeType',
        '{"runtimes":{"x":{}}}': 'either a runtimeType or a path must be configured',
        '{"runtimes":{"x":{"runtimeType":"io.containerd.runc.v2","runtimeArgs":["--a"]}}}':
            'args cannot be used with a runtimeType runtime',
        '{"init-path":"/bin/true" /* x */}': 'invalid JSON',
        '{"init-path":"/bin/true",}': 'invalid JSON',
    }
    for text, reason in cases.items():
        r = dd.analyze(text)
        assert not r['starts'] and r['programs'] == [], text
        assert any(reason in x for x in r['refusals']), (text, r['refusals'])


def test_containerd_shims():  # native
    r = dd.analyze(json.dumps({'runtimes': {'x': {'runtimeType': '/opt/shim/containerd-shim-x-v2'}}}))
    [x] = _by(r, 'runtime_shim', 'x')
    assert x['runtime_type'] == '/opt/shim/containerd-shim-x-v2' and x['shim_binary'] is None and r['complete']
    kata = dd.analyze('{"default-runtime":"io.containerd.kata.v2"}')
    [k] = _by(kata, 'runtime_shim')
    assert kata['starts'] and k['default'] and k['shim_binary'] == 'containerd-shim-kata-v2'


def test_userland_proxy_disabled_and_custom_path():  # native
    r = dd.analyze('{"userland-proxy":false,"userland-proxy-path":"/opt/p"}')
    proxy = _by(r, 'userland_proxy')[0]
    assert proxy == {'kind': 'userland_proxy', 'path': '/opt/p', 'configured': True, 'enabled': False,
                     'argv': ['/opt/p']}


def test_authorization_plugins_and_nulls():  # nulls: native
    r = dd.analyze('{"authorization-plugins":["authz-a","authz-b"],"init-path":null,"runtimes":null}')
    assert r['authorization_plugins'] == ['authz-a', 'authz-b'] and r['complete']
    assert _by(r, 'init')[0]['path'] == 'docker-init'


def test_unmodelled_constructs_are_blocking_gaps():
    cases = {
        '[]': 'not_an_object',
        '{"runtimes":[]}': 'wrong_type',
        '{"init":"yes"}': 'wrong_type',
        '{"runtimes":{"x":{"path":"/a","Path":"/b"}}}': 'unmodelled_runtime_key',
        '{"runtimes":{"io.containerd.runc.v2":{"path":"/bin/true"}}}': 'reserved_shim_name',
        '{"runtimes":{"x":{"path":"/a","runtimeArgs":[1]}}}': 'wrong_type',
        '{"authorization-plugins":[1]}': 'wrong_type',
    }
    for text, code in cases.items():
        r = dd.analyze(text)
        assert not r['complete'] and r['gaps'][0]['code'] == code, (text, r['gaps'])
    assert dd.analyze(None)['gaps'][0]['code'] == 'input_malformed'
    assert dd.analyze('x' * (dd.MAX_TEXT + 1))['gaps'][0]['code'] == 'text_too_large'
    nan = dd.analyze('{"init": NaN}')
    assert not nan['starts'] and nan['programs'] == []


def test_limits_and_gap_truncation():
    many = {f'r{i}': {'path': '/a'} for i in range(dd.MAX_RUNTIMES + 1)}
    assert dd.analyze(json.dumps({'runtimes': many}))['gaps'][0]['code'] == 'too_many_runtimes'
    args = dd.analyze(json.dumps({'runtimes': {'x': {'path': '/a', 'runtimeArgs': ['-a'] * (dd.MAX_ARGS + 1)}}}))
    assert args['gaps'][0]['code'] == 'too_many_args'
    bad = {f'r{i}': {'path': '/a', 'X': 1} for i in range(dd.MAX_GAPS + 5)}
    r = dd.analyze(json.dumps({'runtimes': bad}))
    assert len(r['gaps']) == dd.MAX_GAPS + 1 and r['gaps'][-1]['code'] == 'gaps_truncated'


def test_contract_is_pure_and_not_a_verdict():
    import inspect
    source = inspect.getsource(dd)
    for forbidden in ('open(', 'subprocess', 'os.', 'socket', 'shutil', 'Path('):
        assert forbidden not in source
    r = dd.analyze('{}')
    assert r['not_a_verdict'] and r['unobserved'] and r['run_as'] == 'root'
    assert r['contract_version'] == 1 and r['reference'] == {'dockerd': '29.9.3'}
