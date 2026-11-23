"""pam_env contract. Expected values were recorded from the real pam_env.so
(libpam-modules 1.5.3-5ubuntu5.7) driven through pam_start_confdir and
pam_open_session, and the optional differential test re-checks them when
that library is available."""

import ctypes
import ctypes.util
import os
import tempfile

import pytest

from app.pam_env_contract import evaluate, parse_arguments

ROOT = {'name': 'root', 'home': '/root', 'shell': '/bin/bash'}
ITEMS = {'PAM_USER': 'root', 'PAM_TTY': 'tty1', 'PAM_RHOST': None, 'PAM_RUSER': None, 'PAM_USER_PROMPT': None}


def run(conf, env=None, **kw):
    kw.setdefault('items', ITEMS)
    kw.setdefault('user', ROOT)
    kw.setdefault('initial_env_complete', True)
    return evaluate(conf_text=conf, env_text=env, **kw)


def pairs(result):
    return [(v['name'], v['value']) for v in result['variables']]


# (conf, env, initial env, expected module result, expected ordered variables) from the real module.
CASES = [
    ('FOO DEFAULT=x\nBAR DEFAULT=${FOO}y OVERRIDE=@{HOME}\n', 'export Z="q"\nW=1 # c\n', {}, 'success',
     [('FOO', 'x'), ('BAR', '/root'), ('Z', 'q'), ('W', '1 ')]),
    # A missing configuration file makes pam_env return PAM_IGNORE before /etc/environment.
    (None, 'Z=1\n', {}, 'ignore', []),
    # Removing an unset variable on the last line aborts and skips /etc/environment.
    ('FOO\n', 'Z=1\n', {}, 'abort', []),
    ('FOO\nBAR DEFAULT=1\n', 'Z=1\n', {}, 'success', [('BAR', '1'), ('Z', '1')]),
    ('FOO\n', 'Z=1\n', {'FOO': 'init'}, 'success', [('Z', '1')]),
    # A malformed final line also aborts, after earlier lines took effect.
    ('A DEFAULT=1\nB JUNK=2\n', 'Z=1\n', {}, 'abort', [('A', '1')]),
    ('A DEFAULT=""\nB DEFAULT=\nC OVERRIDE= DEFAULT="v w"\n', '', {}, 'success', [('A', ''), ('C', 'v w')]),
    ('LD_PRELOAD DEFAULT=/tmp/a.so \\\n  OVERRIDE=${NOPE}\n', '', {}, 'success', [('LD_PRELOAD', '/tmp/a.so')]),
    ('A DEFAULT=\\$x\\y@{PAM_TTY}$\n', '', {}, 'success', [('A', '$xytty1$')]),
    ('A=B DEFAULT=v\n', '', {}, 'success', [('A', 'B=v')]),
    ('A DEFAULT=${X\n', 'Z=1\n', {}, 'abort', []),
    ('', 'A-B=1\n=2\nexport  C=3\nD=\'x"y\'\nE="z\nZ\n', {'Z': '1'}, 'success',
     [('D', 'x"y'), ('E', 'z')]),
    ('', 'A=1 \\\n  B\nC=2 \\\n', {}, 'success', [('A', '1   B')]),
]


@pytest.mark.parametrize(('conf', 'env', 'initial', 'result', 'expected'), CASES)
def test_matches_real_pam_env(conf, env, initial, result, expected):
    out = run(conf, env, initial_env=initial)
    assert out['complete'] is True
    assert out['module_result'] == result
    assert pairs(out) == expected


def test_arguments_follow_pam_env_parse():
    opts = parse_arguments(['readenv=abc', 'user_readenv=-1', 'conffile=', 'envfile=/etc/x', 'bogus'])
    assert opts['readenv'] is False and opts['user_readenv'] is True
    assert opts['conffile'] == '/etc/security/pam_env.conf' and opts['envfile'] == '/etc/x'
    assert opts['ignored_arguments'] == ['conffile=', 'bogus']
    out = run('A DEFAULT=1\n', 'Z=2\n', args=['readenv=0'])
    assert pairs(out) == [('A', '1')]


def test_user_environment_file_uses_conf_syntax_and_flags_loader_injection():
    out = run('A DEFAULT=1\n', 'Z=2\n', args=['user_readenv=1'],
              user_env_text='LD_PRELOAD DEFAULT=@{HOME}/evil.so\nFOO OVERRIDE=${Z}x\n')
    assert pairs(out) == [('A', '1'), ('Z', '2'), ('LD_PRELOAD', '/root/evil.so'), ('FOO', '2x')]
    assert [v['name'] for v in out['risky']] == ['LD_PRELOAD']
    assert out['variables'][2]['source'] == '/root/.pam_environment'


def test_risky_variables_are_explained():
    out = run('', 'BASH_ENV=/tmp/x\nPATH=/usr/bin::/opt/x\nLD_AUDIT=/a.so\nLANG=C\n')
    risks = {v['name']: v['risk']['category'] for v in out['risky']}
    assert risks == {'BASH_ENV': 'shell_startup', 'PATH': 'command_path', 'LD_AUDIT': 'dynamic_loader'}
    path = next(v for v in out['risky'] if v['name'] == 'PATH')
    assert path['risk']['entries'] == ['']
    assert next(v for v in out['variables'] if v['name'] == 'BASH_ENV')['line'] == 1


@pytest.mark.parametrize('unobserved', ['conf', 'env'])
def test_unobserved_files_are_gaps(unobserved):
    out = run('A DEFAULT=1\n', 'Z=1\n', unobserved=[unobserved])
    assert out['complete'] is False
    assert out['gaps'][0]['reason'] == f'{unobserved}_unobserved'


def test_unknown_expansions_and_start_environment_fail_closed():
    out = run('LD_PRELOAD DEFAULT=${SOMETHING}/x.so\n', '', initial_env_complete=False)
    assert out['complete'] is False
    entry = next(v for v in out['variables'] if v['name'] == 'LD_PRELOAD')
    assert entry['value'] is None and entry['unresolved'] is True and entry['risk']
    # An unknown override leaves the chosen branch unknown.
    out = run('A DEFAULT=1 OVERRIDE=@{PAM_RHOST}\n', '', items={'PAM_USER': 'root'})
    assert out['complete'] is False
    # Unknown PAM_USER passwd entry for @{HOME}.
    out = run('A DEFAULT=@{HOME}\n', '', user=None)
    assert out['complete'] is False
    # Removing a variable whose existence is unknown leaves the module result unknown.
    out = run('A\n', 'Z=1\n', initial_env_complete=False)
    assert out['complete'] is False and out['module_result'] == 'unknown'


def test_oversized_and_nul_input_are_gaps():
    out = run('A DEFAULT=' + 'x' * 9000 + '\n', 'Z=1\n')
    assert out['complete'] is False and out['gaps'][0]['reason'] == 'oversized_line'
    out = run('', 'A=1\0\n')
    assert out['complete'] is False and out['gaps'][0]['reason'] == 'nul_byte'


def test_user_env_requires_known_user():
    out = run('', '', args=['user_readenv=1'], items={'PAM_USER': 'bob'})
    assert out['complete'] is False and out['gaps'][0]['reason'] == 'user_env_unresolved'


def _real_pam():
    name = ctypes.util.find_library('pam')
    if not name or not os.path.exists('/lib/x86_64-linux-gnu/security/pam_env.so'):
        return None
    lib = ctypes.CDLL(name)
    return lib if hasattr(lib, 'pam_start_confdir') else None


@pytest.mark.skipif(_real_pam() is None, reason='real libpam with pam_start_confdir not available')
@pytest.mark.parametrize(('conf', 'env', 'initial', 'result', 'expected'), CASES)
def test_differential_against_installed_pam_env(conf, env, initial, result, expected):
    lib = _real_pam()
    conv_t = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p)

    class Conv(ctypes.Structure):
        _fields_ = [('conv', conv_t), ('appdata_ptr', ctypes.c_void_p)]

    conv_fn = conv_t(lambda *a: 19)
    lib.pam_start_confdir.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.POINTER(Conv), ctypes.c_char_p,
                                      ctypes.POINTER(ctypes.c_void_p)]
    lib.pam_getenvlist.restype = ctypes.POINTER(ctypes.c_char_p)
    lib.pam_getenvlist.argtypes = [ctypes.c_void_p]
    lib.pam_open_session.argtypes = [ctypes.c_void_p, ctypes.c_int]
    lib.pam_putenv.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    lib.pam_set_item.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p]
    lib.pam_end.argtypes = [ctypes.c_void_p, ctypes.c_int]
    with tempfile.TemporaryDirectory() as d:
        cpath, epath = os.path.join(d, 'c'), os.path.join(d, 'e')
        if conf is not None:
            with open(cpath, 'w') as f:
                f.write(conf)
        with open(epath, 'w') as f:
            f.write(env)
        os.mkdir(os.path.join(d, 'pam.d'))
        with open(os.path.join(d, 'pam.d', 'svc'), 'w') as f:
            f.write(f'session required pam_env.so conffile={cpath} envfile={epath}\n')
        h = ctypes.c_void_p()
        assert lib.pam_start_confdir(b'svc', b'root', ctypes.byref(Conv(conv_fn, None)),
                                     os.path.join(d, 'pam.d').encode(), ctypes.byref(h)) == 0
        lib.pam_set_item(h, 3, ctypes.c_char_p(b'tty1'))
        for k, v in initial.items():
            lib.pam_putenv(h, f'{k}={v}'.encode())
        rc = lib.pam_open_session(h, 0)
        lst = lib.pam_getenvlist(h)
        real = []
        i = 0
        while lst and lst[i]:
            k, _, v = lst[i].decode().partition('=')
            real.append((k, v))
            i += 1
        lib.pam_end(h, 0)
    assert real == expected
    assert (rc == 0) == (result == 'success')
    if result == 'abort':
        assert rc == 26
