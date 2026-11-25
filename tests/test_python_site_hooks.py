import base64
import hashlib
import json
import os
import shutil
import subprocess

import pytest

from app import python_site_hooks as psh

V = '3.12'
LOCAL = '/usr/local/lib/python3.12/dist-packages'
DIST = '/usr/lib/python3/dist-packages'
VERDIST = '/usr/lib/python3.12/dist-packages'
STDLIB = '/usr/lib/python3.12'
USER = '/home/alice/.local/lib/python3.12/site-packages'


def pth(name, text, **extra):
    data = text.encode() if isinstance(text, str) else text
    return {'name': name, 'kind': 'regular', 'content_b64': base64.b64encode(data).decode(), **extra}


def present(*entries, complete=True):
    return {'state': 'present', 'complete': complete, 'entries': list(entries)}


ABSENT = {'state': 'absent'}


def base_dirs(**overrides):
    dirs = {'/usr/lib/python312.zip': ABSENT, STDLIB: present(),
            STDLIB + '/lib-dynload': present(), LOCAL: present(), DIST: present(), VERDIST: ABSENT,
            USER: ABSENT}
    dirs.update(overrides)
    return dirs


def run(dirs=None, version=V, accounts=None, family='debian'):
    return psh.resolve({'family': family, 'python_version': version,
                        'directories': base_dirs() if dirs is None else dirs,
                        'accounts': [{'user': 'alice', 'home': '/home/alice'}] if accounts is None else accounts})


def site_dir(result, path):
    return next(d for d in result['system']['site_dirs'] if d['path'] == path)


def test_clean_debian_layout_is_complete_with_no_hooks():
    result = run()
    assert result['complete'] is True and result['gaps'] == []
    assert [d['path'] for d in result['system']['site_dirs']] == [LOCAL, DIST, VERDIST]
    assert [d['processed'] for d in result['system']['site_dirs']] == [True, True, False]
    assert result['accounts'][0]['user_site']['processed'] is False
    assert result['accounts'][0]['sitecustomize']['outcome'] == 'none'
    assert result['accounts'][0]['executed_code'] == []
    assert any('PYTHONPATH' in note for note in result['unobserved'])


def test_import_lines_run_in_sorted_file_order_and_other_lines_extend_sys_path():
    dirs = base_dirs(**{DIST: present(
        pth('zz.pth', 'import evil; evil.go()\n'),
        pth('a.pth', '# comment\n\n../extra\nimport\tos\n  import sys\nimport\nimporter\n'),
        pth('UPPER.PTH', 'import upper\n'),
        pth('B.pth', 'import b\n'),
    ), '/usr/lib/python3/extra': present(), DIST + '/  import sys': ABSENT, DIST + '/import': ABSENT,
        DIST + '/importer': ABSENT})
    result = run(dirs)
    files = site_dir(result, DIST)['pth_files']
    assert [f['name'] for f in files] == ['B.pth', 'a.pth', 'zz.pth']
    lines = files[1]['lines']
    assert [(x['number'], x['kind']) for x in lines] == [(3, 'path'), (4, 'code'), (5, 'path'), (6, 'path'),
                                                         (7, 'path')]
    assert lines[0]['path'] == '/usr/lib/python3/extra' and lines[0]['exists'] is True
    assert lines[1]['text'] == 'import\tos' and lines[1]['after_code'] is False
    assert lines[2]['text'] == '  import sys' and lines[2]['after_code'] is True
    executed = result['system']['executed_code']
    assert [(e['path'].rsplit('/', 1)[1], e['text']) for e in executed] == [
        ('B.pth', 'import b'), ('a.pth', 'import\tos'), ('zz.pth', 'import evil; evil.go()')]
    assert result['complete'] is True


@pytest.mark.parametrize('version', ['3.11', '3.12'])
def test_hidden_pth_is_patch_dependent_before_3_13(version):
    # Debian bookworm's python3.11 3.11.2 predates gh-113659 and still reads
    # dot-named .pth files; 3.11.8+/3.12.2+ skip them. The patch level is not
    # observed, so a hidden .pth must never be reported as covered or skipped.
    hidden = pth('.evil.pth', 'import inert_marker_module\n')
    dirs = base_dirs(**{DIST: present(hidden, pth('a.pth', 'import ok\n'))})
    dirs = {k.replace('3.12', version).replace('312', version.replace('.', '')): v for k, v in dirs.items()}
    result = run(dirs, version=version)
    files = site_dir(result, DIST)['pth_files']
    assert [(f['name'], f['status']) for f in files] == [('.evil.pth', 'undetermined'), ('a.pth', 'read')]
    assert files[0]['lines'] == []
    assert result['complete'] is False
    assert [g['code'] for g in result['gaps']] == ['pth_hidden_name_patch_dependent']
    assert result['gaps'][0]['path'] == DIST + '/.evil.pth'


def test_hidden_pth_is_skipped_on_3_13():
    dirs = base_dirs(**{DIST: present(pth('.evil.pth', 'import inert_marker_module\n'),
                                      pth('a.pth', 'import ok\n'))})
    dirs13 = {k.replace('3.12', '3.13').replace('312', '313'): v for k, v in dirs.items()}
    result = run(dirs13, version='3.13')
    assert [f['name'] for f in site_dir(result, DIST)['pth_files']] == ['a.pth']
    assert [e['text'] for e in result['system']['executed_code']] == ['import ok']
    assert result['complete'] is True


def test_user_site_runs_before_system_and_only_when_present():
    dirs = base_dirs(**{USER: present(pth('u.pth', 'import userhook\n')),
                        LOCAL: present(pth('l.pth', 'import localhook\n'))})
    account = run(dirs)['accounts'][0]
    assert account['user_site']['processed'] is True
    assert [e['text'] for e in account['executed_code']] == ['import userhook', 'import localhook']


def test_skipped_entries_and_special_files():
    dirs = base_dirs(**{DIST: present({'name': 'd.pth', 'kind': 'directory'},
                                      {'name': 'x.pth', 'kind': 'dangling', 'link_target': '/gone'},
                                      {'name': 'f.pth', 'kind': 'other'})})
    result = run(dirs)
    statuses = {f['name']: f['status'] for f in site_dir(result, DIST)['pth_files']}
    assert statuses == {'d.pth': 'skipped_directory', 'x.pth': 'skipped_dangling', 'f.pth': 'undetermined'}
    assert {g['code'] for g in result['gaps']} == {'pth_special_file'}


def test_version_specific_line_splitting():
    content = b"# note\x0cimport ff\nimport ok\rimport cr\n"
    dirs = base_dirs(**{DIST: present(pth('a.pth', content))})
    old = run(dirs)['system']['executed_code']
    assert [e['text'] for e in old] == ['import ok', 'import cr']
    dirs13 = {k.replace('3.12', '3.13').replace('312', '313'): v for k, v in dirs.items()}
    new = run(dirs13, version='3.13')['system']['executed_code']
    assert [e['text'] for e in new] == ['import ff', 'import ok', 'import cr']


def test_bom_and_non_ascii_depend_on_version_and_locale():
    bom = b'\xef\xbb\xbfimport bom\n'
    dirs = base_dirs(**{DIST: present(pth('a.pth', bom))})
    old = run(dirs)
    assert site_dir(old, DIST)['pth_files'][0]['status'] == 'undetermined'
    assert old['complete'] is False and old['gaps'][0]['code'] == 'pth_non_ascii_locale_dependent'
    dirs13 = {k.replace('3.12', '3.13').replace('312', '313'): v for k, v in dirs.items()}
    new = run(dirs13, version='3.13')
    assert [e['text'] for e in new['system']['executed_code']] == ['import bom'] and new['complete'] is True
    latin = base_dirs(**{DIST: present(pth('a.pth', b'import caf\xe9\n'))})
    latin13 = {k.replace('3.12', '3.13').replace('312', '313'): v for k, v in latin.items()}
    assert run(latin13, version='3.13')['gaps'][0]['code'] == 'pth_not_utf8_locale_fallback'


def test_unknown_inputs_are_gaps_not_coverage():
    dirs = base_dirs()
    del dirs[DIST]
    dirs[LOCAL] = present(pth('a.pth', 'import x\n'), complete=False)
    dirs[VERDIST] = present({'name': 'b.pth', 'kind': 'regular'})
    result = run(dirs)
    codes = {g['code'] for g in result['gaps']}
    assert {'site_dir_not_observed', 'site_dir_listing_incomplete', 'pth_content_not_observed',
            'customize_module_unresolved'} <= codes
    assert result['complete'] is False


def test_unsupported_family_version_and_malformed_input():
    assert run(family='rpm')['gaps'][0]['code'] == 'family_not_supported'
    assert run(version='3.13t')['gaps'][0]['code'] == 'python_version_not_supported'
    assert run(version='3.10')['system'] is None
    bad = base_dirs(**{DIST: present({'name': 'a/b.pth', 'kind': 'regular'})})
    assert run(bad)['gaps'][0]['code'] == 'invalid_observation'
    wrong_hash = pth('a.pth', 'import x\n', sha256='0' * 64)
    assert run(base_dirs(**{DIST: present(wrong_hash)}))['gaps'][0]['code'] == 'invalid_observation'
    result = run(accounts=[{'user': 'alice', 'home': 'relative'}])
    assert result['gaps'][0]['code'] == 'invalid_account' and result['accounts'] == []


def test_truncated_and_oversized_content_is_undetermined():
    dirs = base_dirs(**{DIST: present(pth('a.pth', 'import x\n', truncated=True))})
    result = run(dirs)
    assert site_dir(result, DIST)['pth_files'][0]['status'] == 'undetermined'
    assert result['gaps'][0]['code'] == 'pth_content_truncated'


def test_sitecustomize_resolution_order_and_forms():
    sha = 'c' * 64
    dirs = base_dirs(**{STDLIB: present({'name': 'sitecustomize.py', 'kind': 'regular', 'sha256': sha,
                                         'link_target': '/etc/python3.12/sitecustomize.py'}),
                        USER: present({'name': 'sitecustomize.py', 'kind': 'regular'},
                                      {'name': 'usercustomize.pyc', 'kind': 'regular'}),
                        DIST: present({'name': 'usercustomize.py', 'kind': 'regular'})})
    account = run(dirs)['accounts'][0]
    assert account['sitecustomize']['path'] == STDLIB + '/sitecustomize.py'
    assert account['sitecustomize']['sha256'] == sha and account['sitecustomize']['form'] == 'source'
    assert account['usercustomize']['path'] == USER + '/usercustomize.pyc'
    assert account['usercustomize']['form'] == 'bytecode'


def test_package_beats_source_and_namespace_only_is_uncertain():
    dirs = base_dirs(**{DIST: present({'name': 'sitecustomize', 'kind': 'directory', 'has_init': True},
                                      {'name': 'sitecustomize.py', 'kind': 'regular'})})
    assert run(dirs)['accounts'][0]['sitecustomize']['form'] == 'package'
    dirs = base_dirs(**{LOCAL: present({'name': 'sitecustomize', 'kind': 'directory', 'has_init': False}),
                        DIST: present({'name': 'sitecustomize.py', 'kind': 'regular'})})
    assert run(dirs)['accounts'][0]['sitecustomize']['path'] == DIST + '/sitecustomize.py'
    dirs = base_dirs(**{LOCAL: present({'name': 'sitecustomize', 'kind': 'directory', 'has_init': False})})
    result = run(dirs)
    assert result['accounts'][0]['sitecustomize']['reason'] == 'namespace_package_only'
    assert result['complete'] is False


def test_extension_zip_and_unknown_pth_path_are_uncertain():
    dirs = base_dirs(**{LOCAL: present({'name': 'sitecustomize.cpython-312-x86_64-linux-gnu.so', 'kind': 'regular'})})
    assert run(dirs)['accounts'][0]['sitecustomize']['reason'] == 'extension_module_candidate'
    dirs = base_dirs(**{'/usr/lib/python312.zip': {'state': 'present', 'kind': 'other'}})
    assert run(dirs)['accounts'][0]['sitecustomize']['reason'] == 'zip_path_entry_not_inspected'
    dirs = base_dirs(**{DIST: present(pth('a.pth', '/opt/unknown\n'))})
    result = run(dirs)
    assert 'pth_path_not_observed' in {g['code'] for g in result['gaps']}
    assert result['accounts'][0]['sitecustomize']['reason'] == 'directory_not_observed'


def test_pth_code_marks_customize_resolution_as_shadowable():
    dirs = base_dirs(**{DIST: present(pth('a.pth', 'import x\n'), {'name': 'sitecustomize.py', 'kind': 'regular'})})
    resolution = run(dirs)['accounts'][0]['sitecustomize']
    assert resolution['outcome'] == 'imported' and resolution['origin'] == 'not_assessed'
    assert resolution['reasons'] == ['pth_code_may_change_sys_path']


def test_user_site_disabled_resolution_skips_user_site():
    dirs = base_dirs(**{USER: present({'name': 'sitecustomize.py', 'kind': 'regular'}),
                        DIST: present({'name': 'sitecustomize.py', 'kind': 'regular'})})
    result = run(dirs)
    assert result['accounts'][0]['sitecustomize']['path'] == USER + '/sitecustomize.py'
    assert result['system']['user_site_disabled']['sitecustomize']['path'] == DIST + '/sitecustomize.py'


# Reference: run the real CPython ``site.addsitedir`` from each local Debian
# interpreter against a fixture tree and compare which import lines ran, in order.
REFERENCE_FILES = {
    'b.pth': b"import sys; sys._log.append('b:1')\n# import sys; sys._log.append('never')\n",
    'a.pth': b"\nimport\tsys; sys._log.append('a:2')\n  import sys; sys._log.append('never')\nsub\n"
             b"import sys; sys._log.append('a:5')\rimport sys; sys._log.append('a:6')\r\n",
    '.h.pth': b"import sys; sys._log.append('hidden')\n",
    'c.PTH': b"import sys; sys._log.append('upper')\n",
    'd.pth': b"# x\x0cimport sys; sys._log.append('d:ff')\nimport sys; sys._log.append('d:2')\n",
    'e.pth': b"import sys; sys._log.append('e:1')\nimport nonexistent_module_for_test\n"
             b"import sys; sys._log.append('e:3')\n",
}


def _reference(python, root):
    code = ("import json, site, sys; sys._log = []; site.addsitedir(sys.argv[1]); "
            "print(json.dumps({'log': sys._log, 'path': sys.path}))")
    env = {'PATH': os.environ.get('PATH', '/usr/bin:/bin'), 'LC_ALL': 'C.UTF-8'}
    out = subprocess.run([python, '-S', '-I', '-c', code, root], capture_output=True, check=True, env=env,
                         timeout=60)
    return json.loads(out.stdout)


@pytest.mark.parametrize('version', psh.VERSIONS)
def test_matches_real_cpython_site(tmp_path, version):
    python = shutil.which(f'python{version}')
    if not python:
        pytest.skip(f'python{version} not installed')
    root = tmp_path / 'site'
    root.mkdir()
    (root / 'sub').mkdir()
    (root / 'dir.pth').mkdir()
    for name, data in REFERENCE_FILES.items():
        (root / name).write_bytes(data)
    reference = _reference(python, str(root))
    entries = [{'name': 'sub', 'kind': 'directory', 'has_init': False},
               {'name': 'dir.pth', 'kind': 'directory', 'has_init': False}]
    for name, data in REFERENCE_FILES.items():
        entries.append({'name': name, 'kind': 'regular', 'content_b64': base64.b64encode(data).decode(),
                        'sha256': hashlib.sha256(data).hexdigest()})
    nodot = version.replace('.', '')
    sitedir = '/usr/lib/python3/dist-packages'
    dirs = {f'/usr/lib/python{nodot}.zip': ABSENT, f'/usr/lib/python{version}': present(),
            f'/usr/lib/python{version}/lib-dynload': present(), f'/usr/local/lib/python{version}/dist-packages': ABSENT,
            sitedir: present(*entries), sitedir + '/sub': present(),
            sitedir + "/  import sys; sys._log.append('never')": ABSENT,
            f'/usr/lib/python{version}/dist-packages': ABSENT}
    result = psh.resolve({'family': 'debian', 'python_version': version, 'directories': dirs, 'accounts': []})
    if version in psh.HIDDEN_PTH_PATCH_DEPENDENT:
        # Whether '.h.pth' runs depends on the local interpreter's patch level.
        assert [g['code'] for g in result['gaps']] == ['pth_hidden_name_patch_dependent'], result['gaps']
        reference['log'] = [entry for entry in reference['log'] if entry != 'hidden']
    else:
        assert result['complete'] is True, result['gaps']
        assert 'hidden' not in reference['log']
    executed = result['system']['executed_code']
    # Lines after a failing import line are reported as after_code; the reference
    # shows they did not run. Everything the reference ran is reported, in order.
    reported = [e['text'].split("append('")[1].split("'")[0] if 'append' in e['text'] else e['text']
                for e in executed]
    expected = [entry for entry in reported if entry not in ('e:3', 'import nonexistent_module_for_test')]
    assert reference['log'] == expected
    assert 'never' not in reported and 'hidden' not in reported and 'upper' not in reported
    e3 = next(e for e in executed if 'e:3' in e['text'])
    assert e3['after_code'] is True
    added = [x['path'] for f in site_dir(result, sitedir)['pth_files'] for x in f['lines']
             if x['kind'] == 'path' and x['exists']]
    assert added == [sitedir + '/sub']
    root_index = reference['path'].index(str(root))
    assert reference['path'][root_index + 1:] == [str(root / 'sub')]
    assert ('d:ff' in reported) is (version == '3.13')
