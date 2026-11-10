import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def caddy_image():
    return re.search(r'^    image: (caddy:\S+)$', (ROOT / 'compose.yaml').read_text(), re.M).group(1)


def test_application_base_has_an_immutable_digest_and_readable_tag():
    bases = re.findall(r'^FROM (\S+)(?: AS (\S+))?$', (ROOT / 'Dockerfile').read_text(), re.M)
    assert bases and re.fullmatch(r'python:[^@\s]+@sha256:[0-9a-f]{64}', bases[0][0])
    aliases=set()
    for index,(image,alias) in enumerate(bases):
        if index:assert image in aliases, 'Every stage must reuse the same immutable base'
        if alias:aliases.add(alias)


def test_compiler_stays_in_dependency_stage_and_final_image_uses_its_venv():
    dockerfile=(ROOT/'Dockerfile').read_text()
    builder,runtime=dockerfile.split('FROM runtime-base\n',1)
    assert 'build-essential libffi-dev' in builder
    assert '--require-hashes -r requirements.lock' in builder
    assert 'requirements-build.lock' not in runtime
    assert 'COPY --from=dependencies /opt/venv /opt/venv' in runtime
    assert 'build-essential' not in runtime and 'libffi-dev' not in runtime


def test_deployed_caddy_has_an_immutable_digest_and_readable_tag():
    assert re.fullmatch(r'caddy:[^@\s]+@sha256:[0-9a-f]{64}', caddy_image())


def test_adapter_fixture_uses_the_deployed_caddy_image():
    fixture = re.search(r'docker create --name mrpatchy-caddy-adapter (\S+)',
                        (ROOT / '.github/workflows/ci.yml').read_text()).group(1)
    assert fixture == caddy_image(), 'Adapter validation must exercise the deployed Caddy reference'


def _locked(path):
    pins={}
    for name,version,hashes in re.findall(r'^([A-Za-z0-9_.-]+)==(\S+)((?:\s*\\\n\s+--hash=sha256:[0-9a-f]{64})+)',
                                         (ROOT/path).read_text(),re.M):
        pins[name.lower()]=(version,set(re.findall(r'[0-9a-f]{64}',hashes)))
    return pins


def test_sdist_build_inputs_are_hash_locked_and_consistent_with_runtime_lock():
    build=_locked('requirements-build.lock')
    runtime=_locked('requirements.lock')
    assert set(build)=={'cffi','packaging','pycparser','setuptools'}
    assert all(hashes for _,hashes in build.values())
    for name in ('cffi','pycparser'):
        assert build[name][0]==runtime[name][0], f'{name} build pin must match the runtime lock'
        assert build[name][1]<=runtime[name][1], f'{name} build hashes must be runtime-locked artifacts'
    assert 'setuptools' not in runtime and 'packaging' not in runtime


def test_runtime_packages_build_offline_from_hash_verified_downloads():
    builder=(ROOT/'Dockerfile').read_text().split('FROM runtime-base\n',1)[0]
    steps=[line for line in builder.splitlines() if line.startswith('RUN ')]
    build_lock=next(i for i,s in enumerate(steps) if '-r requirements-build.lock' in s)
    download=next(i for i,s in enumerate(steps) if s.startswith('RUN pip download'))
    install=next(i for i,s in enumerate(steps) if '-r requirements.lock' in s and 'pip install' in s)
    strip=next(i for i,s in enumerate(steps) if 'pip uninstall' in s)
    sdist=next(i for i,s in enumerate(steps) if 'urllib.request' in s)
    assert build_lock<download<install<strip
    assert '--require-hashes --only-binary=:all:' in steps[build_lock]
    for flag in ('--require-hashes','--no-deps','--only-binary=:all:','-r requirements-wheels.lock'):
        assert flag in steps[download]
    assert '--no-build-isolation' not in steps[download]
    assert download<sdist<install
    assert 'files.pythonhosted.org/packages/source/z/zstandard/' in steps[sdist]
    assert 'hashlib.sha256' in steps[sdist] and 'requirements.lock' in steps[sdist]
    assert steps[install].startswith('RUN --network=none pip install')
    for flag in ('--no-index','--find-links /wheelhouse','--no-build-isolation','--require-hashes'):
        assert flag in steps[install]
    assert 'setuptools packaging' in steps[strip] and '! pip show setuptools packaging' in steps[strip]


def test_dependency_audit_covers_build_lock():
    ci=(ROOT/'.github/workflows/ci.yml').read_text()
    assert re.search(r'pip-audit [^\n]*-r requirements\.lock -r requirements-build\.lock',ci)


def test_online_steps_never_run_a_build_backend():
    """Only wheels and raw sdist bytes are fetched with networking; sdist hooks run offline."""
    builder=(ROOT/'Dockerfile').read_text().split('FROM runtime-base\n',1)[0]
    online=[s for s in builder.splitlines() if s.startswith('RUN ') and not s.startswith('RUN --network=none')]
    for step in online:
        if 'pip download' in step or ('pip install' in step and '-r ' in step):
            assert '--only-binary=:all:' in step, step
    split=next(s for s in online if 'requirements-wheels.lock' in s and 'write_text' in s)
    assert "re.sub(r'(?ms)^zstandard==" in split
