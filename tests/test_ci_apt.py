"""CI runner setup must retain repository trust and bound network waits."""
import os
from pathlib import Path
import subprocess

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / '.github/scripts/configure-ci-apt.sh'


@pytest.mark.parametrize('existing_sources', [False, True])
def test_ci_apt_preserves_signed_sources_and_is_idempotent(tmp_path, existing_sources):
    root = tmp_path / 'apt'
    (root / 'sources.list.d').mkdir(parents=True)
    config = root / 'apt.conf.d'
    config.mkdir()
    (config / 'trusted-policy').write_text('APT::Get::AllowUnauthenticated "false";\n')
    paths = ['apt-mirrors.txt', 'sources.list', 'sources.list.d/ubuntu.sources']
    original = ('URIs: http://azure.archive.ubuntu.com/ubuntu\n'
                'Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg\n'
                'URIs: https://packages.microsoft.com/ubuntu/24.04/prod\n'
                'URIs: https://azure.archive.ubuntu.com/ubuntu\n')
    if existing_sources:
        for path in paths:
            (root / path).write_text(original)
    binary = tmp_path / 'bin'
    binary.mkdir()
    sudo = binary / 'sudo'
    sudo.write_text('#!/bin/sh\nexec "$@"\n')
    sudo.chmod(0o755)
    env = {**os.environ, 'PATH': str(binary) + os.pathsep + os.environ['PATH'],
           'MRPATCHY_CI_APT_ROOT': str(root)}
    subprocess.run(['bash', str(SCRIPT)], env=env, check=True)
    first = {p.relative_to(root).as_posix(): p.read_text() for p in root.rglob('*') if p.is_file()}
    subprocess.run(['bash', str(SCRIPT)], env=env, check=True)
    assert first == {p.relative_to(root).as_posix(): p.read_text() for p in root.rglob('*') if p.is_file()}
    assert first['apt.conf.d/trusted-policy'] == 'APT::Get::AllowUnauthenticated "false";\n'
    assert first['apt.conf.d/99-mrpatchy-ci-network'] == (
        'Acquire::Retries "2";\nAcquire::http::Timeout "30";\nAcquire::https::Timeout "30";\n')
    if existing_sources:
        expected = original.replace('http://azure.archive.ubuntu.com/ubuntu', 'https://archive.ubuntu.com/ubuntu').replace(
            'https://azure.archive.ubuntu.com/ubuntu', 'https://archive.ubuntu.com/ubuntu')
        assert all(first[path] == expected for path in paths)
    else:
        assert not any(path in first for path in paths)


def test_ci_apt_routes_regional_ec2_mirror_to_primary_archive(tmp_path):
    """Issue #1166: hosted runners also list a regional EC2 mirror that stalled setup."""
    root = tmp_path / 'apt'
    (root / 'sources.list.d').mkdir(parents=True)
    mirrors = ('http://azure.archive.ubuntu.com/ubuntu\tpriority:1\n'
               'http://us-east-2.ec2.archive.ubuntu.com/ubuntu\tpriority:2\n'
               'https://eu-west-1.ec2.archive.ubuntu.com/ubuntu\tpriority:3\n'
               'http://archive.ubuntu.com/ubuntu\tpriority:4\n'
               'http://ec2.archive.ubuntu.com.example.net/ubuntu\tpriority:5\n')
    (root / 'apt-mirrors.txt').write_text(mirrors)
    sources = ('Types: deb\nURIs: mirror+file:/etc/apt/apt-mirrors.txt\n'
               'Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg\n\n'
               'Types: deb\nURIs: http://us-east-2.ec2.archive.ubuntu.com/ubuntu\n'
               'Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg\n')
    (root / 'sources.list.d' / 'ubuntu.sources').write_text(sources)
    binary = tmp_path / 'bin'
    binary.mkdir()
    sudo = binary / 'sudo'
    sudo.write_text('#!/bin/sh\nexec "$@"\n')
    sudo.chmod(0o755)
    env = {**os.environ, 'PATH': str(binary) + os.pathsep + os.environ['PATH'],
           'MRPATCHY_CI_APT_ROOT': str(root)}
    subprocess.run(['bash', str(SCRIPT)], env=env, check=True)
    first = (root / 'apt-mirrors.txt').read_text()
    assert first == ('https://archive.ubuntu.com/ubuntu\tpriority:1\n'
                     'https://archive.ubuntu.com/ubuntu\tpriority:2\n'
                     'https://archive.ubuntu.com/ubuntu\tpriority:3\n'
                     'http://archive.ubuntu.com/ubuntu\tpriority:4\n'
                     # Only the Ubuntu-operated ec2.archive host is rewritten.
                     'http://ec2.archive.ubuntu.com.example.net/ubuntu\tpriority:5\n')
    assert 'ec2.archive.ubuntu.com/ubuntu' not in first
    rewritten = (root / 'sources.list.d' / 'ubuntu.sources').read_text()
    assert rewritten == sources.replace('http://us-east-2.ec2.archive.ubuntu.com/ubuntu',
                                        'https://archive.ubuntu.com/ubuntu')
    assert rewritten.count('Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg') == 2
    subprocess.run(['bash', str(SCRIPT)], env=env, check=True)
    assert (root / 'apt-mirrors.txt').read_text() == first
    assert (root / 'sources.list.d' / 'ubuntu.sources').read_text() == rewritten


def test_ci_apt_disables_only_the_unused_runner_microsoft_feed(tmp_path):
    root = tmp_path / 'apt'
    sources = root / 'sources.list.d'
    sources.mkdir(parents=True)
    microsoft_source = sources / 'microsoft-prod.list'
    runner_feed = (
        'deb [arch=amd64,arm64,armhf signed-by=/usr/share/keyrings/microsoft-prod.gpg] '
        'https://packages.microsoft.com/ubuntu/24.04/prod noble main\n'
    )
    other_feeds = (
        '# A comment is already inactive.\n'
        'deb https://packages.microsoft.com/ubuntu/22.04/prod jammy main\n'
        'deb https://packages.microsoft.com/ubuntu/24.04/prod-preview noble main\n'
        'deb https://packages.microsoft.com.example.org/ubuntu/24.04/prod noble main\n'
    )
    microsoft_source.write_text(runner_feed + other_feeds)
    other_source = sources / 'other.list'
    other_source.write_text(runner_feed)
    binary = tmp_path / 'bin'
    binary.mkdir()
    sudo = binary / 'sudo'
    sudo.write_text('#!/bin/sh\nexec "$@"\n')
    sudo.chmod(0o755)
    env = {**os.environ, 'PATH': str(binary) + os.pathsep + os.environ['PATH'],
           'MRPATCHY_CI_APT_ROOT': str(root)}

    for _ in range(2):
        subprocess.run(['bash', str(SCRIPT)], env=env, check=True)
        assert microsoft_source.read_text() == '# Disabled for Mr Patchy CI: ' + runner_feed + other_feeds
        assert other_source.read_text() == runner_feed


def test_browser_dependency_install_retries_bounded_attempts():
    import yaml
    workflow = yaml.safe_load((SCRIPT.parents[1] / 'workflows' / 'ci.yml').read_text())
    step = next(s for s in workflow['jobs']['browser']['steps']
                if s.get('name') == 'Install browser system dependencies')
    run = step['run']
    assert 'bash .github/scripts/configure-ci-apt.sh' in run
    assert 'for attempt in 1 2 3' in run
    assert 'timeout 180 npx playwright install-deps chromium' in run
    assert run.rstrip().endswith('exit 1'), 'all attempts failing must still fail the job'
    # A stopped attempt must not leave apt-get holding the dpkg lock for the next one.
    loop = run[run.index('for attempt'):]
    assert loop.index('pkill -KILL -x apt-get') < loop.index('done')
    assert 'dpkg --configure -a' in loop
    # Three bounded attempts plus setup must fit inside the step bound.
    assert 3 * 180 / 60 < step['timeout-minutes'] <= 15
