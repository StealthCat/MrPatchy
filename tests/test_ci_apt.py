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
    first = {str(p.relative_to(root)): p.read_text() for p in root.rglob('*') if p.is_file()}
    subprocess.run(['bash', str(SCRIPT)], env=env, check=True)
    assert first == {str(p.relative_to(root)): p.read_text() for p in root.rglob('*') if p.is_file()}
    assert first['apt.conf.d/trusted-policy'] == 'APT::Get::AllowUnauthenticated "false";\n'
    assert first['apt.conf.d/99-mrpatchy-ci-network'] == (
        'Acquire::Retries "2";\nAcquire::http::Timeout "30";\nAcquire::https::Timeout "30";\n')
    if existing_sources:
        expected = original.replace('http://azure.archive.ubuntu.com/ubuntu', 'https://archive.ubuntu.com/ubuntu').replace(
            'https://azure.archive.ubuntu.com/ubuntu', 'https://archive.ubuntu.com/ubuntu')
        assert all(first[path] == expected for path in paths)
    else:
        assert not any(path in first for path in paths)
