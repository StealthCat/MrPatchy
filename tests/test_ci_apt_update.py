"""The CI refresh retries upstream errors without proceeding on stale indexes."""
import os
from pathlib import Path
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]
HELPER = 'tests/fixtures/ci-apt-update.sh'


@pytest.mark.parametrize(('failures', 'exit_code', 'attempts', 'delays'), [
    (0, 0, 1, []),
    (1, 0, 2, ['5']),
    (2, 0, 3, ['5', '10']),
    (3, 100, 3, ['5', '10']),
])
def test_refresh_apt_indexes_before_install(tmp_path, failures, exit_code, attempts, delays):
    binary = tmp_path / 'bin'
    binary.mkdir()
    commands = tmp_path / 'apt-calls'
    sleeps = tmp_path / 'sleep-calls'
    apt = binary / 'apt-get'
    apt.write_text(
        '#!/bin/sh\n'
        'printf "%s\\n" "$*" >> "$APT_CALLS"\n'
        'if [ "$1" = "update" ] && [ "$(wc -l < "$APT_CALLS")" -le "$APT_FAILURES" ]; then\n'
        '  echo "File has unexpected size. Mirror sync in progress?" >&2\n'
        '  exit 100\n'
        'fi\n',
        newline='\n',
    )
    apt.chmod(0o700)
    sleep = binary / 'sleep'
    sleep.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$SLEEP_CALLS"\n', newline='\n')
    sleep.chmod(0o700)
    sudo = binary / 'sudo'
    sudo.write_text('#!/bin/sh\nexec "$@"\n', newline='\n')
    sudo.chmod(0o700)
    env = {
        **os.environ,
        'APT_TEST_BIN': str(binary),
        'APT_CALLS': str(commands),
        'APT_FAILURES': str(failures),
        'SLEEP_CALLS': str(sleeps),
    }

    # Run the refresh as an install prerequisite, with no network or package changes.
    workflow = (ROOT / '.github/workflows/ci.yml').read_text()
    recovery = next(line.strip() for line in workflow.splitlines() if line.endswith(' restic mariadb-client'))
    # Prepend after bash startup so Git Bash does not put its own sleep first.
    command = 'export PATH="$(cd -- "$APT_TEST_BIN" && pwd):$PATH"; ' + recovery
    result = subprocess.run(
        ['bash', '-c', command], cwd=ROOT, env=env, capture_output=True,
    )

    expected_calls = ['update --error-on=any'] * attempts
    if exit_code == 0:
        expected_calls.append('install -y --no-install-recommends restic mariadb-client')
    assert result.returncode == exit_code
    assert commands.read_text().splitlines() == expected_calls
    assert (sleeps.read_text().splitlines() if sleeps.exists() else []) == delays


def test_ssh_fixture_uses_same_refresh_prerequisite():
    dockerfile = (ROOT / 'tests/fixtures/Dockerfile.ssh').read_text().replace('\\\n', ' ')
    helper_name = Path(HELPER).name
    assert f'COPY {helper_name} /tmp/{helper_name}' in dockerfile
    assert f'RUN sh /tmp/{helper_name} &&' in dockerfile
