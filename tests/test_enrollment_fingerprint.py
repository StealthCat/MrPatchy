"""Run the installer's actual fingerprint block against disposable host keys."""
import os
from pathlib import Path
import subprocess

import pytest
from app.ssh import HOST_FINGERPRINT_SCRIPT


def key(directory, name, kind='ed25519'):
    path = directory / name
    subprocess.run(['ssh-keygen','-q','-t',kind,'-N','','-f',str(path)],check=True)
    return path


def run_block(tmp_path, paths, algorithms='ssh-ed25519,rsa-sha2-512', failure=False):
    config = tmp_path / 'sshd-config.txt'
    config.write_text('hostkeyalgorithms '+algorithms+'\n'+''.join('hostkey '+str(p)+'\n' for p in paths))
    binary = tmp_path / 'bin'; binary.mkdir(exist_ok=True)
    sshd = binary / 'sshd'
    sshd.write_text('#!/bin/sh\n'+('exit 1\n' if failure else 'cat "$TEST_SSHD_CONFIG"\n'))
    sshd.chmod(0o755)
    env = {**os.environ,'PATH':str(binary)+os.pathsep+os.environ['PATH'],'TEST_SSHD_CONFIG':str(config)}
    return subprocess.run(['bash','-euo','pipefail','-c',HOST_FINGERPRINT_SCRIPT+"\nprintf 'Ready to finish installation.\\n'\n"],capture_output=True,text=True,env=env)


def fingerprint(path):
    return subprocess.check_output(['ssh-keygen','-lf',str(path)+'.pub','-E','sha256'],text=True).split()[1]


def test_invalid_legacy_dsa_does_not_abort_fingerprint_display(tmp_path):
    dsa = tmp_path / 'ssh_host_dsa_key'
    dsa.write_text('invalid obsolete key'); Path(str(dsa)+'.pub').write_text('not a public key')
    rsa = key(tmp_path,'ssh_host_rsa_key','rsa')
    ed = key(tmp_path,'ssh_host_ed25519_key')
    result = run_block(tmp_path,[dsa,rsa,ed])
    assert result.returncode == 0, result.stderr
    assert fingerprint(ed) in result.stdout and fingerprint(rsa) not in result.stdout
    assert result.stdout.count('SHA256:') == 1
    assert 'Ready to finish installation.' in result.stdout
    assert 'not a public key' not in result.stderr


def test_custom_configured_private_key_works_with_stale_or_missing_public_file(tmp_path):
    custom = key(tmp_path,'custom host identity')
    expected = fingerprint(custom)
    unrelated = key(tmp_path,'unconfigured')
    Path(str(custom)+'.pub').write_text(Path(str(unrelated)+'.pub').read_text())
    result = run_block(tmp_path,[custom])
    assert result.returncode == 0 and expected in result.stdout
    assert fingerprint(unrelated) not in result.stdout
    Path(str(custom)+'.pub').unlink()
    result = run_block(tmp_path,[custom])
    assert result.returncode == 0 and expected in result.stdout


@pytest.mark.parametrize('reason',['missing','rsa_only','disabled','config_error'])
def test_no_verified_ed25519_key_never_prints_success(tmp_path,reason):
    ed = key(tmp_path,'ed')
    paths = [tmp_path/'missing'] if reason=='missing' else [key(tmp_path,'rsa','rsa')] if reason=='rsa_only' else [ed]
    result = run_block(tmp_path, paths, algorithms='rsa-sha2-512' if reason=='disabled' else 'ssh-ed25519', failure=reason=='config_error')
    assert result.returncode != 0
    assert 'SHA256:' not in result.stdout and 'Ready to finish installation.' not in result.stdout
    if reason!='config_error': assert 'Enrollment files are prepared, but no usable enabled ED25519' in result.stderr
