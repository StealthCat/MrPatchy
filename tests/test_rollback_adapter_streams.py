import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from target import bridge


class TrustedHook:
    """Delegate execution to a fixture while presenting the production trust metadata."""

    def __init__(self, path):
        self.path = path

    def __str__(self):
        return str(self.path)

    def stat(self):
        return SimpleNamespace(st_uid=0, st_mode=0o100755)

    def is_file(self):
        return self.path.is_file()

    def is_symlink(self):
        return self.path.is_symlink()


def warning_hook(tmp_path):
    hook = tmp_path / 'rollback'
    hook.write_text(
        '#!/bin/sh\n'
        "printf 'snapper warning\\n' >&2\n"
        "case \"$1\" in\n"
        "  probe) printf '%s\\n' '{\"ready\":true}' ;;\n"
        "  snapshot) printf '%s\\n' '{\"snapshot\":\"42\"}' ;;\n"
        "  rollback) printf '%s\\n' '{\"reboot_required\":false}' ;;\n"
        'esac\n'
    )
    hook.chmod(0o755)
    return hook


def use_hook(monkeypatch, hook):
    real_path = Path
    monkeypatch.setattr(
        bridge,
        'Path',
        lambda value: TrustedHook(hook)
        if value == '/etc/mrpatchy/rollback'
        else real_path(value),
    )


@pytest.mark.parametrize(
    ('operation', 'expected'),
    [
        ('snapshot', {'snapshot': '42'}),
        ('rollback', {'reboot_required': False}),
    ],
)
def test_recovery_hook_parses_stdout_when_adapter_warns_on_stderr(
    tmp_path, monkeypatch, operation, expected
):
    hook = warning_hook(tmp_path)
    use_hook(monkeypatch, hook)

    assert bridge.recovery_hook(operation, 'fixture') == expected


def test_adapter_warnings_do_not_lose_patch_recovery_journal(tmp_path, monkeypatch):
    hook = warning_hook(tmp_path)
    use_hook(monkeypatch, hook)
    monkeypatch.setattr(bridge, 'ROOT', tmp_path)
    monkeypatch.setattr(
        bridge,
        'handle',
        lambda request: (_ for _ in ()).throw(RuntimeError('apt failure'))
        if request['action'] == 'patch'
        else {'failed_units': '', 'collector_active': True},
    )
    monkeypatch.setattr(
        bridge,
        'verify_patch_original',
        lambda original: {'outcome': 'rolled_back', 'original_state_verified': True},
    )
    job_id = 'a' * 36
    result = bridge.protected_patch(
        {
            'job_id': job_id,
            'packages': ['demo=2'],
            'policy': {'rollback': True},
            'original': {'version': 1},
        }
    )

    journal = json.loads(bridge.transaction_path(job_id).read_text())
    assert result['outcome'] == journal['state'] == 'rolled_back'
    assert journal['snapshot'] == '42'
    assert journal['rollback'] == {'reboot_required': False}


def test_recovery_hook_rejects_oversized_stdout_without_tail_parsing(monkeypatch):
    hook = TrustedHook(Path(__file__))
    monkeypatch.setattr(bridge, 'Path', lambda value: hook)
    monkeypatch.setattr(
        bridge,
        'bounded',
        lambda *args, **kwargs: ('x' * 20_001 + json.dumps({'snapshot': '42'}), ''),
    )

    with pytest.raises(ValueError, match='response exceeds 20 KB'):
        bridge.recovery_hook('snapshot', 'fixture')
