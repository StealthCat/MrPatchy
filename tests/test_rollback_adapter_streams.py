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


@pytest.mark.parametrize(
    ('operation', 'expected'),
    [
        ('snapshot', {'snapshot': '42'}),
        ('rollback', {'reboot_required': True}),
    ],
)
def test_recovery_hook_parses_stdout_when_adapter_warns_on_stderr(
    tmp_path, monkeypatch, operation, expected
):
    hook = tmp_path / 'rollback'
    hook.write_text(
        '#!/bin/sh\n'
        "printf 'snapper warning\\n' >&2\n"
        "if [ \"$1\" = snapshot ]; then\n"
        "  printf '%s\\n' '{\"snapshot\":\"42\"}'\n"
        'else\n'
        "  printf '%s\\n' '{\"reboot_required\":true}'\n"
        'fi\n'
    )
    hook.chmod(0o755)
    real_path = Path
    monkeypatch.setattr(
        bridge,
        'Path',
        lambda value: TrustedHook(hook)
        if value == '/etc/mrpatchy/rollback'
        else real_path(value),
    )

    assert bridge.recovery_hook(operation, 'fixture') == expected


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
