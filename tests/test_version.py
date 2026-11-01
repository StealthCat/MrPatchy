from pathlib import Path
import pytest
from app.main import APP_VERSION,app
from tools import check_version


def test_runtime_and_source_version(admin):
    assert check_version.check() == APP_VERSION == app.version
    assert admin.get('/healthz').json()['version']==APP_VERSION
    assert admin.get('/api/identity').json()['version']==APP_VERSION

@pytest.mark.parametrize('file,replacement', [('CHANGELOG.md','## 0.1.0 — old\n\n1. old')])
def test_inconsistent_documentation_fails(tmp_path,monkeypatch,file,replacement):
    for name in ('CHANGELOG.md','app/main.py'):
        path=tmp_path/name;path.parent.mkdir(exist_ok=True);path.write_text((check_version.ROOT/name).read_text())
    (tmp_path/file).write_text(replacement);monkeypatch.setattr(check_version,'ROOT',tmp_path)
    with pytest.raises(ValueError):check_version.check()
