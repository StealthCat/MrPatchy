import pytest
from pathlib import Path
from target import bridge


def test_boot_id_returns_validated_identity(monkeypatch):
    good='0123abcd-0123-abcd-0123-0123456789ab\n'
    monkeypatch.setattr(Path,'read_text',lambda self,*a,**k:good)
    assert bridge.boot_id()==good.strip()


@pytest.mark.parametrize('bad',['','not-a-boot-id\n','0123ABCD-0123-abcd-0123-0123456789ab','x'*500])
def test_boot_id_rejects_malformed_identity(monkeypatch,bad):
    monkeypatch.setattr(Path,'read_text',lambda self,*a,**k:bad)
    with pytest.raises(ValueError,match='Boot identity'):bridge.boot_id()
