import pytest
from target import rpm_support

GOOD='0123abcd-0123-abcd-0123-0123456789ab'


def test_marker_records_validated_boot_id(tmp_path):
    boot=tmp_path/'boot_id';boot.write_text(GOOD+'\n');marker=tmp_path/'marker'
    rpm_support.write_reboot_marker(marker,boot)
    assert marker.read_text()==GOOD


@pytest.mark.parametrize('bad',['','not-a-boot-id\n','0123ABCD-0123-abcd-0123-0123456789ab','x'*500])
def test_marker_rejects_malformed_boot_id(tmp_path,bad):
    boot=tmp_path/'boot_id';boot.write_text(bad);marker=tmp_path/'marker'
    with pytest.raises(ValueError,match='Boot identity'):rpm_support.write_reboot_marker(marker,boot)
    assert not marker.exists()
