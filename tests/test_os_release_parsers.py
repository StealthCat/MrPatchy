from app.advisories import ecosystem
from target import release, rpm_support

SAMPLE = "# comment\n  #ID=fedora\nID='ubuntu'\nVERSION_ID=\"24.04\"\n  NAME = \"Ubuntu\"\n"


def test_parsers_agree_on_quotes_and_comments():
    a = release.os_info(SAMPLE)
    b = rpm_support.os_info(SAMPLE)
    assert a == b
    assert a['ID'] == 'ubuntu' and a['VERSION_ID'] == '24.04' and a['NAME'] == 'Ubuntu'
    assert '#ID' not in a and '  #ID' not in a


def test_advisory_ecosystem_accepts_single_quoted_values():
    assert ecosystem(SAMPLE) == 'Ubuntu:24.04:LTS'
