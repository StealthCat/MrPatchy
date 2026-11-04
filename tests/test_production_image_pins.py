import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def caddy_image():
    return re.search(r'^    image: (caddy:\S+)$', (ROOT / 'compose.yaml').read_text(), re.M).group(1)


def test_application_base_has_an_immutable_digest_and_readable_tag():
    bases = re.findall(r'^FROM (\S+)$', (ROOT / 'Dockerfile').read_text(), re.M)
    assert len(bases) == 1
    assert re.fullmatch(r'python:[^@\s]+@sha256:[0-9a-f]{64}', bases[0])


def test_deployed_caddy_has_an_immutable_digest_and_readable_tag():
    assert re.fullmatch(r'caddy:[^@\s]+@sha256:[0-9a-f]{64}', caddy_image())


def test_adapter_fixture_uses_the_deployed_caddy_image():
    fixture = re.search(r'docker create --name mrpatchy-caddy-adapter (\S+)',
                        (ROOT / '.github/workflows/ci.yml').read_text()).group(1)
    assert fixture == caddy_image(), 'Adapter validation must exercise the deployed Caddy reference'
