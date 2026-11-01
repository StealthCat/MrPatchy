import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_dependabot_covers_supply_chain_ecosystems():
    text = (ROOT / ".github" / "dependabot.yml").read_text()
    assert re.search(r"^version: 2$", text, re.M)
    found = set(re.findall(r"package-ecosystem: (\S+)", text))
    assert {"pip", "docker", "github-actions", "npm"} <= found
    assert text.count("interval:") == text.count("package-ecosystem:")
