import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _blocks(text):
    parts = re.split(r"^  - package-ecosystem: ", text, flags=re.M)[1:]
    return {p.split()[0]: p for p in parts}


def _directories(block):
    found = set(re.findall(r"^\s+directory: (\S+)$", block, re.M))
    listed = re.search(r"^    directories:\n((?:      - \S+\n)+)", block, re.M)
    if listed:
        found |= set(re.findall(r"- (\S+)", listed.group(1)))
    return found


def _tracked(pattern):
    out = subprocess.run(
        ["git", "ls-files", pattern], cwd=ROOT, capture_output=True, text=True, check=True
    ).stdout.split()
    return [Path(p) for p in out]


def _dir(path):
    return "/" + path.parent.as_posix() if path.parent != Path(".") else "/"


def test_dependabot_covers_supply_chain_ecosystems():
    text = (ROOT / ".github" / "dependabot.yml").read_text()
    assert re.search(r"^version: 2$", text, re.M)
    blocks = _blocks(text)
    assert {"pip", "docker", "github-actions", "npm"} <= set(blocks)
    assert text.count("interval:") == text.count("package-ecosystem:")


def test_dependabot_docker_covers_every_tracked_dockerfile():
    blocks = _blocks((ROOT / ".github" / "dependabot.yml").read_text())
    configured = _directories(blocks["docker"])
    dockerfiles = _tracked("**/Dockerfile*") + _tracked("Dockerfile*")
    assert dockerfiles
    missing = sorted({_dir(p) for p in dockerfiles} - configured)
    assert not missing, f"Dockerfile locations not covered by Dependabot: {missing}"


def test_dependabot_manifest_locations_exist_for_other_ecosystems():
    blocks = _blocks((ROOT / ".github" / "dependabot.yml").read_text())
    for eco, manifest in (("pip", "requirements.txt"), ("npm", "package.json")):
        assert "/" in _directories(blocks[eco])
        assert (ROOT / manifest).exists()
    assert (ROOT / ".github" / "workflows").is_dir()
    assert "/" in _directories(blocks["github-actions"])
