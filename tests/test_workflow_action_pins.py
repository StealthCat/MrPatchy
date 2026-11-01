import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_workflow_actions_are_pinned_to_commit_shas():
    files = sorted((ROOT / ".github" / "workflows").glob("*.y*ml"))
    assert files
    for path in files:
        for number, line in enumerate(path.read_text().splitlines(), 1):
            match = re.match(r"\s*-?\s*uses:\s*(\S+)(.*)$", line)
            if not match or match.group(1).startswith("./"):
                continue
            ref = match.group(1)
            assert re.search(r"@[0-9a-f]{40}$", ref), f"{path.name}:{number} {ref} is not SHA pinned"
            assert re.match(r"\s*#\s*v?\d", match.group(2)), f"{path.name}:{number} lacks version comment"
