import os
import re
from pathlib import Path


ROOT = Path(
    os.environ.get("MRPATCHY_SOURCE_ROOT", Path(__file__).resolve().parents[1])
).resolve()


def _normalized_name(requirement):
    name = requirement.split("[", 1)[0]
    return re.sub(r"[-_.]+", "-", name).lower()


def _locked_requirements(text):
    blocks = re.split(r"(?m)^(?=[A-Za-z0-9])", text)
    locked = {}
    for block in blocks:
        if not block.strip() or block.lstrip().startswith("#"):
            continue
        first_line = block.splitlines()[0]
        match = re.fullmatch(r"([^=\s]+)==([^\s\\]+) \\", first_line)
        assert match, f"unrecognized lock entry: {first_line!r}"
        hashes = re.findall(r"--hash=sha256:([0-9a-f]{64})(?: \\)?$", block, re.M)
        assert hashes, f"lock entry lacks a sha256 hash: {first_line!r}"
        locked[_normalized_name(match.group(1))] = (match.group(2), hashes)
    return locked


def test_runtime_lock_covers_direct_and_transitive_dependencies_with_hashes():
    manifest = (ROOT / "requirements.txt").read_text()
    lock_text = (ROOT / "requirements.lock").read_text()

    assert "uv pip compile requirements.txt --generate-hashes --python-version 3.15" in lock_text
    assert not re.search(r"(?m)^\s*(?:--index-url|--extra-index-url|-r\s)", lock_text)

    locked = _locked_requirements(lock_text)
    assert len(locked) > len(manifest.splitlines())
    for line in manifest.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = re.fullmatch(r"([^=\s]+)==([^\s]+)", line)
        assert match, f"runtime requirement is not exact: {line!r}"
        name = _normalized_name(match.group(1))
        assert name in locked, f"runtime requirement is absent from lock: {line!r}"
        assert locked[name][0] == match.group(2)


def test_container_install_enforces_runtime_lock_hashes():
    dockerfile = (ROOT / "Dockerfile").read_text()
    assert "COPY requirements.txt requirements.lock ./" in dockerfile
    assert re.search(
        r"RUN pip install\s+--no-cache-dir\s+--require-hashes\s+-r requirements\.lock$",
        dockerfile,
        re.M,
    )
    assert not re.search(r"RUN pip install[^\n]*-r requirements\.txt", dockerfile)
