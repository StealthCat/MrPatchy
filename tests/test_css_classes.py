import re
from pathlib import Path

STATIC = Path(__file__).resolve().parents[1] / "app" / "static"


def test_inline_check_labels_are_styled():
    css = (STATIC / "style.css").read_text()
    js = "".join(p.read_text() for p in STATIC.glob("*.js"))
    used = set(re.findall(r'<label class="((?:inline-)?check)"', js))
    assert used
    for name in used:
        assert re.search(r"label\.%s\b" % re.escape(name), css), name
