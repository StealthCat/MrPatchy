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


def test_server_overview_cards_and_link_buttons_are_responsive():
    css = (STATIC / "style.css").read_text()
    grid = re.search(r"\.server-grid\{([^}]*)\}", css).group(1)
    assert "auto-fit" in grid and "minmax(min(100%" in grid
    guide = re.search(r"\.server-overview-guide \{([^}]*)\}", css).group(1)
    assert "padding-right" not in guide and "position:relative" not in guide
    mascot = re.search(r"\.server-guide-mascot \{([^}]*)\}", css).group(1)
    assert "position:absolute" not in mascot and "pointer-events:none" in mascot
    assert not re.search(r"\.server-overview-guide \{ padding-right", css)
    anchor = re.search(r"(?m)^a\.button \{([^}]*)\}", css).group(1)
    assert "display:inline-block" in anchor
