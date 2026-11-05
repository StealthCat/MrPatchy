from pathlib import Path

APP_JS=(Path(__file__).resolve().parents[1]/'app'/'static'/'app.js').read_text()


def test_priority_selects_are_named_per_package():
    assert 'aria-label="Patch priority for ${esc(p.name)}"' in APP_JS
    assert 'aria-label="Patch priority">' not in APP_JS


def test_repository_source_editors_have_accessible_names():
    assert '<textarea data-path="${esc(path)}" aria-label="Contents of ${esc(path)}"' in APP_JS


def test_installer_download_is_not_a_button_inside_a_link():
    assert '<button>↓ Download Bash installer</button>' not in APP_JS
    assert APP_JS.count('<a class="button" href="/api/hosts/${id}/installer" download>↓ Download Bash installer</a>')==3
