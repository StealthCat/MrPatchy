"""Check that licensing travels with the application and its distributed metadata."""
from html import unescape
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]

def test_local_license_page_matches_distributed_license():
    page = (ROOT / 'app/static/license.html').read_text()
    terms = re.search(r'<pre>(.*?)</pre>', page, re.S)
    assert terms is not None
    assert unescape(terms.group(1)) == (ROOT / 'LICENSE').read_text()
    shell = (ROOT / 'app/static/index.html').read_text()
    assert shell.count('href="/static/license.html"') == 2

def test_container_distributes_project_terms():
    dockerfile = (ROOT / 'Dockerfile').read_text()
    assert 'COPY LICENSE COMMERCIAL.md ./' in dockerfile
    assert 'org.opencontainers.image.licenses="LicenseRef-MrPatchy-Personal-Commercial-1.0"' in dockerfile
    ignored = (ROOT / '.dockerignore').read_text().splitlines()
    assert 'LICENSE' not in ignored
    assert 'COMMERCIAL.md' not in ignored

def test_npm_metadata_refers_to_project_license_only():
    package = json.loads((ROOT / 'package.json').read_text())
    lock = json.loads((ROOT / 'package-lock.json').read_text())
    assert package['license'] == 'SEE LICENSE IN LICENSE'
    assert lock['packages']['']['license'] == package['license']
    assert lock['packages']['node_modules/playwright']['license'] == 'Apache-2.0'
    assert lock['packages']['node_modules/playwright-core']['license'] == 'Apache-2.0'

def test_source_distribution_explains_personal_and_commercial_use():
    for filename in ['README.md', 'COMMERCIAL.md', 'CONTRIBUTING.md']:
        text = (ROOT / filename).read_text()
        assert 'LICENSE' in text
        assert 'commercial' in text.lower()
