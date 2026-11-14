import json
import shutil
import subprocess
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / 'app/static/settings.js'


@pytest.mark.skipif(not shutil.which('node'), reason='node required')
def test_settings_index_search_finds_sections_by_familiar_terms():
    script = SRC.read_text().split('function settingsHubCards')[0]
    probe = script + '''
const q=["API key","repository checks","certificate","MySQL","retention","","nonsense-term","  openai   KEY ","agent repair","inherit default"];
console.log(JSON.stringify(q.map(x=>settingsMatches(x))));'''
    out = subprocess.run(['node', '-e', probe], capture_output=True, text=True, check=True).stdout
    got = json.loads(out)
    assert got == [['ai'], ['patching'], ['https'], ['database'], ['history'],
                   ['ai', 'patching', 'database', 'https', 'history', 'agents'], [], ['ai'],
                   ['agents'], ['agents']]


def test_hub_search_is_labelled_and_announces_results():
    src = SRC.read_text()
    assert 'id="settings-search"' in src and 'Find a setting' in src
    assert 'aria-live="polite"' in src
