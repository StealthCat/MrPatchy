import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
STATIC = ROOT / 'app/static'
SOURCES = {path.name: path.read_text() for path in STATIC.glob('*.js')}


def test_no_element_or_handler_uses_confirmation_free_deploy_action():
    assert 'data-action="deploy"' not in ''.join(SOURCES.values())
    assert "['deploy','refresh']" not in SOURCES['app.js']
    assert "actions/${action}" not in SOURCES['app.js']


def test_unused_cfg_state_is_removed():
    for name, source in SOURCES.items():
        assert not re.search(r'\bcfg\b', source), name


def test_single_escape_helper_is_shared():
    definitions = [n for n, s in SOURCES.items() if re.search(r'(?:const|let|function)\s+(?:esc|safe)\b', s)]
    assert definitions == ['ui.js']
    assert 'esc=PatchyUI.esc' in SOURCES['app.js']
    assert 'safe(' not in SOURCES['ui.js']


def test_overview_and_server_pagers_share_one_implementation():
    app = SOURCES['app.js']
    assert app.count('function pagedRows(') == 1 and app.count('function bindPager(') == 1
    assert "pagedRows(state,rows,12,'#fleet-review')" in app
    assert "pagedRows(state,rows,24,'#server-list')" in app
    assert 'Math.ceil(rows.length/12)' not in app and 'Math.ceil(rows.length/24)' not in app


@pytest.mark.skipif(shutil.which('node') is None, reason='node not installed')
def test_shared_pager_clamps_offset_and_toggles_buttons():
    app = SOURCES['app.js']
    start = app.index('function pagedRows(')
    end = app.index('async function servers(')
    script = """
const els={};const $=s=>els[s]||(els[s]={textContent:'',disabled:false});
%s
const state={offset:60};const rows=Array.from({length:30},(_, i)=>i);
const v=pagedRows(state,rows,12,'#p');
console.log(JSON.stringify([state.offset,v.length,$('#p-page').textContent,$('#p-prev').disabled,$('#p-next').disabled]));
const e=pagedRows(state,[],12,'#p');
console.log(JSON.stringify([state.offset,e.length,$('#p-page').textContent]));
""" % app[start:end]
    out = subprocess.run(['node', '-e', script], capture_output=True, text=True, check=True).stdout.split('\n')
    assert out[0] == '[24,6,"Page 3 of 3",false,true]'
    assert out[1] == '[0,0,"No results"]'
