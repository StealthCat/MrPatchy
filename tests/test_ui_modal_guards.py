import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest


pytestmark = pytest.mark.skipif(shutil.which('node') is None, reason='node not installed')
ROOT = Path(__file__).resolve().parents[1]
APP = (ROOT / 'app/static/app.js').read_text()
SCHEDULES = (ROOT / 'app/static/schedules.js').read_text()


def _function(source, name):
    match = re.search(rf"function {name}\([^)]*\)\{{", source)
    assert match, f'{name} not found'
    depth = 0
    for index in range(match.start(), len(source)):
        if source[index] == '{':
            depth += 1
        elif source[index] == '}':
            depth -= 1
            if depth == 0:
                return source[match.start():index + 1]
    raise AssertionError(f'{name} is incomplete')


def _run(sign_out=False):
    helper = re.search(r"function modalRequest\(", APP)
    script = r"""
let modalRevision=0,sessionRevision=0;
const calls=[],messages=[],releases=[],elements={};
const dialog={open:false,close(){this.open=false;calls.push('close');}};
const button=()=>({disabled:false,isConnected:true,onclick:null,click(){if(!this.disabled)return this.onclick({target:this,currentTarget:this});}});
function $(selector){if(selector==='#modal')return dialog;return elements[selector];}
function esc(value){return String(value);}
function hostName(value){return value;}
function modal(){modalRevision++;dialog.open=true;elements['#confirm-source']=button();}
function toast(message,global=false){messages.push({message,global,dialog:dialog.open});}
async function api(){const session=sessionRevision;calls.push('api');await new Promise(resolve=>releases.push(resolve));if(session!==sessionRevision)throw Error('Session changed; previous response discarded');return {};}
%s
%s
(async()=>{
 saveSource('/tmp/race.sources','Types: deb','fixture');
 const submit=elements['#confirm-source'];submit.click();submit.click();
 await Promise.resolve();
 %s
 releases.forEach(resolve=>resolve());
 await new Promise(resolve=>setImmediate(resolve));
 console.log(JSON.stringify({calls,messages,open:dialog.open,disabled:submit.disabled}));
})();
""" % (_function(APP, 'modalRequest') if helper else '', _function(APP, 'saveSource'),
         "sessionRevision++;dialog.open=false;" if sign_out else "modal('Account','');")
    result = subprocess.run(['node', '-e', script], capture_output=True, text=True, check=True)
    return json.loads(result.stdout)


def test_stale_repository_completion_preserves_new_dialog_and_is_one_shot():
    result = _run()
    assert result['calls'].count('api') == 1
    assert result['open'] is True
    assert result['messages'] == [{'message': 'Repository change queued', 'global': True, 'dialog': True}]


def test_repository_completion_after_sign_out_is_silent():
    result = _run(sign_out=True)
    assert result['calls'].count('api') == 1
    assert result['messages'] == []


def test_related_mutation_handlers_use_the_same_modal_guard():
    for marker in ['#key-form', '#access-form', '#confirm-trust']:
        start = APP.index(marker)
        assert 'modalRequest()' in APP[max(0, start - 500):start + 1600]
    for marker in ['#confirm-delete-schedule', '#save-schedule']:
        start = SCHEDULES.index(marker)
        assert 'modalRequest()' in SCHEDULES[max(0, start - 500):start + 1200]
