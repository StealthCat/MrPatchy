import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(shutil.which('node') is None, reason='node not installed')
SERVER = (Path(__file__).resolve().parents[1] / 'app/static/server.js').read_text()


def _function(source, name):
    match = re.search(rf"(?:async )?function {name}\([^)]*\)\{{", source)
    assert match, f'{name} not found'
    depth = 0
    for index in range(match.end() - 1, len(source)):
        if source[index] == '{':
            depth += 1
        elif source[index] == '}':
            depth -= 1
            if depth == 0:
                return source[match.start():index + 1]
    raise AssertionError('incomplete')


def test_agent_upgrade_requires_confirmation_and_is_single_flight():
    script = r"""
let modalRevision=0;const posts=[],titles=[],toasts=[],releases=[],els={};
const dialog={open:false,close(){this.open=false;}};
const mk=()=>({disabled:false,isConnected:true,onclick:null});
function $(s){return s==='#modal'?dialog:els[s];}
function modal(t){modalRevision++;titles.push(t);dialog.open=true;els['#confirm-agent-update']=mk();}
function toast(m){toasts.push(m);}
function esc(v){return String(v);}function badge(v){return v;}function date(v){return v;}
function currentView(){return true;}
async function api(path,method,body){if(method==='POST'){posts.push(path);await new Promise(r=>releases.push(r));return {};}
 return {status:{state:'ok',issues:[],checked:0,report:{}},policy:{},enrolled_outdated:false};}
%s
(async()=>{
 const root={isConnected:true,innerHTML:'',querySelector(s){if(!els[s])els[s]=mk();return els[s];}};
 await serverAgent(1,{root,hostId:'h'});
 const before=posts.length;
 els['#agent-update'].onclick();
 const afterClick={posts:posts.length,titles:[...titles]};
 const confirm=els['#confirm-agent-update'];
 confirm.onclick({currentTarget:confirm});confirm.onclick({currentTarget:confirm});
 await Promise.resolve();await Promise.resolve();
 const during={posts:posts.length,check:els['#agent-check'].disabled,update:els['#agent-update'].disabled};
 releases.forEach(r=>r());await new Promise(r=>setImmediate(r));
 console.log(JSON.stringify({before,afterClick,during,open:dialog.open,after:els['#agent-update'].disabled,toasts}));
})();
""" % (_function(SERVER, 'serverAgent') + '\n' + _function(SERVER, 'agentPolicyCard'))
    out = json.loads(subprocess.run(['node', '-e', script], capture_output=True, text=True, check=True).stdout)
    assert out['afterClick'] == {'posts': 0, 'titles': ['Review agent upgrade']}
    assert out['during'] == {'posts': 1, 'check': True, 'update': True}
    assert out['open'] is False and out['after'] is False
    assert out['toasts'] == ['Agent update queued']
