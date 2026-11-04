import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(shutil.which('node') is None, reason='node not installed')

SRC = (Path(__file__).resolve().parents[1] / 'app/static/app.js').read_text()
FN = re.search(r"async function api\(.*?\n", SRC).group(0)

HARNESS = """
let sessionRevision=0,csrf='t',logins=0;function showLogin(){logins++;}
%s
const cases=%s;
(async()=>{const out=[];for(const c of cases){
 global.fetch=async()=>({ok:c.status<400,status:c.status,statusText:c.statusText||'',text:async()=>c.body});
 try{out.push({ok:await api('/x')});}catch(e){out.push({err:e.message});}}
 console.log(JSON.stringify({out,logins}));})();
"""


def run(cases):
    r = subprocess.run(['node', '-e', HARNESS % (FN, json.dumps(cases))], capture_output=True, text=True, check=True)
    return json.loads(r.stdout)


def test_api_handles_non_json_and_empty_bodies():
    res = run([
        {'status': 502, 'statusText': 'Bad Gateway', 'body': '<html>bad gateway</html>'},
        {'status': 204, 'body': ''},
        {'status': 200, 'body': '<html>oops</html>'},
        {'status': 400, 'body': '{"detail":"nope"}'},
        {'status': 422, 'body': '{"detail":[{"msg":"x"}]}'},
        {'status': 200, 'body': '{"a":1}'},
        {'status': 401, 'body': ''},
        {'status': 200, 'body': 'null'},
    ])
    out = res['out']
    assert out[0]['err'] == 'Request failed (HTTP 502 Bad Gateway)'
    assert out[1] == {'ok': {}}
    assert out[2]['err'] == 'Unexpected non-JSON response (HTTP 200)'
    assert out[3]['err'] == 'nope'
    assert 'msg' in out[4]['err']
    assert out[5] == {'ok': {'a': 1}}
    assert out[6]['err'].startswith('Request failed (HTTP 401')
    assert out[7] == {'ok': None}  # valid JSON null is not a parse failure
    assert res['logins'] == 1
