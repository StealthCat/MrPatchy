"""Real Compose/Caddy trust boundary: forwarded addresses and spoof rejection."""
import json
import ssl
import subprocess
import urllib.request

COMPOSE=['docker','compose','--env-file','.env.ci']
SPOOF='198.51.100.233'
LOGIN={'password':'ci-disposable-password-only'}

def last_login_ip():
    code="from app.db import Session,Audit; from sqlalchemy import select; s=Session(); print(s.scalar(select(Audit.detail).where(Audit.action=='login').order_by(Audit.id.desc()).limit(1)).split()[-1])"
    return subprocess.check_output([*COMPOSE,'exec','-T','app','python','-c',code],text=True).strip()

context=ssl.create_default_context(cafile='/tmp/mrpatchy-ci-root.crt')
request=urllib.request.Request('https://localhost/api/login',data=json.dumps(LOGIN).encode(),
    headers={'Content-Type':'application/json','X-Forwarded-For':SPOOF})
with urllib.request.urlopen(request,context=context,timeout=15) as response:assert response.status==200
assert last_login_ip() not in (SPOOF,'172.30.254.2'), 'Caddy must overwrite spoofed headers and preserve the actual remote address'

# A peer on the management network must not be allowed to forge proxy headers.
code="import json,urllib.request; req=urllib.request.Request('http://app:8000/api/login',data=json.dumps("+repr(LOGIN)+").encode(),headers={'Content-Type':'application/json','X-Forwarded-For':"+repr(SPOOF)+"}); assert urllib.request.urlopen(req,timeout=15).status==200"
subprocess.run([*COMPOSE,'exec','-T','worker','python','-c',code],check=True)
assert last_login_ip() not in (SPOOF,'172.30.254.2'), 'Untrusted peers cannot provide client identity'
print('Real Caddy client identity and untrusted management peer spoof rejection passed')
