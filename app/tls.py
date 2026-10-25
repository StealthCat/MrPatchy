import json
import os
import re
import ssl
import tempfile
import uuid
import threading
import shutil
from pathlib import Path
from urllib.parse import urlsplit
import httpx
from cryptography import x509
from .db import DATA

_lock=threading.Lock()

def apply(payload):
    with _lock:
        return _apply(payload)

def _apply(payload):
    domain=payload['domain']
    if not re.fullmatch(r'[a-zA-Z0-9](?:[a-zA-Z0-9.-]{0,251}[a-zA-Z0-9])?',domain): raise ValueError('Domain must be a DNS name or IPv4 address, without scheme or port')
    mode=payload['mode']; folder=Path(os.getenv('TLS_DIR','/tls'))/str(uuid.uuid4()); folder.mkdir(parents=True,mode=0o700)
    try:
        return _configure(payload,domain,mode,folder)
    except Exception:
        # _configure preserves folders only if Caddy may still reference them.
        if not (folder/'recovery-required').exists(): shutil.rmtree(folder,ignore_errors=True)
        raise

def _configure(payload,domain,mode,folder):
    lines=['{','  admin 0.0.0.0:2019','}',f'{domain} {{','  encode zstd gzip','  reverse_proxy app:8000']
    if mode=='uploaded':
        cert=payload.get('certificate',''); key=payload.get('private_key','')
        (folder/'cert.pem').write_text(cert); (folder/'key.pem').write_text(key); (folder/'key.pem').chmod(0o600)
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.load_cert_chain(folder/'cert.pem',folder/'key.pem')
        parsed=x509.load_pem_x509_certificate(cert.encode())
        from datetime import datetime, timezone
        if parsed.not_valid_before_utc>datetime.now(timezone.utc): raise ValueError('Certificate is not valid yet')
        if parsed.not_valid_after_utc<=datetime.now(timezone.utc): raise ValueError('Certificate has expired')
        names=parsed.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        import ipaddress
        try: covered=ipaddress.ip_address(domain) in names.get_values_for_type(x509.IPAddress)
        except ValueError:
            covered=any(domain.lower()==n.lower() or (n.startswith('*.') and domain.count('.')==n.count('.') and domain.lower().endswith(n[1:].lower())) for n in names.get_values_for_type(x509.DNSName))
        if not covered: raise ValueError('Certificate SAN does not cover this domain')
        lines.append(f'  tls {folder}/cert.pem {folder}/key.pem')
    elif mode=='acme':
        url=payload.get('acme_url') or 'https://acme-v02.api.letsencrypt.org/directory'
        parsed=urlsplit(url)
        if parsed.scheme!='https' or not parsed.hostname or parsed.username is not None or parsed.password is not None or parsed.fragment or any(c.isspace() or c in '{}\"\\' for c in url): raise ValueError('ACME directory must be an HTTPS URL')
        lines.extend(['  tls {','    issuer acme {','      dir '+json.dumps(url)])
        if payload.get('ca'):
            x509.load_pem_x509_certificate(payload['ca'].encode())
            (folder/'ca.pem').write_text(payload['ca']); lines.append(f'      trusted_roots {folder}/ca.pem')
        lines.extend(['    }','  }'])
    elif mode=='internal': lines.append('  tls internal')
    else: raise ValueError('Invalid TLS mode')
    lines.append('}'); content='\n'.join(lines)+'\n'
    # Caddy validates and atomically loads this config. Its admin API is on a private Docker network only.
    path=Path(os.getenv('TLS_DIR','/tls'))/'Caddyfile'
    previous=path.read_text() if path.exists() else None
    staged=folder/'Caddyfile.pending'
    with open(staged,'w') as stream:
        stream.write(content);stream.flush();os.fsync(stream.fileno())
    attempted=False
    endpoint=os.getenv('CADDY_ADMIN','http://caddy:2019')+'/load'
    try:
        attempted=True
        r=httpx.post(endpoint,headers={'Content-Type':'text/caddyfile'},content=content,timeout=30)
        r.raise_for_status()
        staged.replace(path)
    except Exception as error:
        # A timeout can occur after Caddy applied the configuration. Restore the
        # previous configuration before deleting files Caddy could reference.
        if attempted and previous is not None:
            try:
                restored=httpx.post(endpoint,headers={'Content-Type':'text/caddyfile'},content=previous,timeout=30)
                restored.raise_for_status()
            except Exception:
                (folder/'recovery-required').write_text('Caddy state uncertain; preserve these certificates and reload /tls/Caddyfile.\n')
                raise RuntimeError('TLS apply failed and rollback could not be confirmed; inspect Caddy before retrying') from error
        elif attempted and not isinstance(error,httpx.HTTPStatusError):
            (folder/'recovery-required').write_text('Caddy state uncertain; no prior Caddyfile was available.\n')
        raise
    return {'domain':domain,'mode':mode,'acme_url':payload.get('acme_url','')}
