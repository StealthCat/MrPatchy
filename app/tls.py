"""Independent internal/external HTTPS profiles and atomic Caddy configuration."""
import ipaddress
import json
import os
import re
import shlex
import shutil
import ssl
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import httpx
from cryptography import x509

_lock = threading.Lock()
DEFAULT_ACME = 'https://acme-v02.api.letsencrypt.org/directory'
PROFILES = ('internal', 'external')
SECRETS = ('certificate', 'private_key', 'ca', 'eab_key')


def directory():
    return Path(os.getenv('TLS_DIR', '/tls'))


def hostname(value):
    value = value.lower()
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        if len(value) > 253 or not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) for label in value.split('.')):
            raise ValueError('Domain must be a DNS name or IP address, without scheme, port or wildcard')
        return value


def address(host):
    return '[' + host + ']' if ':' in host else host


def defaults():
    common = dict(aliases=[], enabled=False, mode='acme', acme_url=DEFAULT_ACME,
                  email='', certificate='', private_key='', ca='', eab_id='', eab_key='',
                  redirect_http=True, https_port=None, challenge='auto')
    return {'internal': {**common, 'enabled': True, 'domain': os.getenv('DOMAIN', 'localhost'), 'mode': 'internal'},
            'external': {**common, 'domain': ''}}


def _legacy(content):
    """Read the single-site Caddyfile emitted by earlier Mr Patchy versions."""
    match = re.search(r'^([A-Za-z0-9.-]+)\s*\{\s*$', content, re.M)
    if not match:
        raise ValueError('Cannot migrate this Caddyfile automatically; restore a Mr Patchy generated configuration first')
    item = defaults()['internal'] | {'domain': hostname(match[1])}
    directive = re.search(r'^\s*tls\s+([^\n]+)', content, re.M)
    if not directive:
        raise ValueError('Missing legacy TLS configuration')
    tokens = shlex.split(directive[1])
    def material(path):
        resolved = Path(path).resolve()
        if not resolved.is_relative_to(directory().resolve()):
            raise ValueError('Legacy certificate material must be inside TLS_DIR')
        return resolved.read_text()
    if tokens == ['internal']:
        return item
    if len(tokens) == 2:
        return item | {'mode': 'uploaded', 'certificate': material(tokens[0]), 'private_key': material(tokens[1])}
    if tokens == ['{'] and 'issuer acme {' in content:
        url = re.search(r'^\s*dir\s+([^\n]+)', content, re.M)
        ca = re.search(r'^\s*trusted_roots\s+([^\n]+)', content, re.M)
        return item | {'mode': 'acme', 'acme_url': shlex.split(url[1])[0] if url else DEFAULT_ACME,
                       'ca': material(shlex.split(ca[1])[0]) if ca else ''}
    raise ValueError('Unrecognized legacy TLS configuration')


def read_profiles():
    path = directory() / 'Caddyfile'
    if not path.exists():
        return defaults()
    content = path.read_text()
    marker = re.search(r'^# mrpatchy-state: ([a-f0-9-]{36})$', content, re.M)
    if marker:
        state = json.loads((directory() / marker[1] / 'profiles.json').read_text())
        if set(state) != set(PROFILES):
            raise ValueError('Invalid TLS profile state')
        return state
    return defaults() | {'internal': _legacy(content)}


def public_state():
    with _lock:
        return _public(read_profiles())


def _public(profiles):
    result = {}
    for name, item in profiles.items():
        result[name] = {k: v for k, v in item.items() if k not in SECRETS}
        result[name].update(certificate_configured=bool(item.get('certificate') and item.get('private_key')),
                            ca_configured=bool(item.get('ca')), eab_configured=bool(item.get('eab_key')),
                            effective_https_port=item.get('https_port') or int(os.getenv('HTTPS_PORT', '443')))
    # Preserve the original API's summary fields for existing clients.
    primary = result['internal'] if result['internal']['enabled'] else result['external']
    return {'profiles': result, 'domain': primary['domain'], 'mode': primary['mode']}


def _safe(value):
    if any(c.isspace() or c in '{}"\\$' for c in value):
        raise ValueError('Invalid ACME field characters')
    return value


def _normalize(item):
    item = dict(item)
    if not item['enabled'] and not item['domain']:
        return item
    item['domain'] = hostname(item['domain'])
    item['aliases'] = list(dict.fromkeys(hostname(h) for h in item.get('aliases', [])))
    if item['mode'] not in ('internal', 'uploaded', 'acme'):
        raise ValueError('Invalid TLS mode')
    port = item.get('https_port')
    if port is not None and (type(port) is not int or not 1 <= port <= 65535):
        raise ValueError('HTTPS browser port must be 1–65535')
    if item.get('challenge') not in ('auto', 'http', 'tlsalpn'):
        raise ValueError('Invalid ACME challenge method')
    item['acme_url'] = item.get('acme_url') or DEFAULT_ACME
    url = urlsplit(_safe(item['acme_url']))
    if url.scheme != 'https' or not url.hostname or url.username is not None or url.password is not None or url.fragment:
        raise ValueError('ACME directory must be an HTTPS URL without credentials or fragment')
    if item.get('email') and not re.fullmatch(r'[^\s@{}"\\$]+@[^\s@{}"\\$]+', item['email']):
        raise ValueError('Invalid ACME email')
    if item.get('eab_id') and not re.fullmatch(r'[A-Za-z0-9_.:@/-]{1,512}', item['eab_id']):
        raise ValueError('Invalid EAB key ID')
    if item.get('eab_key') and not re.fullmatch(r'[A-Za-z0-9_-]+={0,2}', item['eab_key']):
        raise ValueError('EAB HMAC key must be base64url encoded')
    if bool(item.get('eab_id')) != bool(item.get('eab_key')):
        raise ValueError('Provide both EAB key ID and HMAC key, or explicitly clear EAB')
    return item


def _merge(previous, payload):
    value = {**previous, **{k: v for k, v in payload.items() if not k.startswith('clear_')}}
    value['acme_url'] = value.get('acme_url') or DEFAULT_ACME
    for field in SECRETS:
        if not value.get(field):
            value[field] = previous.get(field, '')
    if payload.get('clear_ca'):
        value['ca'] = ''
    elif previous.get('ca') and not payload.get('ca') and previous.get('acme_url', DEFAULT_ACME) != value['acme_url']:
        raise ValueError('Upload or explicitly clear the trusted CA when changing the ACME server')
    if payload.get('clear_eab'):
        value['eab_id'] = value['eab_key'] = ''
    elif previous.get('eab_key') and not payload.get('eab_key') and any(previous.get(k, '') != value.get(k, '') for k in ('acme_url', 'email', 'eab_id')):
        raise ValueError('Provide or explicitly clear EAB credentials when changing the ACME account/server')
    return _normalize(value)


def _write(path, text):
    with open(path, 'w', opener=lambda p, flags: os.open(p, flags, 0o600)) as stream:
        stream.write(text)
        stream.flush()
        os.fsync(stream.fileno())


def _sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _covers(names, host):
    try:
        return ipaddress.ip_address(host) in names.get_values_for_type(x509.IPAddress)
    except ValueError:
        return any(host == n.lower() or (n.startswith('*.') and host.count('.') == n.count('.') and host.endswith(n[1:].lower())) for n in names.get_values_for_type(x509.DNSName))


def _validate_certificate(item, cert_path, key_path):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)
    chain = x509.load_pem_x509_certificates(item['certificate'].encode())
    now = datetime.now(timezone.utc)
    if not chain or any(not cert.not_valid_before_utc <= now < cert.not_valid_after_utc for cert in chain):
        raise ValueError('Certificate chain is expired or not valid yet')
    try:
        names = chain[0].extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound as exc:
        raise ValueError('Certificate SAN is required') from exc
    for host in [item['domain'], *item.get('aliases', [])]:
        if not _covers(names, host):
            raise ValueError('Certificate SAN does not cover every configured domain/alias')
    return names


def _prepare(profiles, validate=True):
    folder = directory() / str(uuid.uuid4())
    folder.mkdir(parents=True, mode=0o700)
    try:
        lines = ['# mrpatchy-state: ' + folder.name, '{', '  admin 0.0.0.0:2019', '  auto_https disable_redirects', '}']
        assigned = set()
        for name in PROFILES:
            item = profiles[name]
            if not item['enabled']:
                continue
            hosts = list(dict.fromkeys([hostname(item['domain']), *[hostname(h) for h in item.get('aliases', [])]]))
            if assigned.intersection(hosts):
                raise ValueError('Internal and external domains/aliases must be different')
            assigned.update(hosts)
            port = str(item['https_port']) if item.get('https_port') else '{$HTTPS_PORT:443}'
            lines += [', '.join('https://' + address(h) for h in hosts) + ' {', '  encode zstd gzip',
                      '  header Alt-Svc ' + json.dumps('h3=":' + port + '"; ma=86400'), '  reverse_proxy app:8000']
            if item['mode'] == 'uploaded':
                cert_path, key_path = folder / (name + '-cert.pem'), folder / (name + '-key.pem')
                _write(cert_path, item['certificate']); _write(key_path, item['private_key'])
                if validate:
                    names = _validate_certificate(item, cert_path, key_path)
                    for other_name, other in profiles.items():
                        if other_name != name and other['enabled'] and other['mode'] != 'uploaded':
                            if any(_covers(names, h) for h in [other['domain'], *other.get('aliases', [])]):
                                raise ValueError('Uploaded certificate SAN overlaps an automatically managed profile; use a certificate scoped to this profile')
                lines.append(f'  tls {cert_path} {key_path}')
            elif item['mode'] == 'acme':
                lines += ['  tls {', '    issuer acme {', '      dir ' + json.dumps(item['acme_url']), '      test_dir ' + json.dumps(item['acme_url'])]
                if item.get('email'):
                    lines.append('      email ' + json.dumps(item['email']))
                if item.get('ca'):
                    if validate:
                        ssl.create_default_context(cadata=item['ca'])
                        if not x509.load_pem_x509_certificates(item['ca'].encode()):
                            raise ValueError('Provide a PEM CA certificate bundle')
                    ca_path = folder / (name + '-ca.pem'); _write(ca_path, item['ca'])
                    lines.append(f'      trusted_roots {ca_path}')
                if item.get('eab_id'):
                    lines.append('      eab ' + json.dumps(item['eab_id']) + ' ' + json.dumps(item['eab_key']))
                if item.get('challenge') == 'http':
                    lines.append('      disable_tlsalpn_challenge')
                elif item.get('challenge') == 'tlsalpn':
                    lines.append('      disable_http_challenge')
                lines += ['    }', '  }']
            else:
                lines.append('  tls internal')
            lines.append('}')
            for host in hosts:
                lines.append('http://' + address(host) + ' {')
                if item.get('redirect_http', True):
                    lines.append('  redir https://' + address(host) + ':' + port + '{uri} 308')
                else:
                    lines.append('  respond "Use HTTPS" 404')
                lines.append('}')
        if not assigned:
            raise ValueError('Keep at least one HTTPS profile enabled')
        content = '\n'.join(lines) + '\n'
        _write(folder / 'profiles.json', json.dumps(profiles))
        _write(folder / 'Caddyfile.pending', content)
        _sync_directory(folder)
        _sync_directory(directory())
        return folder, content
    except Exception:
        shutil.rmtree(folder, ignore_errors=True)
        raise


def apply(payload, profile='internal'):
    if profile not in PROFILES:
        raise ValueError('Unknown HTTPS profile')
    with _lock:
        profiles = read_profiles()
        profiles[profile] = _merge(profiles[profile], payload)
        folder, content = _prepare(profiles)
        try:
            _activate(folder, content)
        except Exception:
            if not (folder / 'recovery-required').exists():
                shutil.rmtree(folder, ignore_errors=True)
            raise
        return _public(profiles)


def _activate(folder, content):
    path = directory() / 'Caddyfile'
    previous = path.read_text() if path.exists() else None
    endpoint = os.getenv('CADDY_ADMIN', 'http://caddy:2019') + '/load'
    try:
        response = httpx.post(endpoint, headers={'Content-Type': 'text/caddyfile'}, content=content, timeout=30)
        response.raise_for_status()
        (folder / 'Caddyfile.pending').replace(path)
        _sync_directory(directory())
    except Exception as error:
        # A timeout may follow a successful live apply. Retain material until rollback is certain.
        if previous is not None:
            try:
                restored = httpx.post(endpoint, headers={'Content-Type': 'text/caddyfile'}, content=previous, timeout=30)
                restored.raise_for_status()
                if not path.exists() or path.read_text() != previous:
                    rollback = folder / 'Caddyfile.rollback'
                    _write(rollback, previous); rollback.replace(path)
                    _sync_directory(directory())
            except Exception:
                _write(folder / 'recovery-required', 'Caddy state uncertain; preserve these files and reload /tls/Caddyfile.\n')
                raise RuntimeError('TLS apply failed and rollback could not be confirmed; inspect Caddy before retrying') from error
        elif not isinstance(error, httpx.HTTPStatusError):
            _write(folder / 'recovery-required', 'Caddy state uncertain; no prior Caddyfile was available.\n')
        raise


def bootstrap():
    """Run before Caddy starts; migrate generated legacy files without contacting a CA."""
    path = directory() / 'Caddyfile'
    if path.exists() and '# mrpatchy-state: ' in path.read_text():
        return
    profiles = read_profiles()
    # Expiry must not prevent access to the UI for replacing an existing certificate.
    folder, _ = _prepare(profiles, validate=False)
    (folder / 'Caddyfile.pending').replace(path)
    _sync_directory(directory())


if __name__ == '__main__':
    bootstrap()
