"""Encrypted, staged database settings. Activation is exclusively an offline action."""
from contextlib import contextmanager
import fcntl
import json
import os
import ssl
import subprocess
import sys
from pathlib import Path
import tempfile
from threading import BoundedSemaphore
import time

from cryptography.fernet import Fernet
from pydantic import BaseModel, Field, ConfigDict
from sqlalchemy.engine import URL, make_url


def data_dir():
    return Path(os.getenv('DATA_DIR', '/data'))


def read_profile(name):
    path = data_dir() / ('database-' + name + '.json')
    if not path.exists():
        return None
    try:
        encrypted = json.loads(path.read_text())['encrypted']
        return json.loads(Fernet((data_dir() / 'secret.key').read_bytes()).decrypt(encrypted.encode()))
    except Exception:
        raise ValueError('Cannot read encrypted database settings. Restore the matching secret.key and database profile.') from None


def write_profile(name, value):
    from .security import seal
    root = data_dir()
    fd, temporary = tempfile.mkstemp(prefix='.database-', dir=root)
    try:
        with os.fdopen(fd, 'w') as stream:
            os.fchmod(stream.fileno(), 0o600)
            json.dump({'encrypted': seal(json.dumps(value))}, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, root / ('database-' + name + '.json'))
        directory = os.open(root, os.O_RDONLY)
        try: os.fsync(directory)
        finally: os.close(directory)
    finally:
        if os.path.exists(temporary): os.unlink(temporary)


def runtime_url():
    profile = read_profile('active')
    return profile['url'] if profile else os.getenv('DATABASE_URL') or 'sqlite:///' + str(data_dir() / 'mrpatchy.db')


@contextmanager
def maintenance_lock(offline=False):
    """Shared by serving processes; exclusive for migration. Requires shared DATA_DIR."""
    data_dir().mkdir(parents=True, exist_ok=True)
    with open(data_dir() / 'database-maintenance.lock', 'a') as stream:
        try:
            fcntl.flock(stream, (fcntl.LOCK_EX if offline else fcntl.LOCK_SH) | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError('Database maintenance lock is busy. Stop all app and worker replicas before migration; do not start them until it finishes.') from None
        try: yield
        finally: fcntl.flock(stream, fcntl.LOCK_UN)


@contextmanager
def runtime_guard():
    with maintenance_lock():
        from .db import URL as current_url
        if runtime_url() != current_url:
            raise ValueError('Database changed during startup. Restart this process to load the active database.')
        yield


class DatabaseInput(BaseModel):
    model_config = ConfigDict(extra='forbid')
    backend: str = Field(pattern=r'^(sqlite|mysql)$')
    host: str = Field(default='', max_length=253, pattern=r'^[A-Za-z0-9.:-]*$')
    port: int = Field(default=3306, ge=1, le=65535)
    database: str = Field(default='mrpatchy', pattern=r'^[A-Za-z0-9_]{1,64}$')
    username: str = Field(default='', max_length=128)
    password: str = Field(default='', max_length=1000)
    clear_password: bool = False
    tls: bool = True
    ca_file: str = Field(default='', max_length=500)
    sqlite_file: str = Field(default='mrpatchy-migrated.db', pattern=r'^[A-Za-z0-9][A-Za-z0-9_.-]{0,119}\.db$')


def _mysql_profile(body, previous):
    """Validate MySQL input and resolve the password under the unchanged-destination rules."""
    values = body.model_dump(exclude={'clear_password'})
    if any(c in body.username + body.password + body.ca_file for c in '\x00\r\n'):
        raise ValueError('Database credentials and paths cannot contain NUL or line breaks')
    if not body.host or not body.username: raise ValueError('MySQL host and username are required')
    if body.password and body.clear_password: raise ValueError('Provide a password or clear it, not both')
    if not body.password and not body.clear_password:
        identity = ('backend', 'host', 'port', 'database', 'username', 'tls', 'ca_file')
        if all(previous.get(k) == values[k] for k in identity):
            values['password'] = previous.get('password', '')
        else:
            raise ValueError('Enter the password (or explicitly select no password) when changing the MySQL destination or TLS settings')
    if body.ca_file and not body.tls: raise ValueError('Enable verified TLS to use a CA file')
    if body.ca_file and not Path(body.ca_file).is_absolute(): raise ValueError('CA file must be an absolute path accessible inside the app and worker containers')
    return values


def stage(body):
    previous = read_profile('target') or {}
    values = body.model_dump(exclude={'clear_password'})
    if body.backend == 'mysql':
        values = _mysql_profile(body, previous)
    else:
        if any(c in body.username + body.password + body.ca_file for c in '\x00\r\n'):
            raise ValueError('Database credentials and paths cannot contain NUL or line breaks')
        values['password'] = ''
    # Validate URL construction without opening or changing either database.
    profile_url(values)
    write_profile('target', values)
    return public_target(values)


TEST_TIMEOUT = 5
_TEST_SLOTS = BoundedSemaphore(2)
TEST_SCOPE = 'Result describes connectivity from this controller only, not other workers or HA members.'
_TEST_DETAILS = {
    'ok': 'Connected, authenticated and ran a read-only query. This does not prove migration privileges, schema compatibility or HA readiness.',
    'busy': 'Other connection tests are in progress on this controller. Try again shortly.',
    'timeout': 'The connection test timed out. Check the host, port and firewall.',
    'authentication': 'Authentication failed. Check the username and password.',
    'database': 'The database does not exist. Create it first.',
    'access': 'The account cannot access this database.',
    'tls': 'TLS verification failed. Check the CA file and that the host name matches the certificate.',
    'connectivity': 'Could not reach the database host. Check the host name, port and network access.',
    'error': 'The connection test failed. Check the database settings.',
}


def test_connection(body):
    """Read-only, bounded connectivity check using the entered (unsaved) values.

    Never writes settings, creates objects or returns driver text; the result only
    proves this controller can authenticate and run SELECT 1 against the database.
    """
    if body.backend != 'mysql': raise ValueError('Only MySQL destinations can be tested')
    values = _mysql_profile(body, read_profile('target') or {})
    url = make_url(profile_url(values))
    kwargs = dict(host=url.host, port=url.port, user=url.username, password=url.password or '', database=url.database,
                  charset='utf8mb4', connect_timeout=TEST_TIMEOUT, read_timeout=TEST_TIMEOUT, write_timeout=TEST_TIMEOUT,
                  autocommit=False, read_default_file=None)
    if values['tls']:
        kwargs.update(ssl_ca=url.query['ssl_ca'], ssl_verify_cert=True, ssl_verify_identity=True)
    started = time.monotonic()
    category = 'busy'
    if _TEST_SLOTS.acquire(blocking=False):
        try:
            category = _run_mysql_probe(kwargs)
        finally:
            _TEST_SLOTS.release()
    result = {'ok': category == 'ok', 'category': category, 'scope': TEST_SCOPE, 'detail': _TEST_DETAILS[category]}
    if result['ok']:
        result['elapsed_ms'] = int((time.monotonic() - started) * 1000)
    return result


def _run_mysql_probe(kwargs):
    # Killing and reaping the child stops DNS and network activity before the slot is released.
    # Pass credentials through stdin, and accept only a fixed category from the child.
    try:
        result = subprocess.run(
            [sys.executable, str(Path(__file__).with_name('database_probe.py'))],
            input=json.dumps(kwargs).encode(), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=TEST_TIMEOUT, check=False,
        )
    except subprocess.TimeoutExpired:
        return 'timeout'
    except OSError:
        return 'error'
    category = result.stdout.decode('ascii', errors='replace').strip()
    return category if result.returncode == 0 and category in _TEST_DETAILS else 'error'


def profile_url(profile):
    if profile['backend'] == 'sqlite':
        return URL.create('sqlite', database=str(data_dir() / profile['sqlite_file'])).render_as_string(hide_password=False)
    query = {'charset': 'utf8mb4', 'connect_timeout': '10', 'read_timeout': '60', 'write_timeout': '60'}
    if profile['tls']:
        # Supply an explicit trust bundle: PyMySQL disables hostname checking
        # when no ca/capath is supplied, even with verification flags.
        ca = profile['ca_file'] or ssl.get_default_verify_paths().cafile
        if not ca: raise ValueError('No system CA bundle found; provide a database CA file')
        query.update(ssl_ca=ca, ssl_check_hostname='true')
    return URL.create('mysql+pymysql', host=profile['host'], port=profile['port'], database=profile['database'],
                      username=profile['username'], password=profile['password'], query=query).render_as_string(hide_password=False)


def public_target(profile):
    if not profile: return None
    return {k:v for k,v in profile.items() if k != 'password'} | {'password_configured': bool(profile.get('password'))}


def public_state():
    from .db import URL as current_url
    url = make_url(current_url)
    return {'active': {'backend': url.get_backend_name(), 'host': url.host or '', 'port': url.port or 3306,
                       'database': url.database, 'username': url.username or ''},
            'source': 'offline migration profile' if read_profile('active') else 'deployment environment / default',
            'target': public_target(read_profile('target'))}
