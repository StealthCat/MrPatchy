import hashlib
import hmac
import os
import secrets
import threading
from .db import DATA
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

_KEY_CACHE={}
def _key():
    path=DATA/'secret.key'
    if not path.exists():
        with open(path,'xb') as f: os.chmod(path,0o600); f.write(Fernet.generate_key())
    st=path.stat();stamp=(str(path),st.st_ino,st.st_mtime_ns,st.st_size)
    cached=_KEY_CACHE.get('v')
    if cached and cached[0]==stamp: return cached[1],cached[2]
    key=path.read_bytes();fernet=Fernet(key)
    _KEY_CACHE['v']=(stamp,key,fernet)
    return key,fernet
def cipher(): return _key()[1]
def derive_key(purpose):
    """Purpose-bound subkey (HKDF-SHA256) so the Fernet key itself is never reused as another secret."""
    return HKDF(algorithm=hashes.SHA256(),length=32,salt=None,info=b'mrpatchy:'+purpose.encode()).derive(_key()[0])
def seal(value): return cipher().encrypt(value.encode()).decode()
def unseal(value): return cipher().decrypt(value.encode()).decode()
SCRYPT_N,SCRYPT_R,SCRYPT_P=2**17,8,1
_KDF_SLOTS=threading.BoundedSemaphore(int(os.getenv('KDF_CONCURRENCY','4')))
def _scrypt(password,salt,n,r,p):
    # Bound aggregate KDF memory/CPU: at most KDF_CONCURRENCY hashes (~128 MiB each at N=2^17) run at once.
    with _KDF_SLOTS: return hashlib.scrypt(password.encode(),salt=bytes.fromhex(salt),n=n,r=r,p=p,maxmem=128*n*r+(1<<22)).hex()
def password_hash(password,salt=None):
    salt=salt or secrets.token_hex(16)
    return f'scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${salt}${_scrypt(password,salt,SCRYPT_N,SCRYPT_R,SCRYPT_P)}'
_SUPPORTED_COSTS={(16384,8,1),(SCRYPT_N,SCRYPT_R,SCRYPT_P)}
def _hex(value,max_len):
    if not (2<=len(value)<=max_len) or len(value)%2 or not all(c in '0123456789abcdefABCDEF' for c in value): raise ValueError('bad hex')
    return value
def _parse(value):
    """Return (n,r,p,salt,digest); legacy 'salt:digest' hashes used n=16384,r=8,p=1.
    Unsupported cost tuples and malformed salt/digest raise ValueError before any scrypt work starts."""
    if value.startswith('scrypt$'):
        _,n,r,p,salt,digest=value.split('$');cost=(int(n),int(r),int(p))
    else:
        salt,digest=value.split(':');cost=(16384,8,1)
    if cost not in _SUPPORTED_COSTS: raise ValueError('unsupported scrypt cost')
    return (*cost,_hex(salt,64),_hex(digest,128))
def verify(password,value):
    try:n,r,p,salt,digest=_parse(value);computed=_scrypt(password,salt,n,r,p)
    except (ValueError,TypeError):return False
    return hmac.compare_digest(computed,digest)
def needs_rehash(value):
    try:return _parse(value)[:3]!=(SCRYPT_N,SCRYPT_R,SCRYPT_P)
    except (ValueError,TypeError):return False
def token_hash(token): return hashlib.sha256(token.encode()).hexdigest()
