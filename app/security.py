import hashlib
import hmac
import os
import secrets
import time
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
def _scrypt(password,salt,n,r,p):
    return hashlib.scrypt(password.encode(),salt=bytes.fromhex(salt),n=n,r=r,p=p,maxmem=128*n*r+(1<<22)).hex()
def password_hash(password,salt=None):
    salt=salt or secrets.token_hex(16)
    return f'scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${salt}${_scrypt(password,salt,SCRYPT_N,SCRYPT_R,SCRYPT_P)}'
def _parse(value):
    """Return (n,r,p,salt,digest); legacy 'salt:digest' hashes used n=16384,r=8,p=1."""
    if value.startswith('scrypt$'):
        _,n,r,p,salt,digest=value.split('$');return int(n),int(r),int(p),salt,digest
    salt,digest=value.split(':');return 16384,8,1,salt,digest
def verify(password,value):
    try:n,r,p,salt,digest=_parse(value);computed=_scrypt(password,salt,n,r,p)
    except (ValueError,TypeError):return False
    return hmac.compare_digest(computed,digest)
def needs_rehash(value):
    try:return _parse(value)[:3]!=(SCRYPT_N,SCRYPT_R,SCRYPT_P)
    except (ValueError,TypeError):return False
def token_hash(token): return hashlib.sha256(token.encode()).hexdigest()
