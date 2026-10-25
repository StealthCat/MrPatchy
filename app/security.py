import hashlib
import hmac
import os
import secrets
import time
from .db import DATA
from cryptography.fernet import Fernet

def cipher():
    path=DATA/'secret.key'
    if not path.exists():
        with open(path,'xb') as f: os.chmod(path,0o600); f.write(Fernet.generate_key())
    return Fernet(path.read_bytes())
def seal(value): return cipher().encrypt(value.encode()).decode()
def unseal(value): return cipher().decrypt(value.encode()).decode()
def password_hash(password,salt=None):
    salt=salt or secrets.token_hex(16)
    return salt+':'+hashlib.scrypt(password.encode(),salt=bytes.fromhex(salt),n=16384,r=8,p=1).hex()
def verify(password,value):
    return hmac.compare_digest(password_hash(password,value.split(':')[0]),value)
def token_hash(token): return hashlib.sha256(token.encode()).hexdigest()
