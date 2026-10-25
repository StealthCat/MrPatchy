"""Named identities and replay-resistant TOTP. No third-party OTP service."""
import base64
import hashlib
import hmac
import secrets
import struct
import time
from contextvars import ContextVar
from sqlalchemy import String, Boolean, Integer
from sqlalchemy.orm import Mapped,mapped_column
from .db import Base
from .security import seal,unseal

actor=ContextVar('actor',default='system')
class User(Base):
    __tablename__='users'
    username:Mapped[str]=mapped_column(String(64),primary_key=True)
    password:Mapped[str]=mapped_column(String(512))
    role:Mapped[str]=mapped_column(String(20),default='viewer')
    enabled:Mapped[bool]=mapped_column(Boolean,default=True)
    otp_secret:Mapped[str]=mapped_column(String(512),default='')
    otp_pending:Mapped[str]=mapped_column(String(512),default='')
    otp_counter:Mapped[int]=mapped_column(Integer,default=-1)
    generation:Mapped[int]=mapped_column(Integer,default=0)

def code(secret,counter):
    key=base64.b32decode(secret)
    digest=hmac.new(key,struct.pack('>Q',counter),hashlib.sha1).digest()
    offset=digest[-1]&15
    return str((struct.unpack('>I',digest[offset:offset+4])[0]&0x7fffffff)%1000000).zfill(6)

def consume_otp(user,value,now=None,pending=False):
    if not isinstance(value,str) or len(value)!=6 or not value.isascii() or not value.isdigit(): return False
    secret=user.otp_pending if pending else user.otp_secret
    if not secret: return False
    counter=int((time.time() if now is None else now)//30)
    for candidate in (counter-1,counter,counter+1):
        if candidate>user.otp_counter and hmac.compare_digest(code(unseal(secret),candidate),value):
            user.otp_counter=candidate
            return True
    return False

def new_secret(): return base64.b32encode(secrets.token_bytes(20)).decode()
