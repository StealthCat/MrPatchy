"""Limited opt-in worker admission: controller receipt and matching local key.

This does not attest schema, SSH identities, artifact/evidence mounts or target access.
"""
import os
import stat
import re
from cryptography.fernet import Fernet
from .db import DATA, Session, Setting

KEY='controller-state-v1'
MARKER=b'Mr Patchy controller encryption check v1'
RESULT='not_checked'


def local_cipher():
    fd=os.open(DATA/'secret.key',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        info=os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or info.st_mode&0o077 or info.st_size!=44:
            raise ValueError('Key must be a private regular file owned by this runtime')
        return Fernet(os.read(fd,45))
    finally:os.close(fd)


def publish(version):
    """Controller only: retain the existing canary; never repair a mismatch."""
    cipher=local_cipher()
    with Session() as s:
        row=s.get(Setting,KEY)
        if row:
            data=row.value
            if not isinstance(data,dict) or type(data.get('format')) is not int or data.get('format')!=1 or not isinstance(data.get('version'),str) or not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+',data['version']) or cipher.decrypt(data['encrypted'].encode())!=MARKER:
                raise ValueError('Controller state receipt is invalid')
            row.value={**data,'version':version}
        else:s.add(Setting(key=KEY,value={'format':1,'version':version,'encrypted':cipher.encrypt(MARKER).decode()}))
        s.commit()


def verify(version):
    """Read-only. Never generate a key, bootstrap tables or replace a receipt."""
    try:
        cipher=local_cipher()
        with Session() as s:
            row=s.get(Setting,KEY);data=row.value if row else None
            if not isinstance(data,dict) or type(data.get('format')) is not int or data.get('format')!=1 or data.get('version')!=version:
                raise ValueError('Controller receipt missing or incompatible')
            if cipher.decrypt(data['encrypted'].encode())!=MARKER:raise ValueError('Key mismatch')
    except Exception:
        raise ValueError('Worker controller-state preflight failed. Verify controller startup/version, database selection and the matching private secret.key. No work was admitted; inspect deployment configuration without copying secrets into logs.') from None
    return 'verified'


def admission(version):
    global RESULT
    RESULT='not_checked'
    setting=os.getenv('MRPATCHY_REQUIRE_CONTROLLER_STATE','0')
    if setting not in ('0','1'):raise ValueError('MRPATCHY_REQUIRE_CONTROLLER_STATE must be 0 or 1')
    if setting=='1':RESULT=verify(version)
    return RESULT
