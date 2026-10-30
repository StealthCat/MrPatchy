"""Limited opt-in worker admission: controller receipt and matching local key.

Checks required tables/columns/primary keys, not types, shared files or target access.
"""
import os
import stat
import re
import json
import hashlib
from sqlalchemy import inspect
from cryptography.fernet import Fernet
from .db import DATA, Session, Setting

KEY='controller-state-v1'
MARKER=b'Mr Patchy controller encryption check v1'
RESULT='not_checked'
STRUCTURE_RESULT='not_checked'
PROTOCOL=1


def schema_requirements():
    from .db import Base,register_models
    register_models()
    return {table.name:{'columns':sorted(column.name for column in table.columns),
                       'primary_key':[column.name for column in table.primary_key.columns]}
            for table in sorted(Base.metadata.tables.values(),key=lambda table:table.name)}


def requirements_digest(shape):
    return hashlib.sha256(json.dumps(shape,sort_keys=True,separators=(',',':')).encode()).hexdigest()


def inspect_structure(connection,shape):
    inspector=inspect(connection)
    tables=set(inspector.get_table_names())
    for name,required in shape.items():
        if name not in tables:raise ValueError('Required table unavailable')
        columns={column['name'] for column in inspector.get_columns(name)}
        primary=inspector.get_pk_constraint(name).get('constrained_columns') or []
        if not set(required['columns']).issubset(columns) or primary!=required['primary_key']:
            raise ValueError('Required columns or primary key differ')


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
    contract={'protocol':PROTOCOL,'requirements':requirements_digest(schema_requirements())}
    with Session() as s:
        row=s.get(Setting,KEY)
        if row:
            data=row.value
            if not isinstance(data,dict) or type(data.get('format')) is not int or data.get('format')!=1 or not isinstance(data.get('version'),str) or not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+',data['version']) or cipher.decrypt(data['encrypted'].encode())!=MARKER:
                raise ValueError('Controller state receipt is invalid')
            if ('protocol' in data or 'requirements' in data) and (type(data.get('protocol')) is not int or data.get('protocol')!=PROTOCOL or not isinstance(data.get('requirements'),str) or not re.fullmatch('[a-f0-9]{64}',data['requirements'])):
                raise ValueError('Controller receipt protocol is invalid')
            if data.get('version')==version and 'requirements' in data and data['requirements']!=contract['requirements']:
                raise ValueError('Controller receipt requirements differ for this source version')
            if data.get('version')==version and 'requirements' not in data:
                raise ValueError('Current controller receipt lacks requirements')
            row.value={**data,'version':version,**contract}
        else:s.add(Setting(key=KEY,value={'format':1,'version':version,'encrypted':cipher.encrypt(MARKER).decode(),**contract}))
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
            shape=schema_requirements()
            if type(data.get('protocol')) is not int or data.get('protocol')!=PROTOCOL or data.get('requirements')!=requirements_digest(shape):
                raise ValueError('Receipt protocol or requirements differ')
            inspect_structure(s.connection(),shape)
    except Exception:
        raise ValueError('Worker controller-state preflight failed. Verify controller startup/version, receipt protocol, required tables/columns/primary keys, database selection and the matching private secret.key. No work was admitted; inspect deployment configuration without copying secrets into logs.') from None
    return 'verified'


def admission(version):
    global RESULT,STRUCTURE_RESULT
    RESULT='not_checked';STRUCTURE_RESULT='not_checked'
    setting=os.getenv('MRPATCHY_REQUIRE_CONTROLLER_STATE','0')
    if setting not in ('0','1'):raise ValueError('MRPATCHY_REQUIRE_CONTROLLER_STATE must be 0 or 1')
    if setting=='1':
        RESULT=verify(version);STRUCTURE_RESULT='verified'
    return RESULT
