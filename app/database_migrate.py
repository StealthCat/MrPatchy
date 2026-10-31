"""Offline, verified database copy. Never deletes source data or overwrites destination rows."""
import argparse
from decimal import Decimal
import errno as errno_codes
import hashlib
import json
from pathlib import Path
import re
import ssl
import sys

from sqlalchemy import create_engine, inspect, select, func, text
from sqlalchemy.engine import URL, make_url
from sqlalchemy.pool import NullPool

from . import database_config as settings


class MigrationError(ValueError):
    pass


class Progress:
    """Operator-facing stage tracking. Writes only fixed text and safe identifiers to stderr."""
    NOTHING_WRITTEN=('prepare','source-connect','source-validate','source-fingerprint','destination-connect','destination-validate')

    def __init__(self,stream=None,verbose=False):
        self.stream,self.verbose=stream,verbose
        self.stage=self.role=self.table=None
        self.dry_run=False

    def enter(self,stage,message,role=None,table=None):
        self.stage,self.role,self.table=stage,role,table
        if self.stream is not None:
            print('[migrate] '+clean(message),file=self.stream,flush=True)

    def skipped(self,message):
        if self.stream is not None:
            print('[migrate] skipped (dry run): '+clean(message),file=self.stream,flush=True)

    def destination_state(self):
        if self.stage in self.NOTHING_WRITTEN or self.stage is None:
            return 'Destination: nothing has been written by this run.'
        if self.stage=='schema-create':
            return 'Destination: empty tables may have been created (DDL is not transactional); inspect it before retrying.'
        if self.stage in ('copy','verify-transaction'):
            return 'Destination: tables may exist and rows may have been inserted in an uncommitted transaction; rollback was not verified, so inspect it before retrying.'
        if self.stage=='verify-committed':
            return 'Destination: the copy was committed but its fresh-connection verification did not complete; it was NOT activated. Inspect it before retrying.'
        return 'Destination: a complete verified copy exists; the activation outcome is unknown, so inspect the active profile before starting services.'


def clean(value,limit=160):
    """Bound and escape text for terminal output (control characters, newlines, long identifiers)."""
    text_value=re.sub(r'[^\x20-\x7e]',lambda m:'\\x%02x'%ord(m.group()) if ord(m.group())<256 else '\\u%04x'%ord(m.group()),str(value))
    return text_value if len(text_value)<=limit else text_value[:limit-3]+'...'


MYSQL_CATEGORIES={
    1045:('authentication','Check the destination user name and password in Settings → Database.'),
    1044:('permissions','Grant the database user access to the named database.'),
    1142:('permissions','Grant CREATE, INSERT, SELECT and INDEX on the database to the user.'),
    1143:('permissions','Grant column-level privileges or table privileges to the user.'),
    1049:('database-missing','Create the named database or correct its name in Settings → Database.'),
    2002:('connection','Check the host, port, firewall and that the database server is running.'),
    2003:('connection','Check the host, port, firewall and that the database server is running.'),
    2005:('connection','Check that the database host name resolves from the container.'),
    2006:('connection','The server closed the connection; check max_allowed_packet, timeouts and server logs.'),
    2013:('connection','The connection was lost mid-query; check network stability, timeouts and server logs.'),
    2026:('tls','Check MYSQL_SSL_CA and that the server certificate matches the host name.'),
    1114:('storage','The database is out of space; free space on the database server.'),
    1021:('storage','The database server disk is full; free space on it.'),
    1040:('capacity','The server has too many connections; retry after reducing other clients.'),
    1153:('capacity','A row exceeds max_allowed_packet; raise it on the destination server.'),
    1406:('data','A value is too long for the destination column; no truncation was applied.'),
    1366:('data','A value cannot be stored in the destination encoding; check the character set.'),
    1292:('data','A value was rejected by the destination type; check strict-mode and column types.'),
    1205:('locking','Lock wait timeout; ensure no other client is using the database.'),
    1213:('locking','Deadlock detected; ensure no other client is using the database.'),
}
SQLITE_CATEGORIES={
    'SQLITE_BUSY':('locking','Another process holds the SQLite file; stop other users of it.'),
    'SQLITE_LOCKED':('locking','Another connection holds the SQLite file; stop other users of it.'),
    'SQLITE_READONLY':('permissions','The SQLite file or its directory is read-only for this user.'),
    'SQLITE_CANTOPEN':('permissions','The SQLite file cannot be opened; check its path, ownership and the volume mount.'),
    'SQLITE_PERM':('permissions','Permission denied on the SQLite file or directory.'),
    'SQLITE_FULL':('storage','The volume is full; free space and retry with a fresh destination.'),
    'SQLITE_IOERR':('storage','Disk I/O error; check the volume and free space.'),
    'SQLITE_CORRUPT':('corruption','The SQLite file is damaged; restore it from backup.'),
    'SQLITE_NOTADB':('corruption','The file is not a SQLite database.'),
}
OS_CATEGORIES={
    errno_codes.ENOSPC:('storage','The volume is full; free space and retry with a fresh destination.'),
    errno_codes.EDQUOT:('storage','The disk quota is exhausted; free space and retry.'),
    errno_codes.EACCES:('permissions','Permission denied; check ownership and mode of the path.'),
    errno_codes.EPERM:('permissions','Operation not permitted; check ownership and mode of the path.'),
    errno_codes.EROFS:('permissions','The filesystem is read-only.'),
    errno_codes.ECONNREFUSED:('connection','Connection refused; check the host, port and that the server is running.'),
    errno_codes.ETIMEDOUT:('connection','Connection timed out; check the host, port and firewall.'),
    errno_codes.EHOSTUNREACH:('connection','Host unreachable; check routing and firewall.'),
    errno_codes.ENETUNREACH:('connection','Network unreachable; check routing from the container.'),
}
STAGE_HINTS={
    'prepare':'Check DATA_DIR, the maintenance lock and the saved destination profile.',
    'source-connect':'Check the active database settings and that the source file or server is reachable.',
    'source-validate':'Check source integrity and schema; start the current version once to upgrade tables.',
    'source-fingerprint':'Re-run after confirming the source is readable and unchanged.',
    'destination-connect':'Check the destination host, credentials and TLS settings in Settings → Database.',
    'destination-validate':'Use an empty dedicated destination database.',
    'schema-create':'Check the destination user can CREATE tables and that the volume has free space.',
    'copy':'Check destination free space, max_allowed_packet and column limits.',
    'verify-transaction':'Compare the destination collation and column types with the source.',
    'verify-committed':'Inspect the destination; do not activate or start services yet.',
    'activate':'Check DATA_DIR is writable and has free space.',
}


def chain(error,limit=6):
    seen=[]
    while error is not None and len(seen)<limit and all(error is not other for other in seen):
        seen.append(error)
        error=error.__cause__ or (None if error.__suppress_context__ else error.__context__)
    return seen


def diagnose(error):
    """Return (category, hint, code, class names) for an unexpected exception without any message text."""
    category=hint=code=None
    classes=[]
    for item in chain(error):
        driver=getattr(item,'orig',None)
        for candidate in ((item,driver) if driver is not None else (item,)):
            name=type(candidate).__module__.split('.')[0]+'.'+type(candidate).__name__
            if name not in classes:classes.append(name)
            args=getattr(candidate,'args',())
            number=args[0] if args and isinstance(args[0],int) and not isinstance(args[0],bool) else None
            sqlite_name=getattr(candidate,'sqlite_errorname',None)
            sqlstate=getattr(candidate,'sqlstate',None) or getattr(candidate,'pgcode',None)
            if category is None:
                if isinstance(candidate,ssl.SSLError):
                    category,hint,code='tls','TLS negotiation or certificate verification failed; check MYSQL_SSL_CA and the server certificate.','ssl'
                elif sqlite_name:
                    base=sqlite_name.split('_',2)
                    base='_'.join(base[:2]) if len(base)>1 else sqlite_name
                    entry=SQLITE_CATEGORIES.get(sqlite_name) or SQLITE_CATEGORIES.get(base)
                    category,hint=entry or ('database','See the exception class and code, then check the SQLite file.')
                    code=sqlite_name
                elif isinstance(candidate,OSError) and candidate.errno in OS_CATEGORIES:
                    category,hint=OS_CATEGORIES[candidate.errno];code=errno_codes.errorcode.get(candidate.errno,str(candidate.errno))
                elif number in MYSQL_CATEGORIES and 'mysql' in type(candidate).__module__.lower()+type(item).__module__.lower()+str(driver and type(driver).__module__).lower():
                    category,hint=MYSQL_CATEGORIES[number];code='mysql '+str(number)
                elif isinstance(sqlstate,str) and re.fullmatch(r'[0-9A-Z]{5}',sqlstate):
                    category,hint,code='database','See the SQLSTATE and exception class, then check database logs.','SQLSTATE '+sqlstate
                elif number is not None and 'mysql' in type(candidate).__module__.lower():
                    category,hint,code='database','See the MySQL error number in the server documentation and logs.','mysql '+str(number)
    return category or 'unexpected',hint,code,classes


def stack_locations(error,limit=8):
    """File basename:line function for the innermost frames. Never includes locals or message text."""
    trace=error.__traceback__
    frames=[]
    while trace is not None:
        frame=trace.tb_frame.f_code
        frames.append(Path(frame.co_filename).name+':'+str(trace.tb_lineno)+' '+frame.co_name)
        trace=trace.tb_next
    own=[f for f in frames if f.startswith('database_migrate.py:')]
    keep=own[:limit//2]+[f for f in frames if f not in own][-(limit-len(own[:limit//2])):]
    return keep


def failure_report(error,progress):
    stage=progress.stage or 'prepare'
    category,hint,code,classes=diagnose(error)
    where=stage+(' ('+progress.role+')' if progress.role else '')+(' table '+json.dumps(clean(progress.table,80)) if progress.table else '')
    lines=['Migration failed at stage '+where+'.',
        'Category: '+category+'; exception: '+clean(classes[0] if classes else type(error).__name__)+('; code: '+clean(code) if code else '')+'.',
        'Next check: '+(hint or STAGE_HINTS.get(stage,'Inspect the database settings and server logs.'))+' Stage guidance: '+STAGE_HINTS.get(stage,'')]
    lines.append(progress.destination_state()+(' Active database unchanged.' if stage!='activate' else ' Active profile state is unverified.'))
    if progress.verbose:
        lines.append('Cause chain: '+' <- '.join(clean(c,80) for c in classes))
        lines.append('Stack: '+' | '.join(clean(f,100) for f in stack_locations(error)))
    else:
        lines.append('Re-run with --verbose for the exception chain and stack locations. No credentials, rows or driver messages are logged.')
    return '\n'.join(lines)


def schema_object_summary(label, names, limit=8):
    """Render bounded, terminal-safe schema identifiers for operator review."""
    values=sorted(str(name) for name in names)
    shown=[]
    for name in values[:limit]:
        if len(name)>120:name=name[:117]+'...'
        shown.append(json.dumps(name,ensure_ascii=True))
    suffix='' if len(values)<=limit else ', ... (+'+str(len(values)-limit)+' more)'
    return label+': '+', '.join(shown)+suffix


def metadata():
    # Startup and offline tools must use the same registry. A second list can
    # silently omit models when a fresh CLI process has not imported the web app.
    from .db import Base, register_models
    register_models()
    return Base.metadata


def connect_url(value, source=False):
    url = make_url(value)
    if url.drivername not in ('sqlite', 'mysql+pymysql'):
        raise MigrationError('Only file-backed SQLite and mysql+pymysql are supported')
    if url.get_backend_name() == 'sqlite':
        if not url.database or url.database == ':memory:' or url.query:
            raise MigrationError('Use a plain file-backed SQLite database URL')
        path = Path(url.database)
        if not path.is_absolute() or path.is_symlink():
            raise MigrationError('SQLite database paths must be absolute and cannot be symlinks')
        if source:
            if not path.is_file(): raise MigrationError('Source SQLite database does not exist; nothing was created')
            # mode=ro prevents accidental source initialization and writes.
            url = URL.create('sqlite', database=path.resolve().as_uri(), query={'mode':'ro','uri':'true'})
        elif not path.parent.is_dir():
            raise MigrationError('Destination SQLite directory does not exist')
    elif not url.database:
        raise MigrationError('Select an existing named MySQL database')
    return create_engine(url, poolclass=NullPool, hide_parameters=True)


def validate_source(connection, meta):
    inspector = inspect(connection)
    source_tables=set(inspector.get_table_names())
    expected_tables=set(meta.tables)
    source_views=set(inspector.get_view_names())
    missing=expected_tables-source_tables
    unexpected=source_tables-expected_tables
    if missing or unexpected or source_views:
        differences=[]
        if missing:differences.append(schema_object_summary('missing tables',missing))
        if unexpected:differences.append(schema_object_summary('unexpected tables',unexpected))
        if source_views:differences.append(schema_object_summary('unexpected views',source_views))
        raise MigrationError('Source tables do not match this Mr Patchy version ('+'; '.join(differences)+'). Start the current version to upgrade missing tables first; unexpected tables/views must be reviewed separately')
    for table in meta.sorted_tables:
        if {c['name'] for c in inspector.get_columns(table.name)} != set(table.c.keys()):
            raise MigrationError('Source schema differs from this version in table ' + table.name)
    if connection.dialect.name == 'sqlite':
        if connection.exec_driver_sql('PRAGMA integrity_check').scalar() != 'ok': raise MigrationError('Source SQLite integrity check failed')
        if connection.exec_driver_sql('PRAGMA foreign_key_check').first(): raise MigrationError('Source SQLite foreign-key check failed')
    else:
        engines = connection.execute(text('SELECT ENGINE FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE()')).scalars()
        if any(engine != 'InnoDB' for engine in engines): raise MigrationError('Source MySQL tables must use InnoDB')
    jobs = meta.tables['jobs']
    if connection.scalar(select(func.count()).select_from(jobs).where(jobs.c.state == 'running')):
        raise MigrationError('Running jobs remain. Finish or reconcile interrupted operations before migrating')


def validate_destination(connection, meta):
    inspector = inspect(connection)
    names = set(inspector.get_table_names())
    if names - set(meta.tables) or inspector.get_view_names():
        raise MigrationError('Destination contains unknown tables or views; use an empty dedicated database')
    for name in names:
        if {c['name'] for c in inspector.get_columns(name)} != set(meta.tables[name].c.keys()):
            raise MigrationError('Destination schema differs from this Mr Patchy version')
        if connection.scalar(select(func.count()).select_from(meta.tables[name])):
            raise MigrationError('Destination is not empty; existing data will not be overwritten')
    if connection.dialect.name == 'mysql':
        if connection.scalar(text('SELECT COUNT(*) FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA=DATABASE()')):
            raise MigrationError('Destination triggers are not supported')
        engines = connection.execute(text('SELECT ENGINE FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE()')).scalars()
        if any(engine != 'InnoDB' for engine in engines): raise MigrationError('Destination MySQL tables must use InnoDB')


def fingerprint(connection, table):
    """Order-independent SHA-256 row multiset, bounded memory across DB collations."""
    def encode(value):
        if isinstance(value,Decimal):return {'__mrpatchy_decimal__':format(value,'f')}
        raise TypeError('Unsupported database value in migration fingerprint')
    count, total = 0, 0
    rows = connection.execution_options(stream_results=True).execute(select(table)).mappings()
    for row in rows:
        canonical = json.dumps(dict(row), sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False,default=encode)
        total = (total + int.from_bytes(hashlib.sha256(canonical.encode()).digest(), 'big')) % (1 << 256)
        count += 1
    return {'rows': count, 'fingerprint': format(total, '064x')}


def migrate(source_url, target_url, dry_run=False, progress=None):
    progress=progress or Progress()
    progress.dry_run=dry_run
    source_parsed, target_parsed = make_url(source_url), make_url(target_url)
    if source_parsed.get_backend_name() == target_parsed.get_backend_name() == 'mysql':
        if (source_parsed.host, source_parsed.port or 3306, source_parsed.database) == (target_parsed.host, target_parsed.port or 3306, target_parsed.database):
            raise MigrationError('Source and destination are the same MySQL database')
    if source_parsed.get_backend_name() == target_parsed.get_backend_name() == 'sqlite':
        if Path(source_parsed.database).resolve() == Path(target_parsed.database).resolve():
            raise MigrationError('Source and destination are the same SQLite database')
    # A dry run must not create a new SQLite file merely to inspect its destination.
    target_new = target_parsed.get_backend_name() == 'sqlite' and not Path(target_parsed.database).exists()
    progress.enter('source-connect','Connecting to source (read-only)',role='source')
    source = connect_url(source_url, source=True)
    target = connect_url(target_url)
    meta = metadata()
    try:
        with source.connect() as src:
            if src.dialect.name == 'mysql':
                src.exec_driver_sql('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ')
                src.exec_driver_sql('START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY')
            else:
                src.exec_driver_sql('BEGIN')
            progress.enter('source-validate','Validating source schema and integrity',role='source')
            validate_source(src, meta)
            expected = {}
            for table in meta.sorted_tables:
                progress.enter('source-fingerprint','Fingerprinting source table '+table.name,role='source',table=table.name)
                expected[table.name] = fingerprint(src, table)
            if not (dry_run and target_new):
                progress.enter('destination-connect','Connecting to destination',role='destination')
                with target.connect() as dst:
                    progress.enter('destination-validate','Validating destination is empty and compatible',role='destination')
                    validate_destination(dst, meta)
            else:
                progress.skipped('destination does not exist yet; it is not created by a dry run')
            if dry_run:
                progress.skipped('schema creation, copy, verification and activation')
                return expected
            progress.enter('schema-create','Creating destination schema',role='destination')
            # Only destination DDL; MySQL DDL is not transactional. A failure may
            # leave empty tables, which a later retry can reuse after inspection.
            meta.create_all(target)
            with target.begin() as dst:
                validate_destination(dst, meta)
                for table in meta.sorted_tables:
                    progress.enter('copy','Copying table '+table.name,role='destination',table=table.name)
                    rows = src.execution_options(stream_results=True).execute(select(table)).mappings()
                    for batch in rows.partitions(250):
                        dst.execute(table.insert(), [dict(row) for row in batch])
                for table in meta.sorted_tables:
                    progress.enter('verify-transaction','Verifying uncommitted table '+table.name,role='destination',table=table.name)
                    if fingerprint(dst, table) != expected[table.name]:
                        raise MigrationError('Destination content verification failed in ' + table.name)
            # Verify committed data using a fresh connection before activation.
            with target.connect() as dst:
                for table in meta.sorted_tables:
                    progress.enter('verify-committed','Verifying committed table '+table.name,role='destination',table=table.name)
                    if fingerprint(dst, table) != expected[table.name]:
                        raise MigrationError('Committed destination verification failed in ' + table.name)
            return expected
    finally:
        source.dispose()
        target.dispose()


def run(confirm_offline=False, dry_run=False, activate=False, progress=None):
    progress=progress or Progress()
    if not confirm_offline: raise MigrationError('Pass --confirm-offline after stopping ALL app/worker replicas and other database writers')
    if dry_run and activate: raise MigrationError('--dry-run cannot be combined with --activate')
    progress.enter('prepare','Taking the offline maintenance lock and reading the saved destination')
    with settings.maintenance_lock(offline=True):
        profile = settings.read_profile('target')
        if not profile: raise MigrationError('Save a migration destination in Settings → Database first')
        source_url = settings.runtime_url()
        target_url = settings.profile_url(profile)
        result = migrate(source_url, target_url, dry_run, progress)
        if activate:
            progress.enter('activate','Activating the verified destination',role='destination')
            # Single atomic switch read by BOTH web and workers at next startup.
            # Source remains available; passwords never enter command arguments.
            settings.write_profile('active', {'url': target_url})
        return {'dry_run': dry_run, 'activated': activate, 'tables': result}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--confirm-offline', action='store_true')
    parser.add_argument('--dry-run', action='store_true')
    parser.add_argument('--activate', action='store_true', help='Activate the destination only after a complete verified copy')
    parser.add_argument('--verbose', action='store_true', help='On failure also print the sanitized exception chain and stack locations (never messages or data)')
    args = parser.parse_args(argv)
    progress = Progress(sys.stderr, args.verbose)
    try:
        result = run(args.confirm_offline, args.dry_run, args.activate, progress)
    except (MigrationError, ValueError) as error:
        # Only our controlled errors; SQLAlchemy errors can include secrets/data.
        if isinstance(error, MigrationError) or type(error) is ValueError:
            print('Migration refused at stage '+(progress.stage or 'prepare')+(' ('+progress.role+')' if progress.role else '')+': ' + clean(error, 1200), file=sys.stderr)
            print(progress.destination_state()+(' Active database unchanged.' if progress.stage!='activate' else ''), file=sys.stderr)
        else: print(failure_report(error, progress), file=sys.stderr)
        return 1
    except Exception as error:
        print(failure_report(error, progress), file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    if not args.dry_run and not args.activate:
        print('Verified copy complete; active database unchanged. Do not start using both copies independently.', file=sys.stderr)
    return 0


if __name__ == '__main__':
    sys.exit(main())
