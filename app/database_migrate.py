"""Offline, verified database copy. Never deletes source data or overwrites destination rows."""
import argparse
import hashlib
import importlib
import json
from pathlib import Path
import sys

from sqlalchemy import create_engine, inspect, select, func, text
from sqlalchemy.engine import URL, make_url
from sqlalchemy.pool import NullPool

from . import database_config as settings


class MigrationError(ValueError):
    pass


def metadata():
    # Register every durable model, without importing main or starting workers.
    for name in ('identity', 'operations', 'releases', 'scheduling', 'ai_runs', 'update_scores', 'package_history', 'incidents', 'evidence_vault', 'quarantine', 'response_monitor'):
        importlib.import_module('app.' + name)
    from .db import Base
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
    if set(inspector.get_table_names()) != set(meta.tables) or inspector.get_view_names():
        raise MigrationError('Source tables do not match this Mr Patchy version. Start the current version to upgrade its schema first; unknown tables/views must be reviewed separately')
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
    count, total = 0, 0
    rows = connection.execution_options(stream_results=True).execute(select(table)).mappings()
    for row in rows:
        canonical = json.dumps(dict(row), sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False)
        total = (total + int.from_bytes(hashlib.sha256(canonical.encode()).digest(), 'big')) % (1 << 256)
        count += 1
    return {'rows': count, 'fingerprint': format(total, '064x')}


def migrate(source_url, target_url, dry_run=False):
    source_parsed, target_parsed = make_url(source_url), make_url(target_url)
    if source_parsed.get_backend_name() == target_parsed.get_backend_name() == 'mysql':
        if (source_parsed.host, source_parsed.port or 3306, source_parsed.database) == (target_parsed.host, target_parsed.port or 3306, target_parsed.database):
            raise MigrationError('Source and destination are the same MySQL database')
    if source_parsed.get_backend_name() == target_parsed.get_backend_name() == 'sqlite':
        if Path(source_parsed.database).resolve() == Path(target_parsed.database).resolve():
            raise MigrationError('Source and destination are the same SQLite database')
    # A dry run must not create a new SQLite file merely to inspect its destination.
    target_new = target_parsed.get_backend_name() == 'sqlite' and not Path(target_parsed.database).exists()
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
            validate_source(src, meta)
            expected = {table.name: fingerprint(src, table) for table in meta.sorted_tables}
            if not (dry_run and target_new):
                with target.connect() as dst:
                    validate_destination(dst, meta)
            if dry_run: return expected
            # Only destination DDL; MySQL DDL is not transactional. A failure may
            # leave empty tables, which a later retry can reuse after inspection.
            meta.create_all(target)
            with target.begin() as dst:
                validate_destination(dst, meta)
                for table in meta.sorted_tables:
                    rows = src.execution_options(stream_results=True).execute(select(table)).mappings()
                    for batch in rows.partitions(250):
                        dst.execute(table.insert(), [dict(row) for row in batch])
                for table in meta.sorted_tables:
                    if fingerprint(dst, table) != expected[table.name]:
                        raise MigrationError('Destination content verification failed in ' + table.name)
            # Verify committed data using a fresh connection before activation.
            with target.connect() as dst:
                for table in meta.sorted_tables:
                    if fingerprint(dst, table) != expected[table.name]:
                        raise MigrationError('Committed destination verification failed in ' + table.name)
            return expected
    finally:
        source.dispose()
        target.dispose()


def run(confirm_offline=False, dry_run=False, activate=False):
    if not confirm_offline: raise MigrationError('Pass --confirm-offline after stopping ALL app/worker replicas and other database writers')
    if dry_run and activate: raise MigrationError('--dry-run cannot be combined with --activate')
    with settings.maintenance_lock(offline=True):
        profile = settings.read_profile('target')
        if not profile: raise MigrationError('Save a migration destination in Settings → Database first')
        source_url = settings.runtime_url()
        target_url = settings.profile_url(profile)
        result = migrate(source_url, target_url, dry_run)
        if activate:
            # Single atomic switch read by BOTH web and workers at next startup.
            # Source remains available; passwords never enter command arguments.
            settings.write_profile('active', {'url': target_url})
        return {'dry_run': dry_run, 'activated': activate, 'tables': result}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--confirm-offline', action='store_true')
    parser.add_argument('--dry-run', action='store_true')
    parser.add_argument('--activate', action='store_true', help='Activate the destination only after a complete verified copy')
    args = parser.parse_args()
    try:
        result = run(**vars(args))
    except (MigrationError, ValueError) as error:
        # Only our controlled errors; SQLAlchemy errors can include secrets/data.
        if isinstance(error, MigrationError) or type(error) is ValueError:
            print('Migration refused: ' + str(error), file=sys.stderr)
        else: print('Migration failed. Active database unchanged; inspect destination before retrying.', file=sys.stderr)
        return 1
    except Exception:
        print('Migration failed. Active database unchanged. Check database access, TLS, schema and free space; inspect destination before retrying. No credentials or database rows were logged.', file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    if not args.dry_run and not args.activate:
        print('Verified copy complete; active database unchanged. Do not start using both copies independently.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
