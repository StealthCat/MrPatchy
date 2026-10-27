import os
import time
from pathlib import Path
from sqlalchemy import create_engine, String, Text, JSON, Integer, Double, Boolean, event, inspect, text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

DATA = Path(os.getenv('DATA_DIR', '/data'))
DATA.mkdir(parents=True, exist_ok=True)
from .database_config import runtime_url
URL = runtime_url()
engine = create_engine(URL, pool_pre_ping=True, **({'connect_args': {'check_same_thread': False, 'timeout': 30}} if URL.startswith('sqlite') else {}))
if URL.startswith('sqlite'):
    @event.listens_for(engine, 'connect')
    def sqlite_setup(conn, _):
        conn.execute('PRAGMA journal_mode=WAL')
        conn.execute('PRAGMA foreign_keys=ON')
Session = sessionmaker(engine, expire_on_commit=False)
class Base(DeclarativeBase): pass
class Setting(Base):
    __tablename__ = 'settings'
    key: Mapped[str] = mapped_column(String(80), primary_key=True)
    value: Mapped[dict] = mapped_column(JSON)
class Host(Base):
    __tablename__ = 'hosts'
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    name: Mapped[str] = mapped_column(String(120))
    address: Mapped[str] = mapped_column(String(253))
    port: Mapped[int] = mapped_column(Integer, default=22)
    fingerprint: Mapped[str] = mapped_column(String(100))
    state: Mapped[str] = mapped_column(String(40), default='enrolling')
    error: Mapped[str] = mapped_column(Text, default='')
    repo_error: Mapped[str] = mapped_column(Text, default='')
    last_seen: Mapped[float] = mapped_column(Double, default=0)
    last_repo: Mapped[float] = mapped_column(Double, default=0)
    inventory: Mapped[dict] = mapped_column(JSON, default=dict)
    telemetry: Mapped[dict] = mapped_column(JSON, default=dict)
    baseline: Mapped[dict] = mapped_column(JSON, default=dict)
    integrity: Mapped[list] = mapped_column(JSON, default=list)
class Package(Base):
    __tablename__ = 'packages'
    id: Mapped[str] = mapped_column(String(400), primary_key=True)
    host_id: Mapped[str] = mapped_column(String(36), index=True)
    name: Mapped[str] = mapped_column(String(240))
    installed: Mapped[str] = mapped_column(String(240))
    candidate: Mapped[str] = mapped_column(String(240), default='')
    priority: Mapped[str] = mapped_column(String(20), default='normal')
    priority_manual: Mapped[bool] = mapped_column(Boolean, default=False)
    available_since: Mapped[float] = mapped_column(Double, default=0)
    held: Mapped[bool] = mapped_column(Boolean, default=False)
    dpkg_state: Mapped[str] = mapped_column(String(80), default='install ok installed')
    origin: Mapped[str] = mapped_column(Text, default='')
class Behavior(Base):
    __tablename__ = 'behaviors'
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    host_id: Mapped[str] = mapped_column(String(36), index=True)
    evidence: Mapped[dict] = mapped_column(JSON)
    verdict: Mapped[str] = mapped_column(String(30), default='pending')
    analysis: Mapped[str] = mapped_column(Text, default='Awaiting investigation')
    approved: Mapped[bool] = mapped_column(Boolean, default=False)
    first_seen: Mapped[float] = mapped_column(Double, default=time.time)
    last_seen: Mapped[float] = mapped_column(Double, default=time.time)
    attempted: Mapped[float] = mapped_column(Double, default=0)
class Job(Base):
    __tablename__ = 'jobs'
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    host_id: Mapped[str] = mapped_column(String(36), default='')
    action: Mapped[str] = mapped_column(String(80))
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    state: Mapped[str] = mapped_column(String(30), default='queued')
    output: Mapped[str] = mapped_column(Text, default='')
    created: Mapped[float] = mapped_column(Double, default=time.time)
class Audit(Base):
    __tablename__ = 'audit'
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    created: Mapped[float] = mapped_column(Double, default=time.time)
    action: Mapped[str] = mapped_column(String(120))
    detail: Mapped[str] = mapped_column(Text)
class InventoryRevision(Base):
    __tablename__ = 'inventory_revisions'
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    host_id: Mapped[str] = mapped_column(String(36), index=True)
    created: Mapped[float] = mapped_column(Double, default=time.time)
    inventory: Mapped[dict] = mapped_column(JSON)
class Observation(Base):
    __tablename__ = 'observations'
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    host_id: Mapped[str] = mapped_column(String(36), index=True)
    observed: Mapped[float] = mapped_column(Double)
    received: Mapped[float] = mapped_column(Double, default=time.time)
    evidence: Mapped[dict] = mapped_column(JSON)
DEFAULTS = {'repo_minutes': 60, 'deadlines': {'critical': 24, 'high': 72, 'normal': 168, 'low': 720}, 'ai_enabled': False, 'ai_model': '', 'ai_hourly_limit': 20, 'ai_updates_enabled': True, 'ai_update_hourly_limit': 20, 'history_days': 30}
def config(s):
    item = s.get(Setting, 'config')
    return {**DEFAULTS, **(item.value if item else {})}
def audit(s, action, detail): s.add(Audit(action=action, detail=detail))
def init():
    from . import evidence_vault,quarantine,response_monitor
    Base.metadata.create_all(engine)
    columns={c['name'] for c in inspect(engine).get_columns('packages')}
    if 'dpkg_state' not in columns:
        with engine.begin() as connection:
            connection.execute(text("ALTER TABLE packages ADD COLUMN dpkg_state VARCHAR(80) NOT NULL DEFAULT 'install ok installed'"))
    # MySQL FLOAT is single precision: epoch seconds lose tens of seconds.
    # SQLite already stores these values as 64-bit REAL. This migration is
    # idempotent and runs before workers start, with only one app replica.
    if engine.dialect.name in ('mysql', 'mariadb'):
        from sqlalchemy.dialects.mysql import FLOAT
        inspector = inspect(engine)
        with engine.begin() as connection:
            for model in (Host, Package, Behavior, Job, Audit):
                for column in inspector.get_columns(model.__tablename__):
                    if isinstance(column['type'], FLOAT):
                        table_name = model.__tablename__
                        column_name = column['name']
                        connection.execute(text(f'ALTER TABLE `{table_name}` MODIFY COLUMN `{column_name}` DOUBLE NOT NULL'))

