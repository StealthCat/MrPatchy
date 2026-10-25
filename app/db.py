import os
import time
from pathlib import Path
from sqlalchemy import create_engine, String, Text, JSON, Integer, Float, Boolean, event
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

DATA = Path(os.getenv('DATA_DIR', '/data'))
DATA.mkdir(parents=True, exist_ok=True)
URL = os.getenv('DATABASE_URL', f'sqlite:///{DATA}/mrpatchy.db')
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
    last_seen: Mapped[float] = mapped_column(Float, default=0)
    last_repo: Mapped[float] = mapped_column(Float, default=0)
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
    available_since: Mapped[float] = mapped_column(Float, default=0)
    held: Mapped[bool] = mapped_column(Boolean, default=False)
    origin: Mapped[str] = mapped_column(Text, default='')
class Behavior(Base):
    __tablename__ = 'behaviors'
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    host_id: Mapped[str] = mapped_column(String(36), index=True)
    evidence: Mapped[dict] = mapped_column(JSON)
    verdict: Mapped[str] = mapped_column(String(30), default='pending')
    analysis: Mapped[str] = mapped_column(Text, default='Awaiting investigation')
    approved: Mapped[bool] = mapped_column(Boolean, default=False)
    first_seen: Mapped[float] = mapped_column(Float, default=time.time)
    last_seen: Mapped[float] = mapped_column(Float, default=time.time)
    attempted: Mapped[float] = mapped_column(Float, default=0)
class Job(Base):
    __tablename__ = 'jobs'
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    host_id: Mapped[str] = mapped_column(String(36), default='')
    action: Mapped[str] = mapped_column(String(80))
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    state: Mapped[str] = mapped_column(String(30), default='queued')
    output: Mapped[str] = mapped_column(Text, default='')
    created: Mapped[float] = mapped_column(Float, default=time.time)
class Audit(Base):
    __tablename__ = 'audit'
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    created: Mapped[float] = mapped_column(Float, default=time.time)
    action: Mapped[str] = mapped_column(String(120))
    detail: Mapped[str] = mapped_column(Text)
DEFAULTS = {'repo_minutes': 60, 'deadlines': {'critical': 24, 'high': 72, 'normal': 168, 'low': 720}, 'ai_enabled': False, 'ai_model': '', 'ai_hourly_limit': 20}
def config(s):
    item = s.get(Setting, 'config')
    return {**DEFAULTS, **(item.value if item else {})}
def audit(s, action, detail): s.add(Audit(action=action, detail=detail))
def init(): Base.metadata.create_all(engine)
