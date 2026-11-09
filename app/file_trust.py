"""Durable, controller-derived file authenticity decisions, never behavior approval."""
import hashlib
import json
import time

from sqlalchemy import String, Text, Double, JSON, Index, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Mapped, mapped_column
from .db import Base, audit


class Trust(Base):
    __tablename__ = 'file_trust_observations'
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    host_id: Mapped[str] = mapped_column(String(36), index=True)
    path: Mapped[str] = mapped_column(Text)
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    source: Mapped[str] = mapped_column(String(40))
    reference: Mapped[dict] = mapped_column(JSON)
    # Exact path identity independent of database collation (MySQL Text
    # comparisons are case-insensitive by default; POSIX paths are not).
    path_sha256: Mapped[str] = mapped_column(String(64), default='')
    created: Mapped[float] = mapped_column(Double, default=time.time)
    __table_args__ = (Index('ix_file_trust_lookup', 'sha256', 'path_sha256', 'source'),)


def path_identity(path):
    return hashlib.sha256(path.encode('utf-8', 'surrogateescape')).hexdigest()


def identity(host_id, path, checksum, source, reference):
    return hashlib.sha256(json.dumps([host_id, path, checksum, source, reference],
        sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def retain(s, host_id, path, checksum, source, reference):
    """Internal only: callers supply validated controller provenance."""
    key = identity(host_id, path, checksum, source, reference)
    row = s.get(Trust, key)
    if row is None:
        try:
            with s.begin_nested():
                row = Trust(id=key, host_id=host_id, path=path, path_sha256=path_identity(path),
                            sha256=checksum, source=source, reference=reference)
                s.add(row)
                s.flush()
                audit(s, 'automatically trust file', host_id+' '+key+' '+source)
        except IntegrityError:
            # A concurrent writer committed the same observation. Under MySQL
            # REPEATABLE READ a plain read still uses this transaction's older
            # snapshot, so resolve the winner with a locking (current) read.
            row = s.get(Trust, key, with_for_update={'read': True}, populate_existing=True)
            if row is None:
                raise
    return row


def previous(s, path, checksum):
    """Reuse repository-rooted observations only while their origin still matches.

    Contextual AI candidates are deliberately handled by known_good.lookup, not
    this byte lookup. No chains of trust or target-supplied assertions are used.
    """
    from .file_status import repositories, resolve
    roots, seen = {}, set()
    # Bind exact path identity in SQL so unrelated paths sharing these bytes can
    # never crowd the requested path out; recheck the exact text in Python.
    query = select(Trust).where(Trust.sha256 == checksum, Trust.path_sha256 == path_identity(path),
            Trust.source == 'authenticated_repository').order_by(Trust.created.desc(), Trust.id)
    # Buffered (not streamed): origin revalidation below issues further queries.
    for row in s.scalars(query).all():
        if row.path != path:
            continue
        if not isinstance(row.reference, dict) or not row.reference.get('host_id'):
            continue
        marker = (row.reference.get('host_id'), row.reference.get('inspection_id'))
        if marker in seen:
            continue
        seen.add(marker)
        origin = row.reference['host_id']
        if origin not in roots:
            roots[origin] = repositories(s, origin)
        match = resolve(path, checksum, roots[origin])
        if (match['status'] == 'verified' and
                match['reference']['inspection_id'] == row.reference.get('inspection_id')):
            return row.reference
    return None


def assess(s, host_id, path, checksum, proofs, *, persist=True):
    from .file_status import resolve
    if not isinstance(path, str) or not path.startswith('/') or len(path) > 4096:
        return {'status': 'unavailable', 'method': 'none', 'reason': 'No valid file path recorded.'}
    result = resolve(path, checksum, proofs)
    reference = None
    if result['status'] == 'verified':
        proof = result['reference']
        if proof.get('finding'):
            # The newest authenticated receipt reported different (or missing)
            # bytes at this path. Target-reported observation times are on the
            # target's clock and cannot be ordered against the controller's
            # receipt, so no telemetry observation may restore trust. Only a
            # newer authenticated matching inspection can.
            result['reason'] += (' Not trusted: the newest authenticated receipt reported different '
                                 'bytes at this path.')
            return result
        reference = {'host_id': host_id, 'inspection_id': proof['inspection_id']}
    elif result['status'] == 'unassessed':
        reference = previous(s, path, checksum)
        if reference:
            result.update(status='known_good', method='known_good_database',
                          reason='Exact bytes match a previously authenticated file observation.')
    if reference:
        row = (retain(s, host_id, path, checksum, 'authenticated_repository', reference) if persist else
               s.get(Trust, identity(host_id, path, checksum, 'authenticated_repository', reference)))
        if row and row.reference == reference:
            result.update(trusted=True, trust_id=row.id, trust_source=row.source,
                          reason='Automatically trusted and stored. '+result['reason'])
    return result


def record_snapshot(s, host):
    from .file_status import repositories
    proofs = repositories(s, host.id)
    telemetry = host.telemetry or {}
    for path, checksum in telemetry.get('managed', {}).items():
        assess(s, host.id, path, checksum, proofs)
    for process in telemetry.get('processes', []):
        assess(s, host.id, process.get('executable'), process.get('sha256'), proofs)


def record_reuse(s, behavior, assessment, hit):
    retain(s, behavior.host_id, behavior.evidence['executable'], behavior.evidence['sha256'],
           'known_good_database', {'assessment_id': assessment.id, 'fingerprint': hit['fingerprint']})
