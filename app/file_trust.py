"""Durable, controller-derived file authenticity decisions, never behavior approval."""
import hashlib
import json
import time

from sqlalchemy import String, Text, Double, JSON, select
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
    created: Mapped[float] = mapped_column(Double, default=time.time)


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
                row = Trust(id=key, host_id=host_id, path=path, sha256=checksum,
                            source=source, reference=reference)
                s.add(row)
                s.flush()
                audit(s, 'automatically trust file', host_id+' '+key+' '+source)
        except IntegrityError:
            row = s.get(Trust, key)
            if row is None:
                raise
    return row


def previous(s, path, checksum):
    """Reuse repository-rooted observations only while their origin still matches.

    Contextual AI candidates are deliberately handled by known_good.lookup, not
    this byte lookup. No chains of trust or target-supplied assertions are used.
    """
    from .file_status import repositories, resolve
    roots = {}
    for row in s.scalars(select(Trust).where(Trust.sha256 == checksum,
            Trust.source == 'authenticated_repository').order_by(Trust.created.desc()).limit(100)):
        if row.path != path:
            continue
        if not isinstance(row.reference, dict) or not row.reference.get('host_id'):
            continue
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
        reference = {'host_id': host_id, 'inspection_id': result['reference']['inspection_id']}
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
