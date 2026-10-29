"""Bounded, metadata-only response exports. Caller holds the host operation lock."""
import hashlib
import json
import time
import uuid
from sqlalchemy import select
from . import incidents, quarantine, response_monitor, response_processes
from . import process_response, repair_preparation, repair_staging, repair_publication, response_health, service_monitor
from .evidence_vault import EvidenceCopy, EvidenceArchive, ArchiveObservation

MAX_ROWS = 5000
MAX_SECTION_ROWS = 1000
MAX_BYTES = 16 * 1024 * 1024
MAX_SECONDS = 30

# Deliberate field allowlists: adding a model column must not expand an export.
FIELDS = {
    'response': 'id host_id incident_id archive_id created state hold fingerprint evidence_digest plan receipt observed approval_id',
    'incident': 'id host_id state created updated scan_id evidence',
    'incident_events': 'id incident_id created actor kind details',
    'advisory_plans': 'id incident_id created run_id state evidence_digest content approved_by expires',
    'preservation': 'id host_id incident_id created state evidence_digest snapshot receipt actor reason expires',
    'acquisition': 'id host_id copy_id created state snapshot fingerprint actor reason expires',
    'acquisition_observations': 'id archive_id host_id created job_id state actor',
    'file_approvals': 'id quarantine_id action created expires plan_digest actor reason before_state before_hold',
    'file_events': 'id quarantine_id created kind actor details',
    'monitor_checks': 'id host_id quarantine_id created state report',
    'process_observations': 'id host_id quarantine_id created actor state report',
    'process_responses': 'id host_id quarantine_id observation_id created state hold fingerprint plan receipt observed approval_id',
    'process_approvals': 'id process_id action created expires plan_digest actor reason before_state before_hold',
    'process_events': 'id process_id created kind actor details',
    'repair_preparations': 'id host_id quarantine_id bundle_id path actor created finished state fingerprint response_plan_digest report',
    'repair_stages': 'id host_id quarantine_id preparation_id preparation_digest created expires actor reason fingerprint plan state observed report',
    'stage_events': 'id stage_id host_id created actor kind report',
    'repair_publications': 'id host_id quarantine_id stage_id created expires actor reason fingerprint stage_report_digest plan state hold before_state before_hold observed receipt report',
    'publication_events': 'id publication_id host_id created actor kind details',
    'service_observations': 'id host_id quarantine_id created actor reason state report',
    'service_watch': 'id host_id created updated actor reason revision enabled interval_minutes pause_on_problem baseline_id baseline_digest units binding hold last_attempt last_observation_id last_state last_observed',
}


class ExportLimit(ValueError):
    pass


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('ascii')


def sha256(value):
    return hashlib.sha256(canonical(value)).hexdigest()


class Builder:
    def __init__(self, fields=None):
        self.fields = FIELDS if fields is None else fields
        self.sections = {}
        self.rows = 0
        self.bytes = 0
        self.deadline = time.monotonic() + MAX_SECONDS

    def check(self):
        if time.monotonic() > self.deadline:
            raise ExportLimit('Response record exceeded its time budget; no partial export was created')

    def add(self, name, rows):
        fields = self.fields[name].split()
        values = []
        for row in rows:
            self.check()
            self.rows += 1
            if len(values) >= MAX_SECTION_ROWS or self.rows > MAX_ROWS:
                raise ExportLimit('Response history exceeds the export row limit; no partial export was created')
            value = {field: getattr(row, field) for field in fields}
            self.bytes += len(canonical(value))
            if self.bytes > MAX_BYTES:
                raise ExportLimit('Response record exceeds the 16 MiB export limit; no partial export was created')
            values.append(value)
        self.sections[name] = values

    def query(self, s, name, model, *conditions):
        # Stream individual bounded rows; do not materialize an unbounded history.
        rows = s.scalars(select(model).where(*conditions).order_by(model.created, model.id)
                         .limit(MAX_SECTION_ROWS + 1).execution_options(yield_per=1))
        try:
            self.add(name, rows)
        finally:
            rows.close()


def build(s, host, response, actor, reason):
    """Only stored metadata: never SSH, artifact access, file reads or AI calls."""
    if response.host_id != host.id:
        raise ValueError('Response does not belong to the selected host')
    b = Builder()
    missing = []
    b.add('response', [response])
    watch=s.get(service_monitor.Watch,response.id)
    b.add('service_watch',[watch] if watch and watch.host_id==host.id else [])
    incident = s.get(incidents.Incident, response.incident_id)
    if not incident or incident.host_id != host.id:
        incident = None
        missing.append('incident')
    b.add('incident', [incident] if incident else [])
    for name, model in (('incident_events', incidents.IncidentEvent), ('advisory_plans', incidents.Plan)):
        if incident:
            b.query(s, name, model, model.incident_id == incident.id)
        else:
            b.add(name, [])
    archive = s.get(EvidenceArchive, response.archive_id)
    if not archive or archive.host_id != host.id:
        archive = None
        missing.append('acquisition')
    b.add('acquisition', [archive] if archive else [])
    copy = s.get(EvidenceCopy, archive.copy_id) if archive else None
    if not copy or copy.host_id != host.id or copy.incident_id != response.incident_id:
        copy = None
        missing.append('preservation')
    b.add('preservation', [copy] if copy else [])
    b.query(s, 'acquisition_observations', ArchiveObservation,
            ArchiveObservation.host_id == host.id, ArchiveObservation.archive_id == (archive.id if archive else None))
    for name, model in (('file_approvals', quarantine.Approval), ('file_events', quarantine.Event),
                        ('monitor_checks', response_monitor.Check), ('process_observations', response_processes.Observation),
                        ('process_responses', process_response.ProcessResponse), ('repair_preparations', repair_preparation.Preparation),
                        ('repair_stages', repair_staging.Stage), ('repair_publications', repair_publication.Publication),
                        ('service_observations', response_health.Observation)):
        conditions = [model.quarantine_id == response.id]
        if hasattr(model, 'host_id'):
            conditions.append(model.host_id == host.id)
        b.query(s, name, model, *conditions)
    for name, model, parent, foreign in (
        ('process_approvals', process_response.Approval, process_response.ProcessResponse, 'process_id'),
        ('process_events', process_response.Event, process_response.ProcessResponse, 'process_id'),
        ('stage_events', repair_staging.Event, repair_staging.Stage, 'stage_id'),
        ('publication_events', repair_publication.Event, repair_publication.Publication, 'publication_id'),
    ):
        parents = select(parent.id).where(parent.host_id == host.id, parent.quarantine_id == response.id)
        conditions = [getattr(model, foreign).in_(parents)]
        if hasattr(model, 'host_id'):
            conditions.append(model.host_id == host.id)
        b.query(s, name, model, *conditions)
    # Read only these policy fields, never arbitrary settings or host credentials.
    policy = response_monitor.policy(s, host.id)
    watch = response_monitor.watch(s, response)
    record = {
        'format': 'mrpatchy-response-record', 'version': 3,
        'export': {'id': str(uuid.uuid4()), 'created': time.time(), 'actor': actor, 'reason': reason},
        'host': {'id': host.id, 'name': host.name, 'fingerprint': host.fingerprint},
        'scope': {'quarantine_id': response.id, 'plan_digest': incidents.digest(response.plan),
                  'missing_references': missing, 'primary_references_complete': not missing,
                  'history_truncated': False,
                  'source': 'controller_database_under_host_operation_lock',
                  'excludes': ['file_bytes', 'target_journal_files', 'full_scan_reports', 'job_payloads_and_outputs',
                               'credential_configuration', 'other_file_responses', 'live_host_verification'],
                  'limits': {'section_rows': MAX_SECTION_ROWS, 'total_rows': MAX_ROWS, 'bytes': MAX_BYTES}},
        'monitoring': {'policy': {key: policy[key] for key in ('enabled', 'interval_minutes', 'pause_on_problem', 'revision')},
                       'watch': {key: watch[key] for key in ('enabled', 'revision')}},
        'sections': b.sections,
    }
    integrity = {'algorithm': 'sha256', 'canonicalization': 'python-json-sort-keys-ascii-compact-v1',
                 'record_sha256': sha256(record),
                 'sections': {name: {'sha256': sha256(rows), 'records': len(rows), 'bytes': len(canonical(rows))}
                              for name, rows in b.sections.items()},
                 'meaning': 'Integrity hashes detect changes against a separately trusted digest; they do not authenticate the controller or prove historical completeness.'}
    data = canonical({'record': record, 'integrity': integrity}) + b'\n'
    b.check()
    if len(data) > MAX_BYTES:
        raise ExportLimit('Response record exceeds the 16 MiB export limit; no partial export was created')
    return record['export']['id'], data, hashlib.sha256(data).hexdigest()
