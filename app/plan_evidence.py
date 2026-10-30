"""Opt-in bounded historical context for advisory scanner plans; never action authority."""
import json
from . import security_correlation

MAX_BYTES=65536


def capture(s,incident,as_of=None):
    snapshot=security_correlation.page(s,incident,as_of=as_of)
    if len(json.dumps(snapshot,ensure_ascii=True).encode())>MAX_BYTES:
        raise ValueError('Related AI evidence exceeds 64 KiB; use a scanner-only plan or review related evidence manually')
    return snapshot


def evidence(s,incident,scope=None):
    result={'incident_id':incident.id,'scan_id':incident.scan_id,'finding':incident.evidence}
    if scope is not None:
        if scope.get('version')!=1 or scope.get('host_id')!=incident.host_id:
            raise ValueError('Unsupported related AI evidence scope')
        result.update(host_id=incident.host_id,incident_updated=incident.updated,incident_state=incident.state,
            related=capture(s,incident,scope['snapshot']['as_of']))
    return result
