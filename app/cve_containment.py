"""Pure CVE-exploitation automatic-containment eligibility contract (roadmap D, #725).

This module decides, without I/O, whether one CVE-specific exploitation detection
may trigger automatic file quarantine and/or verified process termination under
an administrator-defined per-CVE policy. Advisory ingestion, exploitation
detectors, stored policies, executors, alerts and UI are later milestones;
nothing here contacts a server, a provider or the database.

Safety properties:

* Only an authenticated, fresh, CVE-specific detection rule that matched the
  exact detected artifact hash can establish exploitation. The rule must name
  the same CVE as the detection, and its confidence must meet the policy.
* The endpoint must be ``affected`` by that CVE according to an applicability
  assessment bound to the same server and CVE (``uncertain`` only when the
  policy explicitly opts in). Applicability is a precondition, never evidence of
  exploitation: a vulnerable version, an advisory match or a CVSS score alone
  authorizes nothing.
* At least ``min_supporting_kinds`` distinct supporting observations bound to
  the same server, evidence revision and artifact are required. Observations
  bound elsewhere are ignored and reported as coverage gaps.
* AI output is never authoritative. Any supplied AI enrichment is ignored for
  the decision and reported as such, so evaluation does not depend on AI
  availability or per-server AI pause.
* Quarantine and termination reuse the malware contract's (#682) hash-bound
  identity checks, exclusions, pseudo-filesystem refusal, effect statements and
  ``still_bound`` recheck. Anything malformed fails closed.
"""
import hashlib
import json
import re

from . import malware_response as _mr
from .cve_exposure import AFFECTED, FIXED, UNAFFECTED, UNCERTAIN

CONTRACT_VERSION = 1
MODES = _mr.MODES
ACTIONS = _mr.ACTIONS
EFFECTS = _mr.EFFECTS
Invalid = _mr.Invalid
still_bound = _mr.still_bound

RULE_CONFIDENCES = ('low', 'medium', 'high')
MIN_RULE_CONFIDENCE_FLOOR = 'medium'
APPLICABILITY_STATUSES = (AFFECTED, FIXED, UNAFFECTED, UNCERTAIN)
SUPPORTING_KINDS = ('execution', 'process', 'file_change', 'integrity_mismatch', 'service', 'network', 'log')
MIN_SUPPORTING_FLOOR = 1
MAX_RULE_AGE_LIMIT = 30 * 86400
MAX_POLICY_CVES = 256
_CVE = re.compile(r'CVE-\d{4}-\d{4,7}')
_MAX_LIST = 256


def _cve(value):
    return isinstance(value, str) and bool(_CVE.fullmatch(value))


def _sha(value):
    return isinstance(value, str) and bool(_mr._SHA256.fullmatch(value))


def _time(value):
    return _mr._num(value) and value >= 0


def normalize_policy(policy):
    """Validate an administrator per-CVE policy; raise ``Invalid`` on any defect."""
    if not isinstance(policy, dict):
        raise Invalid('policy must be an object')
    allowed = {'mode', 'cve_ids', 'actions', 'min_rule_confidence', 'min_supporting_kinds',
               'max_rule_age_seconds', 'allow_uncertain_applicability', 'excluded_paths', 'excluded_sha256'}
    if set(policy) - allowed:
        raise Invalid('unsupported policy fields')
    mode = policy.get('mode', 'disabled')
    if mode not in MODES:
        raise Invalid('unsupported policy mode')
    cves = policy.get('cve_ids', [])
    if not isinstance(cves, list) or len(cves) > MAX_POLICY_CVES or any(not _cve(c) for c in cves):
        raise Invalid('invalid cve_ids')
    actions = policy.get('actions', [])
    if not isinstance(actions, list) or any(a not in ACTIONS for a in actions) or len(set(actions)) != len(actions):
        raise Invalid('invalid actions')
    confidence = policy.get('min_rule_confidence', 'high')
    if confidence not in RULE_CONFIDENCES or \
            RULE_CONFIDENCES.index(confidence) < RULE_CONFIDENCES.index(MIN_RULE_CONFIDENCE_FLOOR):
        raise Invalid('min_rule_confidence out of range')
    supporting = policy.get('min_supporting_kinds', MIN_SUPPORTING_FLOOR)
    if not _mr._int(supporting, MIN_SUPPORTING_FLOOR, len(SUPPORTING_KINDS)):
        raise Invalid('min_supporting_kinds out of range')
    age = policy.get('max_rule_age_seconds', 7 * 86400)
    if not _mr._int(age, 1, MAX_RULE_AGE_LIMIT):
        raise Invalid('max_rule_age_seconds out of range')
    uncertain = policy.get('allow_uncertain_applicability', False)
    if type(uncertain) is not bool:
        raise Invalid('allow_uncertain_applicability must be boolean')
    paths = policy.get('excluded_paths', [])
    hashes = policy.get('excluded_sha256', [])
    if not isinstance(paths, list) or len(paths) > _MAX_LIST or not isinstance(hashes, list) or len(hashes) > _MAX_LIST:
        raise Invalid('invalid exclusions')
    if any(not _sha(h) for h in hashes):
        raise Invalid('invalid excluded hash')
    return {
        'mode': mode, 'cve_ids': frozenset(cves), 'actions': tuple(a for a in ACTIONS if a in actions),
        'min_rule_confidence': confidence, 'min_supporting_kinds': supporting, 'max_rule_age_seconds': age,
        'allow_uncertain_applicability': uncertain,
        'excluded_paths': tuple(sorted({_mr._path(p) for p in paths})), 'excluded_sha256': frozenset(hashes),
    }


def normalize_detection(detection):
    """Validate one CVE exploitation detection; raise ``Invalid`` on any defect."""
    if not isinstance(detection, dict):
        raise Invalid('detection must be an object')
    required = {'server_id', 'evidence_revision', 'observed_at', 'cve_id', 'artifact_sha256', 'rule',
                'applicability'}
    allowed = required | {'supporting', 'file', 'process', 'ai'}
    if not required <= set(detection) or set(detection) - allowed:
        raise Invalid('unsupported detection fields')
    if not _mr._token(detection['server_id']) or not _mr._token(detection['evidence_revision']):
        raise Invalid('invalid server or evidence binding')
    if not _time(detection['observed_at']):
        raise Invalid('invalid observation time')
    if not _cve(detection['cve_id']):
        raise Invalid('invalid CVE identifier')
    if not _sha(detection['artifact_sha256']):
        raise Invalid('invalid artifact hash')
    out = {k: detection[k] for k in required - {'rule', 'applicability'}}
    out['observed_at'] = float(detection['observed_at'])
    out['file'] = _mr._file(detection.get('file'))
    out['process'] = _mr._process(detection.get('process'))
    rule = detection['rule']
    if not isinstance(rule, dict) or set(rule) != {'rule_id', 'rule_version', 'cve_id', 'authenticated', 'updated_at',
                                                   'confidence', 'matched_sha256'}:
        raise Invalid('incomplete detection-rule provenance')
    if not _mr._token(rule['rule_id']) or not _mr._token(rule['rule_version']) or not _cve(rule['cve_id']):
        raise Invalid('invalid detection rule identity')
    if type(rule['authenticated']) is not bool or not _time(rule['updated_at']):
        raise Invalid('invalid detection-rule provenance')
    if rule['confidence'] not in RULE_CONFIDENCES or not _sha(rule['matched_sha256']):
        raise Invalid('invalid detection-rule match')
    out['rule'] = dict(rule)
    applicability = detection['applicability']
    if not isinstance(applicability, dict) or set(applicability) != {'status', 'server_id', 'cve_id', 'assessed_at'}:
        raise Invalid('incomplete applicability assessment')
    if applicability['status'] not in APPLICABILITY_STATUSES or not _mr._token(applicability['server_id']) \
            or not _cve(applicability['cve_id']) or not _time(applicability['assessed_at']):
        raise Invalid('invalid applicability assessment')
    out['applicability'] = dict(applicability)
    supporting = detection.get('supporting', [])
    if not isinstance(supporting, list) or len(supporting) > _MAX_LIST:
        raise Invalid('invalid supporting evidence')
    items = []
    for item in supporting:
        if not isinstance(item, dict) or set(item) != {'kind', 'event_id', 'server_id', 'evidence_revision',
                                                       'artifact_sha256', 'observed_at'}:
            raise Invalid('invalid supporting evidence item')
        if item['kind'] not in SUPPORTING_KINDS or not _mr._token(item['event_id']) \
                or not _mr._token(item['server_id']) or not _mr._token(item['evidence_revision']):
            raise Invalid('invalid supporting evidence item')
        if not _sha(item['artifact_sha256']) or not _time(item['observed_at']):
            raise Invalid('invalid supporting evidence binding')
        items.append(dict(item))
    out['supporting'] = items
    # AI enrichment is accepted only so that it can be explicitly ignored.
    ai = detection.get('ai')
    if ai is not None and not isinstance(ai, dict):
        raise Invalid('invalid AI enrichment')
    out['ai_supplied'] = ai is not None
    return out


def binding_digest(detection):
    """Stable digest of the identities an authorization is bound to."""
    return _digest(normalize_detection(detection))


def _digest(d):
    subject = {
        'contract': 'cve_containment', 'version': CONTRACT_VERSION, 'server_id': d['server_id'],
        'evidence_revision': d['evidence_revision'], 'cve_id': d['cve_id'], 'artifact_sha256': d['artifact_sha256'],
        'file': d['file'], 'process': d['process'], 'rule': (d['rule']['rule_id'], d['rule']['rule_version']),
    }
    return hashlib.sha256(json.dumps(subject, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def _classify(d, p, now, reasons, gaps):
    if d['observed_at'] > now:
        reasons.append('observation_in_future')
        return 'invalid'
    if d['cve_id'] not in p['cve_ids']:
        reasons.append('cve_not_in_policy')
        return 'not_in_policy'
    rule = d['rule']
    if not rule['authenticated']:
        reasons.append('rule_unauthenticated')
        return 'unverified_rule'
    if rule['updated_at'] > now or now - rule['updated_at'] > p['max_rule_age_seconds']:
        reasons.append('rule_stale')
        return 'unverified_rule'
    if rule['cve_id'] != d['cve_id']:
        reasons.append('rule_not_bound_to_cve')
        return 'unverified_rule'
    if rule['matched_sha256'] != d['artifact_sha256']:
        reasons.append('rule_not_bound_to_artifact')
        return 'unverified_rule'
    applicability = d['applicability']
    if applicability['server_id'] != d['server_id'] or applicability['cve_id'] != d['cve_id']:
        reasons.append('applicability_not_bound')
        return 'unverified_applicability'
    if applicability['assessed_at'] > now:
        reasons.append('applicability_in_future')
        return 'unverified_applicability'
    if applicability['status'] in (FIXED, UNAFFECTED):
        reasons.append(f"endpoint_{applicability['status']}")
        gaps.append('artifact_left_to_malware_policy')
        return 'not_exposed'
    if applicability['status'] == UNCERTAIN:
        gaps.append('applicability_uncertain')
        if not p['allow_uncertain_applicability']:
            reasons.append('uncertain_applicability_not_allowed')
            return 'unverified_applicability'
    kinds = set()
    for item in d['supporting']:
        if item['server_id'] != d['server_id'] or item['artifact_sha256'] != d['artifact_sha256']:
            if 'unbound_supporting_evidence_ignored' not in gaps:
                gaps.append('unbound_supporting_evidence_ignored')
        elif item['evidence_revision'] != d['evidence_revision']:
            if 'stale_supporting_evidence_ignored' not in gaps:
                gaps.append('stale_supporting_evidence_ignored')
        elif item['observed_at'] > now:
            if 'future_supporting_evidence_ignored' not in gaps:
                gaps.append('future_supporting_evidence_ignored')
        else:
            kinds.add(item['kind'])
    if RULE_CONFIDENCES.index(rule['confidence']) < RULE_CONFIDENCES.index(p['min_rule_confidence']):
        reasons.append('rule_confidence_below_policy')
        return 'suspected_exploitation'
    if len(kinds) < p['min_supporting_kinds']:
        reasons.append('insufficient_supporting_evidence')
        return 'suspected_exploitation'
    return 'confirmed_exploitation'


def evaluate(policy, detection, *, now):
    """Decide automatic containment for one CVE exploitation detection.

    Returns a dict with ``authorized`` actions (only in ``enforce`` mode),
    ``would_authorize`` actions (computed in every valid mode), ``withheld``
    actions with reasons, ``reasons``, ``coverage_gaps`` and a ``binding``
    digest. Executors must call :func:`still_bound` immediately before acting.
    The decision never depends on AI availability.
    """
    result = {'version': CONTRACT_VERSION, 'mode': 'disabled', 'classification': 'invalid', 'cve_id': None,
              'authorized': [], 'would_authorize': [], 'withheld': [], 'reasons': [], 'coverage_gaps': [],
              'binding': None}
    if not _mr._num(now):
        result['reasons'].append('invalid_evaluation_context')
        return result
    try:
        p = normalize_policy(policy)
        d = normalize_detection(detection)
    except Invalid as exc:
        result['reasons'].append(f'invalid_input: {exc}')
        return result
    result['mode'] = p['mode']
    result['cve_id'] = d['cve_id']
    result['binding'] = _digest(d)
    if d['ai_supplied']:
        result['reasons'].append('ai_output_not_authoritative')
    classification = _classify(d, p, float(now), result['reasons'], result['coverage_gaps'])
    result['classification'] = classification
    if classification != 'confirmed_exploitation':
        return result
    for kind in ACTIONS:
        if kind not in p['actions']:
            result['withheld'].append({'action': kind, 'reason': 'not_in_policy_scope'})
            continue
        target, reason = _mr._candidate(kind, d, p)
        if target is None:
            result['withheld'].append({'action': kind, 'reason': reason})
            continue
        result['would_authorize'].append({'action': kind, 'target': target, 'effect': EFFECTS[kind]})
    if p['mode'] == 'enforce':
        result['authorized'] = [dict(a, target=dict(a['target'])) for a in result['would_authorize']]
    elif result['would_authorize']:
        result['reasons'].append('monitor_only' if p['mode'] == 'monitor_only' else 'policy_disabled')
    return result
