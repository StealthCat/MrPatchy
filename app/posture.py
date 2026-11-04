"""Versioned read-only security posture rules; pure evaluation of stored evidence, no target I/O.

Each rule yields exactly one of pass/fail/not_applicable/unknown. Missing, failed, stale or
future-dated evidence is never reported as compliant."""
import math

RULESET_VERSION=1
STATES=('pass','fail','not_applicable','unknown')
DEFAULT_MAX_AGE=86400
FUTURE_SKEW=300


def _in(*allowed):return lambda v:v in allowed
def _max_int(limit):
    def check(v):
        try:return 0<int(v)<=limit
        except (TypeError,ValueError):return False
    return check

# id, sshd keyword, expected description, predicate, remediation guidance
SSH_RULES=(
    ('ssh.permitrootlogin','permitrootlogin','no, prohibit-password or forced-commands-only',_in('no','prohibit-password','without-password','forced-commands-only'),'Set PermitRootLogin to no or prohibit-password.'),
    ('ssh.passwordauthentication','passwordauthentication','no',_in('no'),'Set PasswordAuthentication to no once key-based access is verified.'),
    ('ssh.permitemptypasswords','permitemptypasswords','no',_in('no'),'Set PermitEmptyPasswords to no.'),
    ('ssh.pubkeyauthentication','pubkeyauthentication','yes',_in('yes'),'Set PubkeyAuthentication to yes.'),
    ('ssh.x11forwarding','x11forwarding','no',_in('no'),'Set X11Forwarding to no unless required.'),
    ('ssh.maxauthtries','maxauthtries','1 to 4',_max_int(4),'Set MaxAuthTries to 4 or lower.'),
)


def _result(rule,state,measured,reason):
    return {'rule':rule[0],'setting':rule[1],'state':state,'measured':measured,'expected':rule[2],'reason':reason,'remediation':rule[4] if state=='fail' else None,'rule_version':RULESET_VERSION}


def _evidence_problem(evidence,now,max_age):
    """Return (state,reason) when the evidence cannot support a verdict, else None."""
    if not isinstance(evidence,dict):return 'unknown','No evidence collected'
    if evidence.get('applicable') is False:return 'not_applicable','SSH daemon is not present on this target'
    if evidence.get('error'):return 'unknown','Collection failed: '+str(evidence['error'])[:200]
    at=evidence.get('collected_at')
    if type(at) not in (int,float) or not math.isfinite(at):return 'unknown','Evidence has no valid collection time'
    if at>now+FUTURE_SKEW:return 'unknown','Evidence collection time is in the future'
    if now-at>max_age:return 'unknown','Evidence is stale'
    if not isinstance(evidence.get('settings'),dict):return 'unknown','Evidence has no settings'
    return None


def evaluate_ssh(evidence,now,max_age=DEFAULT_MAX_AGE):
    """Evaluate bounded `sshd -T` style evidence: {'collected_at','source','settings':{keyword:value}}."""
    problem=_evidence_problem(evidence,now,max_age)
    settings=evidence['settings'] if problem is None else {}
    results=[]
    for rule in SSH_RULES:
        if problem:results.append(_result(rule,problem[0],None,problem[1]));continue
        raw=settings.get(rule[1])
        if not isinstance(raw,str) or not raw.strip():results.append(_result(rule,'unknown',None,'Setting not reported'));continue
        value=raw.strip().lower()[:200]
        ok=rule[3](value)
        results.append(_result(rule,'pass' if ok else 'fail',value,'Matches expected value' if ok else 'Does not match expected value'))
    counts={s:sum(r['state']==s for r in results) for s in STATES}
    overall='fail' if counts['fail'] else 'unknown' if counts['unknown'] else 'not_applicable' if counts['not_applicable']==len(results) else 'pass'
    return {'ruleset':'ssh','version':RULESET_VERSION,'state':overall,'counts':counts,'results':results,
            'collected_at':evidence.get('collected_at') if problem is None else None,'source':str(evidence.get('source',''))[:100] if isinstance(evidence,dict) else ''}
