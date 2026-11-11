"""Administrator-reviewed application probes for rollout health gates (#338, first slice).

Probes are data, never commands: a fixed HTTP or TCP adapter on the target connects to
the server's own loopback address only. Definitions are bounded and stored per host; the
rollout runner collects a baseline before patching and compares it after, so failures
that already existed are reported but do not stop the rollout, while a newly failing
required probe does. Missing, malformed, timed-out or unavailable results are never healthy.
"""
import re
from .db import Setting

MAX_PROBES=16
NAME=re.compile(r'[a-z0-9][a-z0-9_.-]{0,39}')
PATH=re.compile(r"/[A-Za-z0-9/_.~%:@!$&'()*+,;=?-]{0,199}")
KINDS=('http','tcp')

def key(host_id):return 'probes:'+host_id

def normalize(probes):
    """Validate reviewed probe definitions and return a canonical list."""
    if not isinstance(probes,list) or len(probes)>MAX_PROBES:raise ValueError('Provide at most '+str(MAX_PROBES)+' probes')
    result=[];seen=set()
    for probe in probes:
        if not isinstance(probe,dict):raise ValueError('Each probe must be an object')
        allowed={'name','kind','port','path','expect_status','timeout','required','reason'}
        if set(probe)-allowed:raise ValueError('Unsupported probe field: '+sorted(set(probe)-allowed)[0])
        name=probe.get('name');kind=probe.get('kind');port=probe.get('port')
        if not isinstance(name,str) or not NAME.fullmatch(name):raise ValueError('Probe names use 1–40 lowercase letters, digits, dot, dash or underscore')
        if name in seen:raise ValueError('Duplicate probe name: '+name)
        seen.add(name)
        if kind not in KINDS:raise ValueError('Probe kind must be http or tcp')
        if type(port) is not int or not 1<=port<=65535:raise ValueError('Probe port must be 1–65535')
        timeout=probe.get('timeout',5)
        if type(timeout) is not int or not 1<=timeout<=10:raise ValueError('Probe timeout must be 1–10 seconds')
        required=probe.get('required',True)
        if type(required) is not bool:raise ValueError('Probe required must be true or false')
        reason=probe.get('reason')
        if not isinstance(reason,str) or not 1<=len(reason.strip())<=200 or any(ord(c)<32 for c in reason):
            raise ValueError('Record why the probe is required (1–200 characters)')
        item={'name':name,'kind':kind,'port':port,'timeout':timeout,'required':required,'reason':reason.strip()}
        if kind=='http':
            path=probe.get('path','/');status=probe.get('expect_status',200)
            if not isinstance(path,str) or not PATH.fullmatch(path):raise ValueError('HTTP probe path must start with / and use URL-safe characters')
            if type(status) is not int or not 100<=status<=599:raise ValueError('Expected HTTP status must be 100–599')
            item.update(path=path,expect_status=status)
        elif 'path' in probe or 'expect_status' in probe:raise ValueError('TCP probes take no path or expected status')
        result.append(item)
    return result

def load(s,host_id):
    row=s.get(Setting,key(host_id))
    return list(row.value.get('probes',[])) if row else []

def request(probes):
    """Target request carrying only the reviewed fields the fixed adapter understands."""
    return {'action':'app-probe','probes':[{k:v for k,v in p.items() if k!='reason'} for p in probes]}

def baseline_trusted(probes,results):
    """Require exactly one explicit boolean observation per reviewed probe.

    A known failure is useful baseline evidence; missing or ambiguous evidence is
    not a known pre-existing failure and cannot authorize a package change.
    """
    if not isinstance(results,dict) or not isinstance(results.get('results'),list):return False
    rows=results['results']
    if len(rows)!=len(probes) or len(rows)>MAX_PROBES:return False
    expected={p['name'] for p in probes};seen=set()
    for row in rows:
        if not isinstance(row,dict) or not isinstance(row.get('name'),str):return False
        name=row['name']
        if name not in expected or name in seen or type(row.get('ok')) is not bool:return False
        seen.add(name)
    return seen==expected

def _outcomes(probes,results):
    """name -> (healthy, detail); anything missing, repeated or malformed is unhealthy."""
    rows={}
    if isinstance(results,dict) and isinstance(results.get('results'),list) and len(results['results'])<=MAX_PROBES:
        for row in results['results']:
            if isinstance(row,dict) and isinstance(row.get('name'),str):
                rows.setdefault(row['name'],[]).append(row)
    out={}
    for probe in probes:
        found=rows.get(probe['name'],[])
        if len(found)!=1 or found[0].get('ok') is not True and found[0].get('ok') is not False:
            out[probe['name']]=(False,'no trustworthy result')
        else:
            out[probe['name']]=(found[0]['ok'],str(found[0].get('detail',''))[:200])
    return out

def comparison(probes,before,after):
    """Pre/post contract: only a required probe that was healthy and is not now stops a rollout."""
    valid=baseline_trusted(probes,before)
    previous=_outcomes(probes,before);current=_outcomes(probes,after)
    required=[p['name'] for p in probes if p['required']]
    new=[n for n in required if previous[n][0] and not current[n][0]]
    pre=[n for n in required if valid and not previous[n][0] and not current[n][0]]
    return {'probes':len(probes),'new_probe_failures':new,'pre_existing_probe_failures':pre,
            'recovered_probes':[n for n in required if valid and not previous[n][0] and current[n][0]],
            'details':{n:current[n][1] for n in new+pre},'baseline_valid':valid,'passed':valid and not new}
