"""Pure asset metadata, group membership and effective-policy preview (first slice of #334).

Nothing here touches the database, routes, authorization or runtime actions. Inputs are
plain dicts; every result is deterministic (sorted) so it can be previewed and audited.
"""
import re
ENVIRONMENTS=('production','staging','development','test')
CRITICALITIES=('low','medium','high','critical')
FIELDS=('tag','site','owner','environment','criticality')
MAX_TAGS=20;MAX_DEPTH=8
TAG=re.compile(r'^[a-z0-9][a-z0-9._:-]{0,31}$')
TEXT=re.compile(r'^[^\x00-\x1f\x7f]{1,64}$')
def _text(value,name):
    value=value.strip() if isinstance(value,str) else value
    if value in (None,''):return ''
    if not isinstance(value,str) or not TEXT.match(value):raise ValueError(f'{name} must be 1-64 printable characters')
    return value
def normalize_asset(raw):
    """Validate host metadata; unknown keys are rejected, tags are lowercased, de-duplicated and sorted."""
    if not isinstance(raw,dict):raise ValueError('asset metadata must be an object')
    extra=sorted(set(raw)-{'tags','site','owner','environment','criticality'})
    if extra:raise ValueError('unknown asset field: '+extra[0])
    tags=raw.get('tags') or []
    if not isinstance(tags,(list,tuple)):raise ValueError('tags must be a list')
    clean=sorted({t.strip().lower() if isinstance(t,str) else t for t in tags})
    if len(clean)>MAX_TAGS:raise ValueError(f'at most {MAX_TAGS} tags')
    if any(not isinstance(t,str) or not TAG.match(t) for t in clean):raise ValueError('tags must be lowercase letters, digits and . _ : -')
    env=(raw.get('environment') or '');crit=(raw.get('criticality') or '')
    env=env.strip().lower() if isinstance(env,str) else env;crit=crit.strip().lower() if isinstance(crit,str) else crit
    if env and env not in ENVIRONMENTS:raise ValueError('environment must be one of '+', '.join(ENVIRONMENTS))
    if crit and crit not in CRITICALITIES:raise ValueError('criticality must be one of '+', '.join(CRITICALITIES))
    return {'tags':clean,'site':_text(raw.get('site'),'site'),'owner':_text(raw.get('owner'),'owner'),'environment':env,'criticality':crit}
def _condition(asset,cond):
    field,op,value=cond['field'],cond['op'],cond['value']
    if field=='tag':return value in asset['tags'] if op in ('eq','has') else any(v in asset['tags'] for v in value)
    actual=asset[field]
    if op=='in':return actual in value
    if op=='min':return bool(actual) and CRITICALITIES.index(actual)>=CRITICALITIES.index(value)
    return actual==value
def validate_group(group):
    """Return a normalized group. Kinds: static (explicit host ids) or rule (conditions over asset metadata)."""
    if not isinstance(group,dict):raise ValueError('group must be an object')
    gid=group.get('id')
    if not isinstance(gid,str) or not TAG.match(gid):raise ValueError('group id must be lowercase letters, digits and . _ : -')
    kind=group.get('kind')
    if kind not in ('static','rule'):raise ValueError('group kind must be static or rule')
    out={'id':gid,'kind':kind,'parent':group.get('parent') or '','priority':group.get('priority',0),'policy':dict(group.get('policy') or {})}
    if not isinstance(out['priority'],int) or isinstance(out['priority'],bool) or not -1000<=out['priority']<=1000:raise ValueError('priority must be an integer from -1000 to 1000')
    if out['parent'] and not isinstance(out['parent'],str):raise ValueError('parent must be a group id')
    if kind=='static':
        hosts=group.get('hosts') or []
        if not isinstance(hosts,(list,tuple)) or any(not isinstance(h,(int,str)) or isinstance(h,bool) for h in hosts):raise ValueError('hosts must be a list of host ids')
        out['hosts']=sorted({str(h) for h in hosts})
    else:
        match=group.get('match','all')
        if match not in ('all','any'):raise ValueError('match must be all or any')
        conds=group.get('conditions')
        if not isinstance(conds,(list,tuple)) or not conds:raise ValueError('rule groups need at least one condition')
        clean=[]
        for c in conds:
            if not isinstance(c,dict) or c.get('field') not in FIELDS:raise ValueError('condition field must be one of '+', '.join(FIELDS))
            field,op,value=c['field'],c.get('op','eq'),c.get('value')
            if op not in ('eq','in','has','min') or (op=='has' and field!='tag') or (op=='min' and field!='criticality'):raise ValueError('unsupported condition operator for '+field)
            if op in ('in',) :
                if not isinstance(value,(list,tuple)) or not value:raise ValueError('in needs a non-empty list')
                value=sorted(set(value))
            elif not isinstance(value,str) or not value:raise ValueError('condition value must be a non-empty string')
            if op=='min' and value not in CRITICALITIES:raise ValueError('min needs a criticality level')
            clean.append({'field':field,'op':op,'value':value})
        out['match']=match;out['conditions']=clean
    return out
def _validated(groups):
    out={}
    for g in groups:
        g=validate_group(g)
        if g['id'] in out:raise ValueError('duplicate group id: '+g['id'])
        out[g['id']]=g
    for g in out.values():
        seen=[g['id']];cur=g
        while cur['parent']:
            if cur['parent'] not in out:raise ValueError('unknown parent group: '+cur['parent'])
            if cur['parent'] in seen:raise ValueError('group parent cycle at '+cur['parent'])
            seen.append(cur['parent']);cur=out[cur['parent']]
            if len(seen)>MAX_DEPTH:raise ValueError('group nesting too deep')
    return out
def membership(groups,assets):
    """Map group id -> sorted host ids. assets maps host id -> raw metadata. Static members without a host record are ignored."""
    groups=_validated(groups);assets={str(h):normalize_asset(a) for h,a in assets.items()};result={}
    for gid,g in sorted(groups.items()):
        if g['kind']=='static':result[gid]=[h for h in g['hosts'] if h in assets]
        else:
            test=all if g['match']=='all' else any
            result[gid]=sorted(h for h,a in assets.items() if test(_condition(a,c) for c in g['conditions']))
    return result
def membership_diff(before,after):
    """Preview of what a membership change adds or removes, keyed by group id; unchanged groups are omitted."""
    diff={}
    for gid in sorted(set(before)|set(after)):
        old,new=set(before.get(gid,())),set(after.get(gid,()))
        if old!=new:diff[gid]={'added':sorted(new-old),'removed':sorted(old-new)}
    return diff
def effective_policy(host_id,groups,assets):
    """Resolve a host's policy. A child group overrides its parent; across unrelated groups the higher
    priority wins; equal priority with different values is a conflict and the key is left unset."""
    host_id=str(host_id);valid=_validated(groups);members=membership(groups,assets)
    direct=[gid for gid in sorted(valid) if host_id in members[gid]]
    claims={}
    for gid in direct:
        chain=[];cur=valid[gid]
        while cur:chain.append(cur);cur=valid.get(cur['parent'])
        merged={}
        for g in reversed(chain):  # parent first so the child overrides
            for k,v in g['policy'].items():merged[k]=(v,g['id'])
        for k,(v,src) in merged.items():claims.setdefault(k,[]).append({'value':v,'source':src,'group':gid,'priority':valid[gid]['priority']})
    policy={};conflicts=[]
    for k in sorted(claims):
        top=max(c['priority'] for c in claims[k]);best=[c for c in claims[k] if c['priority']==top]
        values={repr(c['value']) for c in best}
        if len(values)==1:policy[k]={'value':best[0]['value'],'source':sorted(c['source'] for c in best)[0],'priority':top}
        else:conflicts.append({'key':k,'priority':top,'groups':sorted({c['group'] for c in best}),'values':sorted(values)})
    return {'host':host_id,'groups':direct,'policy':policy,'conflicts':conflicts}
