"""Container workload inventory contract (issue #336, first slice).

Pure, read-only normalisation of Docker/Podman container reports. Nothing here
executes a runtime, reads manifests or installs anything: it only validates a
bounded report that a collector produced and attributes workloads to images by
immutable digest. A movable tag is never treated as identity.
"""
import re

RUNTIMES=('docker','podman')
STATES=('running','stopped')
MAX_CONTAINERS=512
MAX_TAGS=16
MAX_TEXT=256
CONTAINER_ID=re.compile(r'^[0-9a-f]{12,64}$')
IMAGE_DIGEST=re.compile(r'^sha256:[0-9a-f]{64}$')
NAME=re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$')
TAG=re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.:/@-]{0,%d}$'%(MAX_TEXT-1))
GAPS=[
    'Host packages, image packages and application dependencies are separate inventories; none is implied by a container record.',
    'Image contents are not scanned: an image listed here is not assessed for advisories.',
    'Only runtimes that reported are covered; an inaccessible or absent runtime is a gap, not proof of no workloads.',
]


def _text(value,pattern):
    return value if isinstance(value,str) and len(value)<=MAX_TEXT and pattern.fullmatch(value) else None


def _pid_list(value):
    if not isinstance(value,list) or len(value)>64:return []
    return sorted({p for p in value if isinstance(p,int) and not isinstance(p,bool) and 0<p<2**22})


def workload_key(runtime,container_id):
    """Stable identity of one workload instance (the same image in two containers differs)."""
    return f'{runtime}:{container_id}'


def normalize(report):
    """Return a normalised inventory for one host report.

    Malformed records are counted and skipped, never guessed. Workloads are keyed
    by runtime and container id; images by immutable digest with their observed
    tags as non-identifying labels. Duplicate container reports collapse, and
    reports beyond the bound set ``truncated`` instead of being silently dropped.
    """
    runtimes={};workloads={};images={};rejected=0;truncated=False;conflicts=set();tags_truncated=False
    raw_runtimes=report.get('runtimes') if isinstance(report,dict) else None
    if not isinstance(raw_runtimes,dict):raw_runtimes={}
    for name in RUNTIMES:
        item=raw_runtimes.get(name)
        if name in RUNTIMES and isinstance(item,dict):
            runtimes[name]='accessible' if item.get('accessible') is True else 'inaccessible'
    containers=report.get('containers') if isinstance(report,dict) else None
    if not isinstance(containers,list):containers=[]
    if len(containers)>MAX_CONTAINERS:containers=containers[:MAX_CONTAINERS];truncated=True
    for item in containers:
        if not isinstance(item,dict):rejected+=1;continue
        runtime=item.get('runtime');cid=_text(item.get('id'),CONTAINER_ID);digest=_text(item.get('image_digest'),IMAGE_DIGEST)
        state=item.get('state');name=_text(item.get('name'),NAME)
        if runtime not in RUNTIMES or cid is None or digest is None or state not in STATES or name is None:rejected+=1;continue
        if runtimes.get(runtime)!='accessible':rejected+=1;continue
        tag=_text(item.get('image_tag'),TAG) if item.get('image_tag') is not None else None
        key=workload_key(runtime,cid)
        value={'key':key,'runtime':runtime,'container_id':cid,'name':name,'state':state,'image_digest':digest,
               'image_tag':tag,'pids':_pid_list(item.get('pids')) if state=='running' else []}
        if key in conflicts:rejected+=1;continue
        if key in workloads:
            if workloads[key]==value:continue
            del workloads[key];conflicts.add(key);rejected+=2;continue
        workloads[key]=value
    # Build reverse links only after duplicate/conflict handling, so every image
    # reference resolves to exactly one retained workload observation.
    for key,item in workloads.items():
        digest=item['image_digest'];tag=item['image_tag']
        image=images.setdefault(digest,{'digest':digest,'tags':[],'workloads':[]})
        if tag and tag not in image['tags']:
            if len(image['tags'])<MAX_TAGS:image['tags'].append(tag)
            else:tags_truncated=True
        image['workloads'].append(key)
    for image in images.values():image['tags'].sort();image['workloads'].sort()
    gaps=list(GAPS)
    for name in RUNTIMES:
        if runtimes.get(name)=='inaccessible':gaps.append(f'{name} runtime was present but not accessible; its workloads are unknown.')
        elif name not in runtimes:gaps.append(f'{name} runtime did not report; its workloads are unknown.')
    if rejected:gaps.append(f'{rejected} malformed or unattributable container record(s) were skipped.')
    if truncated:gaps.append(f'More than {MAX_CONTAINERS} containers were reported; the inventory is incomplete.')
    if tags_truncated:gaps.append(f'More than {MAX_TAGS} tags were reported for an image; tag coverage is incomplete.')
    return {'runtimes':runtimes,'workloads':sorted(workloads.values(),key=lambda w:w['key']),
            'images':sorted(images.values(),key=lambda i:i['digest']),'rejected':rejected,'truncated':truncated or tags_truncated,'gaps':gaps}


def compare(previous,current):
    """Classify changes between two normalised inventories by workload identity.

    ``replaced`` is a container whose name persists under a new id; ``retagged``
    lists every newly observed digest for an image tag. It does not assert the
    current registry resolution of that movable label. Neither is conflated
    with an unchanged workload.
    """
    old={w['key']:w for w in previous['workloads']};new={w['key']:w for w in current['workloads']}
    added=sorted(set(new)-set(old));removed=sorted(set(old)-set(new))
    by_name={}
    for k in removed:by_name.setdefault((old[k]['runtime'],old[k]['name']),[]).append(k)
    replacements={}
    for k in added:replacements.setdefault((new[k]['runtime'],new[k]['name']),[]).append(k)
    replaced=sorted((values[0],replacements[name][0]) for name,values in by_name.items()
        if len(values)==1 and len(replacements.get(name,[]))==1)
    changed=sorted(k for k in set(old)&set(new) if (old[k]['state'],old[k]['image_digest'])!=(new[k]['state'],new[k]['image_digest']))
    tags={}
    for image in previous['images']:
        for tag in image['tags']:tags.setdefault(tag,set()).add(image['digest'])
    moved={}
    for image in current['images']:
        for tag in image['tags']:
            if tag in tags and image['digest'] not in tags[tag]:moved.setdefault(tag,set()).add(image['digest'])
    return {'added':added,'removed':removed,'replaced':[list(p) for p in replaced],'changed':changed,
            'retagged':{tag:sorted(digests) for tag,digests in sorted(moved.items())}}
