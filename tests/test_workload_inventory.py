"""Container workload inventory contract (issue #336 first slice)."""
from app import workload_inventory as wi

D1='sha256:'+'a'*64
D2='sha256:'+'b'*64


def c(cid='1'*12,name='web',digest=D1,tag='nginx:1',state='running',runtime='docker',**extra):
    return {'runtime':runtime,'id':cid,'name':name,'image_digest':digest,'image_tag':tag,'state':state,'pids':[10],**extra}


def report(*containers,docker=True,podman=False):
    runtimes={}
    if docker is not None:runtimes['docker']={'accessible':docker}
    if podman is not None:runtimes['podman']={'accessible':podman}
    return {'runtimes':runtimes,'containers':list(containers)}


def test_same_image_in_two_containers_stays_distinct_instances():
    inv=wi.normalize(report(c('1'*12,'a'),c('2'*12,'b')))
    assert [w['key'] for w in inv['workloads']]==['docker:'+'1'*12,'docker:'+'2'*12]
    assert len(inv['images'])==1 and inv['images'][0]['workloads']==[w['key'] for w in inv['workloads']]


def test_duplicate_container_reports_collapse():
    inventory=wi.normalize(report(c(),c()))
    assert len(inventory['workloads'])==1
    assert inventory['images'][0]['workloads']==[inventory['workloads'][0]['key']]


def test_tag_is_label_not_identity():
    inv=wi.normalize(report(c('1'*12,'a',D1,'app:latest'),c('2'*12,'b',D2,'app:latest')))
    assert [i['digest'] for i in inv['images']]==[D1,D2]
    assert all(i['tags']==['app:latest'] for i in inv['images'])


def test_malformed_records_are_skipped_and_reported():
    bad=[c(cid='XYZ'),c(digest='nginx:latest'),c(state='paused'),c(name='-bad'),c(runtime='lxc'),'x',c(cid='3'*12,name='ok')]
    inv=wi.normalize(report(*bad))
    assert [w['name'] for w in inv['workloads']]==['ok'] and inv['rejected']==6
    assert any('6 malformed' in g for g in inv['gaps'])


def test_inaccessible_or_missing_runtime_is_explicit_gap_and_drops_its_records():
    inv=wi.normalize(report(c(),c('2'*12,'p',runtime='podman'),docker=True,podman=False))
    assert [w['runtime'] for w in inv['workloads']]==['docker']
    assert any('podman runtime was present but not accessible' in g for g in inv['gaps'])
    assert any('podman runtime did not report' in g for g in wi.normalize(report(docker=True,podman=None))['gaps'])


def test_oversize_report_sets_truncated_and_gap():
    many=[c('%012x'%i,'w%d'%i) for i in range(wi.MAX_CONTAINERS+5)]
    inv=wi.normalize(report(*many))
    assert inv['truncated'] and len(inv['workloads'])==wi.MAX_CONTAINERS and any('incomplete' in g for g in inv['gaps'])


def test_stopped_workload_has_no_pids_and_hostile_input_is_inert():
    inv=wi.normalize(report(c(state='stopped',pids=[1,2])))
    assert inv['workloads'][0]['pids']==[] and inv['workloads'][0]['state']=='stopped'
    for junk in (None,[],'x',{'runtimes':[],'containers':'x'}):
        assert wi.normalize(junk)['workloads']==[]
    assert wi.normalize(report(c(pids=[True,-1,0,5,5,'x'])))['workloads'][0]['pids']==[5]
    assert wi.normalize(report(c(tag='bad tag;rm')))['workloads'][0]['image_tag'] is None


def test_every_inventory_states_scope_gaps():
    assert any('not assessed for advisories' in g for g in wi.normalize(report())['gaps'])


def test_compare_replacement_tag_movement_and_state_change():
    old=wi.normalize(report(c('1'*12,'web',D1,'app:1'),c('2'*12,'db',D1,'app:1')))
    new=wi.normalize(report(c('3'*12,'web',D2,'app:1'),c('2'*12,'db',D1,'app:1',state='stopped')))
    diff=wi.compare(old,new)
    assert diff['replaced']==[['docker:'+'1'*12,'docker:'+'3'*12]]
    assert diff['added']==['docker:'+'3'*12] and diff['removed']==['docker:'+'1'*12]
    assert diff['changed']==['docker:'+'2'*12]
    assert diff['retagged']=={'app:1':[D2]}
    assert wi.compare(old,old)=={'added':[],'removed':[],'replaced':[],'changed':[],'retagged':{}}


def test_conflicting_duplicate_identity_is_unknown_and_leaves_no_stale_image_link():
    inv=wi.normalize(report(c(),c(digest=D2)))
    assert not inv['workloads'] and not inv['images'] and inv['rejected']==2


def test_replacement_does_not_cross_runtime_namespace():
    old=wi.normalize(report(c(),docker=True,podman=True))
    new=wi.normalize(report(c(cid='2'*12,runtime='podman'),docker=True,podman=True))
    assert wi.compare(old,new)['replaced']==[]


def test_newline_is_not_an_immutable_identity():
    assert not wi.normalize(report(c(digest=D1+'\n')))['workloads']


def test_tag_overflow_has_an_explicit_coverage_gap():
    inv=wi.normalize(report(*(c(cid=f'{i:012x}',name='w'+str(i),tag='app:'+str(i)) for i in range(17))))
    assert len(inv['images'][0]['tags'])==wi.MAX_TAGS
    assert inv['truncated'] and any('tag' in gap and 'incomplete' in gap for gap in inv['gaps'])


def test_tag_comparison_retains_every_new_observed_digest():
    d3='sha256:'+'c'*64
    old=wi.normalize(report(c(tag='app:latest')))
    new=wi.normalize(report(c(cid='2'*12,digest=D2,tag='app:latest'),c(cid='3'*12,digest=d3,tag='app:latest')))
    assert wi.compare(old,new)['retagged']=={'app:latest':[D2,d3]}
