import pytest
from app import asset_groups as ag
A={'1':{'tags':['Web','edge'],'site':'ams','owner':'ops','environment':'production','criticality':'high'},
   '2':{'tags':['db'],'site':'ams','environment':'staging','criticality':'low'},
   '3':{'site':'nyc','environment':'production','criticality':'critical'}}
def test_normalize_asset():
    n=ag.normalize_asset({'tags':[' Web ','web','b'],'environment':'Production'})
    assert n=={'tags':['b','web'],'site':'','owner':'','environment':'production','criticality':''}
@pytest.mark.parametrize('raw',[{'x':1},{'tags':['bad tag']},{'tags':'a'},{'tags':[1]},{'environment':'prod'},{'criticality':'urgent'},{'site':'a\nb'},{'owner':'x'*65},{'tags':[f't{i}' for i in range(21)]},[]])
def test_normalize_rejects(raw):
    with pytest.raises(ValueError):ag.normalize_asset(raw)
def rule(gid,*conds,**kw):return {'id':gid,'kind':'rule','conditions':list(conds),**kw}
def test_membership_static_and_rules():
    groups=[{'id':'pinned','kind':'static','hosts':[2,'3',99]},
        rule('prod',{'field':'environment','value':'production'}),
        rule('hi',{'field':'criticality','op':'min','value':'high'}),
        rule('either',{'field':'tag','op':'has','value':'db'},{'field':'site','value':'nyc'},match='any'),
        rule('both',{'field':'site','value':'ams'},{'field':'tag','op':'in','value':['web','db']})]
    m=ag.membership(groups,A)
    assert m=={'both':['1','2'],'either':['2','3'],'hi':['1','3'],'pinned':['2','3'],'prod':['1','3']}
def test_membership_diff():
    assert ag.membership_diff({'a':['1','2'],'b':['1']},{'a':['2','3'],'b':['1']})=={'a':{'added':['3'],'removed':['1']}}
@pytest.mark.parametrize('g',[{'id':'A','kind':'static'},{'id':'a','kind':'x'},rule('a'),rule('a',{'field':'nope','value':'x'}),rule('a',{'field':'site','op':'min','value':'x'}),rule('a',{'field':'criticality','op':'min','value':'huge'}),rule('a',{'field':'site','op':'in','value':[]}),rule('a',{'field':'site','value':'x'},priority=True),{'id':'a','kind':'static','hosts':[[1]]}])
def test_group_validation(g):
    with pytest.raises(ValueError):ag.validate_group(g)
def test_group_graph_errors():
    s=lambda i,p='':{'id':i,'kind':'static','parent':p}
    for gs in ([s('a'),s('a')],[s('a','zz')],[s('a','b'),s('b','a')]+[]):
        with pytest.raises(ValueError):ag.membership(gs,A)
def test_effective_policy_priority_inheritance_and_conflict():
    groups=[rule('prod',{'field':'environment','value':'production'},policy={'window':'sun','approve':'two'},priority=1),
        rule('hi',{'field':'criticality','op':'min','value':'high'},policy={'window':'sat','freeze':True},priority=1),
        rule('edge',{'field':'tag','value':'edge'},parent='prod',policy={'approve':'one'},priority=5),
        {'id':'pin','kind':'static','hosts':[1],'policy':{'freeze':False},'priority':9}]
    r=ag.effective_policy(1,groups,A)
    assert r['groups']==['edge','hi','pin','prod']
    assert r['conflicts']==[] and r['policy']['window']=={'value':'sun','source':'prod','priority':5}  # inherited at the child's priority
    c=ag.effective_policy(3,groups,A)
    assert c['conflicts']==[{'key':'window','priority':1,'groups':['hi','prod'],'values':["'sat'","'sun'"]}]
    assert 'window' not in c['policy'] and c['policy']['approve']['value']=='two'
    assert r['policy']['approve']=={'value':'one','source':'edge','priority':5}
    assert r['policy']['freeze']['source']=='pin'
    assert ag.effective_policy(2,groups,A)=={'host':'2','groups':[],'policy':{},'conflicts':[]}
def test_inherited_parent_policy_applies_to_child_members_only():
    groups=[rule('prod',{'field':'environment','value':'production'},policy={'k':1}),rule('edge',{'field':'tag','value':'edge'},parent='prod')]
    assert ag.effective_policy(1,groups,A)['policy']['k']['source']=='prod'
    assert ag.effective_policy(2,groups,A)['policy']=={}
