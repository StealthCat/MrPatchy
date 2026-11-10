import json
import time
import pytest
from target import agent
from app import persistence,startup_inventory as view
from app.db import Session,Host
from app.incidents import Inspection
from app.identity import User

SYSTEM=b'''SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/sbin
MAILTO=ops@example.invalid
# m h dom mon dow user command
17 *\t* * *\troot    cd / && run-parts --report /etc/cron.hourly
@reboot root /usr/local/bin/agent --password hunter2 -v
*/5 * * * * www-data curl -s https://deploy:s3cr3t@repo.example/x?token=abc123 -H "Authorization: Bearer eyJabc"
0 1 * * * backup mysqldump -u root -pTopSecret appdb > /srv/backup.sql
not a cron line
@fortnightly root /bin/true
0 2 * * * bad/user /bin/true
'''


def test_system_crontab_jobs_accounts_specials_and_counts():
    result=agent.parse_cron(SYSTEM,'system')
    jobs=result['jobs']
    assert [j['line'] for j in jobs]==[5,6,7,8]
    assert jobs[0]=={'line':5,'schedule':'17 * * * *','account':'root','command':'cd / && run-parts --report /etc/cron.hourly','redacted':False,'command_truncated':False}
    assert jobs[1]['schedule']=='@reboot' and jobs[1]['account']=='root'
    assert [j['account'] for j in jobs]==['root','root','www-data','backup']
    assert result['environment']==3 and result['unparsed']==3 and result['truncated'] is False


def test_commands_and_environment_never_export_credentials():
    text=json.dumps(agent.parse_cron(SYSTEM,'system'))
    for secret in ('hunter2','s3cr3t','abc123','eyJabc','TopSecret','ops@example.invalid','/usr/local/sbin'):assert secret not in text
    jobs=agent.parse_cron(SYSTEM,'system')['jobs']
    assert all(j['redacted'] for j in jobs[1:]) and '[REDACTED]' in jobs[2]['command']
    assert agent.parse_cron(b'* * * * * find / -perm -4000 -print\n','user','alice')['jobs'][0]['command']=='find / -perm -4000 -print'


def test_user_crontab_takes_account_from_spool_and_bounds_output():
    result=agent.parse_cron(b'@daily /bin/x\n* * * * * /bin/y\n','user','alice')
    assert [j['account'] for j in result['jobs']]==['alice','alice'] and result['format']=='user'
    many=agent.parse_cron(b''.join(b'* * * * * /bin/job%d\n'%i for i in range(70)),'user','alice')
    assert len(many['jobs'])==agent.CRON_FILE_JOBS and many['truncated']
    budget=agent.parse_cron(b'* * * * * /a\n* * * * * /b\n','user','alice',budget=1)
    assert len(budget['jobs'])==1 and budget['truncated']
    long=agent.parse_cron(b'* * * * * /bin/'+b'x'*2000+b'\n','user','alice')['jobs'][0]
    assert len(long['command'])==agent.CRON_COMMAND_LIMIT and long['command_truncated']
    assert agent.parse_cron(b'\xff\xfe* * * * * /bin/x\n','user')['unparsed']==1


@pytest.mark.parametrize('path,form',[('/etc/crontab','system'),('/etc/cron.d/backup','system'),('/var/spool/cron/crontabs/bob','user'),
    ('/var/spool/cron/bob','user'),('/etc/cron.daily/logrotate',None),('/var/spool/cron/atjobs/a0001',None),('/etc/profile.d/x.sh',None)])
def test_only_crontab_format_paths_are_parsed(path,form):assert agent.cron_format(path)==form


def test_inventory_parses_exactly_the_hashed_bytes(tmp_path,monkeypatch):
    import hashlib
    crond=tmp_path/'cron.d';crond.mkdir();(crond/'backup').write_bytes(SYSTEM)
    spool=tmp_path/'crontabs';spool.mkdir();(spool/'alice').write_text('@hourly /home/alice/sync --token=xyz\n')
    daily=tmp_path/'daily';daily.mkdir();(daily/'script').write_text('#!/bin/sh\nSECRET CONTENT\n')
    monkeypatch.setattr(agent,'PERSISTENCE_ROOTS',(str(crond),str(spool),str(daily)))
    monkeypatch.setattr(agent,'PERSISTENCE_FILES',())
    monkeypatch.setattr(agent,'CRON_SYSTEM_DIRS',(str(crond),))
    monkeypatch.setattr(agent,'CRON_USER_DIRS',(str(spool),))
    result=agent.persistence_inventory(time.monotonic()+5)
    rows={r['path']:r for r in result['entries']}
    backup=rows[str(crond/'backup')];assert backup['sha256']==hashlib.sha256(SYSTEM).hexdigest() and len(backup['cron']['jobs'])==4
    alice=rows[str(spool/'alice')]['cron']['jobs'][0];assert alice['account']=='alice' and 'xyz' not in alice['command']
    assert 'cron' not in rows[str(daily/'script')] and 'SECRET CONTENT' not in json.dumps(result)
    assert result['state']=='collected'
    persistence.validate(result)


def test_inventory_job_total_is_bounded(tmp_path,monkeypatch):
    crond=tmp_path/'cron.d';crond.mkdir()
    for i in range(5):(crond/('f'+str(i))).write_bytes(b''.join(b'* * * * * root /bin/j%d\n'%n for n in range(64)))
    monkeypatch.setattr(agent,'PERSISTENCE_ROOTS',(str(crond),));monkeypatch.setattr(agent,'PERSISTENCE_FILES',())
    monkeypatch.setattr(agent,'CRON_SYSTEM_DIRS',(str(crond),))
    result=agent.persistence_inventory(time.monotonic()+5)
    assert sum(len(r['cron']['jobs']) for r in result['entries'])==agent.CRON_TOTAL_JOBS
    assert any(r['cron']['truncated'] for r in result['entries'])
    persistence.validate(result)


def inventory(cron=None,sha='a'*64):
    row=dict(path='/etc/cron.d/backup',kind='regular',uid=0,gid=0,mode=420,size=1,mtime_ns=1,sha256=sha)
    if cron is not None:row['cron']=cron
    return dict(state='collected',scope=['/etc/cron.d'],entries=[row],gaps=[],missing_roots=[],skipped=0)


def parsed(command='/bin/x'):
    return {'format':'system','jobs':[{'line':1,'schedule':'@daily','account':'root','command':command,'redacted':False,'command_truncated':False}],
            'unparsed':0,'environment':0,'truncated':False}


@pytest.mark.parametrize('bad',[
    {'format':'other','jobs':[],'unparsed':0,'environment':0,'truncated':False},
    {**parsed(),'extra':1},
    {**parsed(),'unparsed':-1},
    {**parsed(),'jobs':parsed()['jobs']*65},
    {**parsed(),'jobs':[{**parsed()['jobs'][0],'line':0}]},
    {**parsed(),'jobs':[{**parsed()['jobs'][0],'command':''}]},
    {**parsed(),'jobs':[{**parsed()['jobs'][0],'command':'x'*513}]},
    {**parsed(),'jobs':[{**parsed()['jobs'][0],'account':5}]},
    {**parsed(),'jobs':[{**parsed()['jobs'][0],'raw':'secret'}]},
])
def test_controller_rejects_malformed_cron_detail(bad):
    persistence.validate(inventory())
    persistence.validate(inventory(parsed()))
    with pytest.raises(ValueError):persistence.validate(inventory(bad))


def test_controller_rejects_more_than_total_jobs():
    many={**parsed(),'jobs':parsed()['jobs']*64}
    inv=inventory(many);inv['entries']=[{**inv['entries'][0],'path':'/etc/cron.d/f'+str(i)} for i in range(5)]
    with pytest.raises(ValueError):persistence.validate(inv)


def test_changes_and_incident_evidence_stay_metadata_only():
    before=inventory(parsed('/bin/old'));after=inventory(parsed('/bin/new-command'),sha='b'*64)
    changes=persistence.compare(before,after)['changes']
    assert changes[0]['fields']==['sha256'] and 'cron' not in changes[0]['before'] and 'cron' not in changes[0]['after']
    assert 'new-command' not in json.dumps(changes)
    # Upgrading the agent adds parsed jobs without content changes: no spurious change.
    assert persistence.compare(inventory(),inventory(parsed()))['changes']==[]


@pytest.fixture
def seeded(admin):
    with Session() as s:
        s.add(Host(id='one',name='fixture',address='192.0.2.1',fingerprint='fixture'))
        inv=inventory(parsed('/usr/bin/nightly-backup'))
        inv['entries'].append(dict(path='/etc/cron.d/legacy',kind='regular',uid=0,gid=0,mode=420,size=1,mtime_ns=1,sha256='c'*64))
        s.add(Inspection(id='receipt',host_id='one',report={'persistence':inv}));s.commit()
    return admin


def test_view_returns_jobs_search_and_older_agent_state(seeded,monkeypatch):
    from app import ai,ssh
    monkeypatch.setattr(ai,'request',lambda *a,**k:pytest.fail('no AI'))
    monkeypatch.setattr(ssh,'call',lambda *a,**k:pytest.fail('no target'))
    url='/api/hosts/one/security/startup-inventory'
    data=seeded.get(url).json()
    rows={r['path']:r for r in data['items']}
    assert rows['/etc/cron.d/backup']['jobs_state']=='parsed' and rows['/etc/cron.d/backup']['cron']['jobs'][0]['command']=='/usr/bin/nightly-backup'
    assert rows['/etc/cron.d/legacy']['jobs_state']=='not_reported' and 'cron' not in rows['/etc/cron.d/legacy']
    assert data['cron']=={'files':1,'jobs':1,'unparsed':0,'truncated':False,'not_reported':1}
    assert [r['path'] for r in seeded.get(url,params={'q':'nightly-backup'}).json()['items']]==['/etc/cron.d/backup']
    assert any('crontab-format' in gap for gap in data['gaps'])
    for role in ('operator','viewer'):
        with Session() as s:s.get(User,'admin').role=role;s.commit()
        assert seeded.get(url).status_code==403


@pytest.mark.parametrize('path,kind,state',[('/etc/crontab','regular','not_reported'),('/var/spool/cron/crontabs/bob','regular','not_reported'),
    ('/etc/cron.daily/x','regular','not_crontab'),('/etc/cron.d/link','symlink','not_crontab')])
def test_jobs_state_for_entries_without_detail(path,kind,state):
    assert view.jobs_state({'path':path,'kind':kind})==state
