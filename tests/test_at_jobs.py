import hashlib
import json
import time
import pytest
from target import agent
from app import persistence,startup_inventory as view
from app.db import Session,Host
from app.incidents import Inspection
from app.identity import User

# Layout written by Debian at 3.1.14+ (heredoc) for `echo ... | at 02:00`.
HEREDOC=b'''#!/bin/sh
# atrun uid=1000 gid=1000
# mail    alice 0
umask 22
LANG=C.UTF-8; export LANG
API_TOKEN=supersecretvalue; export API_TOKEN
PWD=/home/alice; export PWD
cd /home/alice || {
\t echo 'Execution directory inaccessible' >&2
\t exit 1
}
${SHELL:-/bin/sh} << 'marcinDELIMITER2c8e1f4b'
/usr/local/bin/sync --password hunter2 /srv
# a comment
curl -s https://deploy:s3cr3t@repo.example/x

marcinDELIMITER2c8e1f4b
'''
# Older at (before 3.1.14) appends the commands directly after the cd block.
PLAIN=b'''#!/bin/sh
# atrun uid=0 gid=0
# mail root 1
umask 22
HOME=/root; export HOME
cd /root || {
\t echo 'Execution directory inaccessible' >&2
\t exit 1
}
/sbin/reboot
'''
NAME='a0000301a2b3c4'
SCHEDULED=int('01a2b3c4',16)*60


def test_name_decodes_queue_job_and_time():
    assert agent.at_job_name('/var/spool/cron/atjobs/'+NAME)==('a',3,SCHEDULED)
    assert agent.at_job_name('/var/spool/cron/atjobs/=0000a01a2b3c4')==('=',10,SCHEDULED)
    for path in ('/var/spool/cron/atjobs/.SEQ','/var/spool/cron/atjobs/a0001','/var/spool/cron/crontabs/'+NAME,'/var/spool/at/'+NAME,'/var/spool/cron/atjobs/x/'+NAME):
        assert agent.at_job_name(path) is None


def test_heredoc_job_commands_owner_and_redaction():
    result=agent.parse_at_job(HEREDOC,('a',3,SCHEDULED))
    assert result['parsed'] and result['uid']==1000 and result['gid']==1000 and result['account']=='alice'
    assert result['queue']=='a' and result['job']==3 and result['scheduled_at']==SCHEDULED and result['running'] is False
    assert result['environment']==3 and result['redacted'] and not result['truncated']
    assert len(result['commands'])==2 and result['commands'][0].startswith('/usr/local/bin/sync --password [REDACTED]')
    text=json.dumps(result)
    for secret in ('hunter2','s3cr3t','supersecretvalue','C.UTF-8','Execution directory','marcinDELIMITER','a comment'):assert secret not in text


def test_plain_layout_and_running_queue():
    result=agent.parse_at_job(PLAIN,('=',7,SCHEDULED))
    assert result['parsed'] and result['commands']==['/sbin/reboot'] and result['account']=='root' and result['uid']==0
    assert result['queue']=='=' and result['running'] is True and result['environment']==1


def test_uppercase_batch_queue_is_not_running():
    # at(1): an uppercase queue letter is a batch-style queue; only the reserved '=' queue marks a running job.
    result=agent.parse_at_job(PLAIN,('B',7,SCHEDULED))
    assert result['queue']=='B' and result['running'] is False
    persistence.validate(inventory(result,path='/var/spool/cron/atjobs/B0000701a2b3c4'))
    for bad in ({**result,'queue':'b'},{**result,'running':True}):
        with pytest.raises(ValueError):persistence.validate(inventory(bad,path='/var/spool/cron/atjobs/B0000701a2b3c4'))
    running=agent.parse_at_job(PLAIN,('=',7,SCHEDULED))
    persistence.validate(inventory(running,path='/var/spool/cron/atjobs/=0000701a2b3c4'))
    with pytest.raises(ValueError):persistence.validate(inventory({**running,'running':False},path='/var/spool/cron/atjobs/=0000701a2b3c4'))


@pytest.mark.parametrize('data',[
    b'',b'echo hi\n',
    b'#!/bin/sh\n/bin/rm -rf /\n',  # no atrun header
    HEREDOC.replace(b'umask 22\n',b'umask 22\neval "$(curl x)"\n'),  # unexpected preamble
    HEREDOC.replace(b'marcinDELIMITER2c8e1f4b\n',b'',1)[:-1]+b'X\n',  # unterminated heredoc
    HEREDOC+b'/bin/after-heredoc\n',  # content after the heredoc end
    PLAIN.replace(b'}\n',b''),  # unterminated cd block
])
def test_unrecognized_layouts_are_unparsed_not_guessed(data):
    result=agent.parse_at_job(data,('a',1,60))
    assert result['parsed'] is False and result['commands']==[]
    persistence.validate_at(result,'/var/spool/cron/atjobs/a0000100000001')


def test_commands_are_bounded_and_control_characters_escaped():
    body=PLAIN.replace(b'/sbin/reboot\n',b''.join(b'/bin/j%d\n'%i for i in range(40))+b'/bin/'+b'x'*900+b'\n')
    result=agent.parse_at_job(body,('a',1,60))
    assert len(result['commands'])==agent.AT_COMMAND_LINES and result['truncated']
    long=agent.parse_at_job(PLAIN.replace(b'/sbin/reboot',b'/bin/'+b'x'*900),('a',1,60))
    assert len(long['commands'][0])==agent.CRON_COMMAND_LIMIT and long['truncated']
    escaped=agent.parse_at_job(PLAIN.replace(b'/sbin/reboot',b'/bin/echo \x1b[31m'),('a',1,60))
    assert escaped['commands']==['/bin/echo \\x1b[31m']


def spool(tmp_path,monkeypatch,data=HEREDOC):
    root=tmp_path/'cron';atjobs=root/'atjobs';atjobs.mkdir(parents=True)
    (atjobs/NAME).write_bytes(data);(atjobs/'.SEQ').write_bytes(b'3\n')
    monkeypatch.setattr(agent,'PERSISTENCE_ROOTS',(str(root),));monkeypatch.setattr(agent,'PERSISTENCE_FILES',())
    monkeypatch.setattr(agent,'CRON_USER_DIRS',());monkeypatch.setattr(agent,'AT_SPOOL_DIR',str(atjobs))
    monkeypatch.setattr(persistence,'AT_SPOOL_DIR',str(atjobs))
    return atjobs


def test_inventory_parses_exactly_the_hashed_bytes_only_when_asked(tmp_path,monkeypatch):
    atjobs=spool(tmp_path,monkeypatch)
    result=agent.persistence_inventory(time.monotonic()+5,cron_jobs=True)
    rows={r['path']:r for r in result['entries']}
    job=rows[str(atjobs/NAME)]
    assert job['sha256']==hashlib.sha256(HEREDOC).hexdigest() and job['at']['parsed'] and job['at']['job']==3
    assert 'at' not in rows[str(atjobs/'.SEQ')] and 'cron' not in job
    assert result['state']=='collected' and 'hunter2' not in json.dumps(result)
    persistence.validate(result)
    older=agent.persistence_inventory(time.monotonic()+5,cron_jobs=False)
    assert all('at' not in r for r in older['entries'])


def at_record(**changes):
    return {**agent.parse_at_job(HEREDOC,('a',3,SCHEDULED)),**changes}


def inventory(at=None,sha='a'*64,path='/var/spool/cron/atjobs/'+NAME):
    row=dict(path=path,kind='regular',uid=1000,gid=1,mode=0o700,size=1,mtime_ns=1,sha256=sha)
    if at is not None:row['at']=at
    return dict(state='collected',scope=['/var/spool/cron'],entries=[row],gaps=[],missing_roots=[],skipped=0)


@pytest.mark.parametrize('bad',[
    at_record(extra=1),at_record(job=4),at_record(queue='b'),at_record(running=True),at_record(scheduled_at=SCHEDULED+60),
    at_record(commands=['x']*33),at_record(commands=['']),at_record(commands=['x'*513]),at_record(commands=['a\x00b']),
    at_record(parsed=False),at_record(uid=-1),at_record(uid=None),at_record(account='bad user'),at_record(environment=True),
    {k:v for k,v in at_record().items() if k!='redacted'},
])
def test_controller_rejects_malformed_at_detail(bad):
    persistence.validate(inventory());persistence.validate(inventory(at_record()))
    with pytest.raises(ValueError):persistence.validate(inventory(bad))


def test_controller_rejects_at_detail_outside_the_spool():
    with pytest.raises(ValueError):persistence.validate(inventory(at_record(),path='/var/spool/cron/crontabs/'+NAME))
    with pytest.raises(ValueError):persistence.validate(inventory(at_record(),path='/var/spool/cron/atjobs/.SEQ'))


def test_changes_and_incident_evidence_stay_metadata_only():
    before=inventory(at_record());after=inventory(at_record(commands=['/bin/new-command']),sha='b'*64)
    changes=persistence.compare(before,after)['changes']
    assert changes[0]['fields']==['sha256'] and 'at' not in changes[0]['before'] and 'at' not in changes[0]['after']
    assert 'new-command' not in json.dumps(changes)
    assert persistence.compare(inventory(),inventory(at_record()))['changes']==[]


@pytest.fixture
def seeded(admin):
    with Session() as s:
        s.add(Host(id='one',name='fixture',address='192.0.2.1',fingerprint='fixture'))
        inv=inventory(at_record())
        inv['entries'].append(dict(path='/var/spool/cron/atjobs/a0000401a2b3c4',kind='regular',uid=0,gid=0,mode=0o700,size=1,mtime_ns=1,sha256='c'*64))
        inv['entries'].append(dict(path='/var/spool/cron/atjobs/.SEQ',kind='regular',uid=1,gid=1,mode=0o600,size=1,mtime_ns=1,sha256='d'*64))
        s.add(Inspection(id='receipt',host_id='one',report={'persistence':inv}));s.commit()
    return admin


def test_view_returns_at_jobs_search_coverage_and_older_agent_state(seeded,monkeypatch):
    from app import ai,ssh
    monkeypatch.setattr(ai,'request',lambda *a,**k:pytest.fail('no AI'))
    monkeypatch.setattr(ssh,'call',lambda *a,**k:pytest.fail('no target'))
    url='/api/hosts/one/security/startup-inventory'
    data=seeded.get(url).json()
    rows={r['path']:r for r in data['items']}
    job=rows['/var/spool/cron/atjobs/'+NAME]
    assert job['at_state']=='parsed' and job['at']['account']=='alice' and job['mechanism']=='at'
    assert rows['/var/spool/cron/atjobs/a0000401a2b3c4']['at_state']=='not_reported' and 'at' not in rows['/var/spool/cron/atjobs/a0000401a2b3c4']
    assert 'at_state' not in rows['/var/spool/cron/atjobs/.SEQ']
    at=[c for c in data['catalog'] if c['id']=='at'][0]
    assert at['observed_files']==3 and '1 parsed job' in at['label'] and '1 not reported' in at['label']
    assert [r['path'] for r in seeded.get(url,params={'q':'/usr/local/bin/sync'}).json()['items']]==['/var/spool/cron/atjobs/'+NAME]
    assert [r['path'] for r in seeded.get(url,params={'q':'alice'}).json()['items']]==['/var/spool/cron/atjobs/'+NAME]
    assert any('/var/spool/cron/atjobs' in gap for gap in data['gaps'])
    for role in ('operator','viewer'):
        with Session() as s:s.get(User,'admin').role=role;s.commit()
        assert seeded.get(url).status_code==403


@pytest.mark.parametrize('entry,state',[
    ({'path':'/var/spool/cron/atjobs/'+NAME,'kind':'regular'},'not_reported'),
    ({'path':'/var/spool/cron/atjobs/'+NAME,'kind':'regular','at':{}},'parsed'),
    ({'path':'/var/spool/cron/atjobs/.SEQ','kind':'regular'},None),
    ({'path':'/var/spool/cron/atjobs/'+NAME,'kind':'symlink'},None),
    ({'path':'/var/spool/cron/crontabs/'+NAME,'kind':'regular'},None),
])
def test_at_state_for_entries(entry,state):
    assert view.at_state(entry)==state
