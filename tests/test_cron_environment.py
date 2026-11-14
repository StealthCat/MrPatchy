"""SHELL and PATH a crontab assigns above each parsed job (#837)."""
import json
import pytest
from target import agent
from app import persistence


def jobs(text,form='user',account='alice'):
    return agent.parse_cron(text,form,account)['jobs']


def test_assignment_applies_only_to_following_jobs():
    result=jobs(b'* * * * * /bin/a\nPATH=/tmp/evil:/usr/bin\nSHELL=/home/alice/sh\n* * * * * /bin/b\nPATH=/usr/bin\n* * * * * /bin/c\n')
    assert [(j['shell'],j['path']) for j in result]==[(None,None),('/home/alice/sh','/tmp/evil:/usr/bin'),('/home/alice/sh','/usr/bin')]
    assert not any(j['shell_truncated'] or j['path_truncated'] for j in result)


def test_quotes_blanks_and_empty_values_follow_cron():
    result=jobs(b'PATH = "/opt/x:/usr/bin"\nSHELL=\'/bin/bash\'\n@daily /bin/a\nPATH=\n@daily /bin/b\n')
    assert (result[0]['shell'],result[0]['path'])==('/bin/bash','/opt/x:/usr/bin')
    assert result[1]['path']==''


def test_other_assignments_are_counted_but_never_disclosed():
    result=agent.parse_cron(b'MAILTO=ops@example.invalid\nAPI_TOKEN=hunter2\nHOME=/srv/secret-home\n* * * * * root /bin/a\n','system')
    text=json.dumps(result)
    assert result['environment']==3
    for value in ('ops@example.invalid','hunter2','/srv/secret-home'):assert value not in text


def test_values_are_bounded_escaped_and_redacted():
    long=jobs(b'PATH=/'+b'a'*2000+b'\n* * * * * /bin/x\n')[0]
    assert len(long['path'])==agent.CRON_COMMAND_LIMIT and long['path_truncated']
    escaped=jobs(b'SHELL=/bin/sh\x1b[31m\n* * * * * /bin/x\n')[0]
    assert escaped['shell']=='/bin/sh\\x1b[31m'
    secret=jobs(b'PATH=/usr/bin:https://u:pw@x/token=abc\n* * * * * /bin/x\n')[0]
    assert 'pw@' not in secret['path'] and '[REDACTED]' in secret['path']


def cron(job):
    return {'format':'user','jobs':[job],'unparsed':0,'environment':0,'truncated':False}


OLD={'line':1,'schedule':'@daily','account':'alice','command':'/bin/x','redacted':False,'command_truncated':False,'stdin':False}
NEW=OLD|{'shell':None,'shell_truncated':False,'path':'/usr/bin','path_truncated':False}


def test_controller_accepts_old_and_new_agents():
    assert persistence.validate_cron(cron(OLD))==1
    assert persistence.validate_cron(cron(NEW))==1
    assert persistence.validate_cron(cron(NEW|{'path':''}))==1
    parsed=jobs(b'PATH=/usr/bin\n@daily /bin/x\n')[0]
    assert persistence.validate_cron(cron(parsed))==1


@pytest.mark.parametrize('job',[
    OLD|{'shell':None},
    NEW|{'path':1},
    NEW|{'shell':'x'*(agent.CRON_COMMAND_LIMIT+1)},
    NEW|{'path':'/bin\x00'},
    NEW|{'path_truncated':'no'},
    NEW|{'extra':1},
])
def test_controller_rejects_malformed_environment_fields(job):
    with pytest.raises(ValueError):persistence.validate_cron(cron(job))
