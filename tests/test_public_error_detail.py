import binascii
from app import ai,ai_runs,packages
from app.db import Session,Host


def test_source_rejection_shows_only_plain_validator_messages():
    assert packages.source_rejection(ValueError('Repository weakens signature verification'))=='Repository weakens signature verification'
    assert packages.source_rejection(ValueError('x'*5000))=='x'*1000
    assert packages.source_rejection(ValueError('two','args'))==packages.SOURCE_REJECTED
    assert packages.source_rejection(ValueError(object()))==packages.SOURCE_REJECTED
    assert packages.source_rejection(UnicodeDecodeError('utf-8',b'\xff secret',0,1,'invalid start byte'))==packages.SOURCE_REJECTED
    assert packages.source_rejection(binascii.Error('Incorrect padding near secret'))==packages.SOURCE_REJECTED


def test_ai_errors_expose_only_their_controlled_diagnostic():
    assert ai_runs.safe_error(ai.AIError('OpenAI model discovery timed out.'))=='OpenAI model discovery timed out.'
    assert ai_runs.safe_error(ai.AIError('y'*3000))=='y'*2000
    assert 'secret' not in ai_runs.safe_error(ai.AIError({'body':'secret'}))
    assert ai_runs.safe_error(RuntimeError('password=secret')).startswith('Internal RuntimeError during AI processing')


def test_repository_health_hides_unexpected_exception_text(admin,monkeypatch):
    with Session() as s:
        s.add(Host(id='health-host',name='Health',address='192.0.2.10',fingerprint='SHA256:'+'h'*43,state='online',
                   inventory={'package_manager':'apt','files':{'/etc/apt/sources.list':'deb [trusted=yes] https://example.org/debian stable main\n',
                                                               '/etc/apt/sources.list.d/other.list':'deb https://example.org/other stable main\n'}}))
        s.commit()
    health={item['path']:item for item in admin.get('/api/hosts/health-host/repositories').json()['health']}
    assert health['/etc/apt/sources.list']=={'path':'/etc/apt/sources.list','state':'blocked','detail':'Repository weakens signature verification'}
    real=packages.sources
    def failing(content,path,inv,access):
        if path.endswith('other.list'):raise binascii.Error('internal parser state: token=secret')
        return real(content,path,inv,access)
    monkeypatch.setattr(packages,'sources',failing)
    health={item['path']:item for item in admin.get('/api/hosts/health-host/repositories').json()['health']}
    assert health['/etc/apt/sources.list.d/other.list']['state']=='blocked'
    assert health['/etc/apt/sources.list.d/other.list']['detail']==packages.SOURCE_REJECTED
