import pytest
from sqlalchemy import event
from app.db import Session,Host
from app.ai_runs import AIRun,AIRunHost
from app.update_scores import UpdateScore
from app.identity import User


def test_history_reads_only_shared_membership_for_the_visible_page(admin):
    with Session() as s:
        for number, run_id in enumerate(('lookahead', 'empty', 'mixed', 'duplicates', 'legacy'), 1):
            s.add(AIRun(id=run_id, purpose='update_scoring', started=number))
        s.add_all([
            AIRunHost(run_id='mixed', host_id='a'),
            AIRunHost(run_id='lookahead', host_id='a'),
            AIRunHost(run_id='lookahead', host_id='b'),
        ])
        # Legacy links retain exact host IDs even under case-insensitive collations.
        for run_id, hosts in (
                ('mixed', ['a', 'b']), ('duplicates', ['a'] * 20), ('legacy', ['a', 'A'])):
            for number, host_id in enumerate(hosts):
                s.add(UpdateScore(id=f'{run_id}-{number}', host_id=host_id,
                    name=f'package-{number}', installed='1', candidate='2', run_id=run_id))
        s.commit()
        engine = s.get_bind()

    membership_reads = []

    def record(_conn, _cursor, statement, parameters, _context, _many):
        if 'FROM ai_run_hosts' in statement or 'FROM update_scores' in statement:
            membership_reads.append((statement, parameters))

    event.listen(engine, 'before_cursor_execute', record)
    try:
        response = admin.get('/api/ai/runs?purpose=update_scoring&limit=4')
    finally:
        event.remove(engine, 'before_cursor_execute', record)
    assert response.status_code == 200
    body = response.json()
    assert body['more'] is True
    assert [(item['id'], item['shared_batch']) for item in body['items']] == [
        ('legacy', True), ('duplicates', False), ('mixed', True), ('empty', False),
    ]
    assert len(membership_reads) == 1
    statement, parameters = membership_reads[0]
    assert 'HAVING' in statement and 'lookahead' not in parameters

    for run_id, shared in [('legacy', True), ('duplicates', False), ('mixed', True)]:
        detail = admin.get(f'/api/ai/runs/{run_id}')
        assert detail.status_code == 200
        assert detail.json()['shared_batch'] is shared


def test_detail_scope_direct_shared_legacy_and_unlinked(admin,monkeypatch):
    from app import ai,ssh
    monkeypatch.setattr(ai,'request',lambda *a,**k:pytest.fail('History must not call AI'))
    monkeypatch.setattr(ssh,'call',lambda *a,**k:pytest.fail('History must not contact targets'))
    with Session() as s:
        for host in ('a','b','c'):s.add(Host(id=host,name=host,address='192.0.2.1',fingerprint='',enabled=False))
        s.add_all([AIRun(id='direct',purpose='triage',host_id='a'),AIRun(id='shared',purpose='update_scoring'),AIRun(id='legacy',purpose='update_scoring')]);s.flush()
        s.add_all([AIRunHost(run_id='shared',host_id='a'),AIRunHost(run_id='shared',host_id='b'),UpdateScore(id='score',host_id='a',name='fixture',installed='1',candidate='2',run_id='legacy')]);s.commit()
    for run in ('direct','shared','legacy'):
        result=admin.get('/api/ai/runs/'+run+'?host_id=a');assert result.status_code==200
        assert result.json()['shared_batch']==(run=='shared')
        assert admin.get('/api/ai/runs/'+run+'?host_id=c').status_code==404
    assert admin.get('/api/ai/runs/shared?host_id=b').status_code==200
    assert admin.get('/api/ai/runs/shared?host_id=missing').status_code==404
    assert admin.get('/api/ai/runs/missing?host_id=a').status_code==404
    assert admin.get('/api/ai/runs/direct').status_code==200


@pytest.mark.parametrize('role',['viewer','operator'])
def test_detail_scope_requires_admin(admin,role):
    with Session() as s:s.get(User,'admin').role=role;s.commit()
    assert admin.get('/api/ai/runs/anything?host_id=a').status_code==403
