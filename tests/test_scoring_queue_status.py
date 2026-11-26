"""Read-only update-importance scoring queue summary (#917)."""
import json
import time

import httpx
import pytest
from sqlalchemy import delete, event, select
from test_operations import login_as

from app import ai, ai_runs, scoring_queue_status, update_scores
from app.db import Host, Package, Session, Setting, config, engine
from app.security import seal

STATUS = '/api/update-scores/status'
HOSTS = ('ready', 'retry', 'deferred', 'expired', 'blocked', 'old-block', 'running', 'done', 'dupe', 'fresh')


def seed():
    now = time.time()
    with Session() as s:
        for index, host in enumerate(HOSTS + ('paused', 'disabled')):
            s.add(Host(id=host, name=host, address='192.0.2.1', fingerprint='', state='online',
                       enabled=host != 'disabled', inventory={'os': 'ID=debian\nVERSION_ID=12'}))
            s.add(Package(id=host + ':secret-package', host_id=host, name='secret-package', installed='1',
                          candidate='2', available_since=now - 7200 + index))
        s.merge(Setting(key='server-ai:paused', value={'paused': True}))
        s.merge(Setting(key='config', value={'ai_enabled': True, 'ai_updates_enabled': True,
                                              'ai_model': 'fixture-model', 'ai_control_mode': 'unthrottled'}))
        s.merge(Setting(key='openai_key', value={'encrypted': seal('private-key')}))
        s.commit()
        signature = update_scores.ai_retry.configuration_signature('fixture-model', s.get(Setting, 'openai_key').value)

        def score(host, state, key=None, **values):
            package = s.get(Package, host + ':secret-package')
            identity = key or update_scores.identity(s.get(Host, host), package)
            s.add(update_scores.UpdateScore(id=identity, host_id=host, name=package.name, installed='1', candidate='2',
                                            state=state, explanation='private provider text', **values))

        score('retry', 'error', attempted=now - 600)
        score('deferred', 'deferred', next_at=now + 900, attempted=now - 60)
        score('expired', 'deferred', next_at=now - 1, attempted=now - 60)
        score('blocked', 'blocked', configuration=signature, attempted=now - 60)
        score('old-block', 'blocked', configuration='earlier-signature', attempted=now - 60)
        score('running', 'running', attempted=now - 30)
        score('done', 'complete', attempted=now - 60, completed=now - 50)
        # A complete row from an earlier scoring context never masks the exact current row.
        score('dupe', 'complete', key='a' * 64, attempted=now - 60)
        score('dupe', 'error', attempted=now - 300)
        score('fresh', 'superseded', key='b' * 64, attempted=now - 60)
        s.commit()
    return now


def summary(now):
    with Session() as s:
        return scoring_queue_status.status(s, config(s), now)


def no_provider(*args, **kwargs):
    raise AssertionError('the scoring queue summary must not call a provider')


def test_each_current_update_is_classified_once_like_the_scheduler(admin, monkeypatch):
    monkeypatch.setattr(scoring_queue_status, 'CHUNK', 2)
    monkeypatch.setattr(ai.transport, 'post', no_provider)
    now = seed()
    result = summary(now)
    assert result['counts'] == {'eligible': 4, 'retry_wait': 2, 'deferred': 1, 'blocked': 1,
                                'running': 1, 'complete': 1}
    assert result['current_updates'] == 10 and result['unscored'] == 9
    # 'fresh' has only a superseded row and counts as eligible; paused and disabled servers stay out.
    assert result['paused_server_updates'] == 1
    assert result['scheduler'] == 'enabled'
    assert result['next_eligible_at'] == pytest.approx(now + 900)
    with Session() as s:
        oldest = s.get(Package, 'ready:secret-package').available_since
    assert result['oldest_waiting_since'] == pytest.approx(oldest)


def test_retry_wait_reports_the_hourly_retry_boundary(admin):
    now = seed()
    with Session() as s:
        for row in s.scalars(select(update_scores.UpdateScore).where(update_scores.UpdateScore.host_id == 'deferred')):
            row.next_at = now + 7200
        s.commit()
    assert summary(now)['next_eligible_at'] == pytest.approx(now - 600 + 3600)


def test_interrupted_scoring_attempt_enters_retry_wait_without_mutating_scores(admin):
    now = seed()
    attempted = now - 30
    with Session() as s:
        for row in s.scalars(select(update_scores.UpdateScore).where(
                update_scores.UpdateScore.state.in_(('error', 'deferred')))):
            row.state = 'complete'
        interrupted = s.scalar(select(update_scores.UpdateScore).where(update_scores.UpdateScore.host_id == 'running'))
        interrupted.run_id = 'interrupted'
        s.add(ai_runs.AIRun(id='interrupted', purpose='update_scoring', state='interrupted',
                           started=attempted + 1, finished=attempted + 2))
        s.add(ai_runs.AIRun(id='live', purpose='update_scoring', started=attempted + 1))
        for host, run_id, started in (('ready', 'live', attempted), ('fresh', 'interrupted', attempted + 3),
                                      ('paused', '', attempted), ('expired', '', attempted)):
            package = s.get(Package, host + ':secret-package')
            s.merge(update_scores.UpdateScore(
                id=update_scores.identity(s.get(Host, host), package), host_id=host, name=package.name,
                installed='1', candidate='2', state='running', attempted=started, run_id=run_id))
        interrupted_id = interrupted.id
        s.commit()

    result = summary(now)
    assert result['counts']['retry_wait'] == 1
    assert result['counts']['running'] == 3
    assert result['next_eligible_at'] == pytest.approx(attempted + 3600)
    expired = summary(attempted + 3600)
    assert expired['counts']['retry_wait'] == 0
    assert expired['counts']['eligible'] == result['counts']['eligible'] + 3
    with Session() as s:
        row = s.get(update_scores.UpdateScore, interrupted_id)
        assert (row.state, row.run_id, row.attempted) == ('running', 'interrupted', attempted)


def test_eligible_updates_are_exactly_the_ones_the_scheduler_sends(admin, monkeypatch):
    now = seed()
    sent = []

    def success(*args, **kwargs):
        items = json.loads(kwargs['json']['input'])
        sent.extend(items)
        result = {'assessments': [{'id': item['id'], 'score': 50, 'confidence': 'low',
                                   'explanation': 'Bounded fixture assessment.', 'limitations': 'None.'}
                                  for item in items]}
        return httpx.Response(200, json={'status': 'completed', 'output': [{'content': [
            {'type': 'output_text', 'text': json.dumps(result)}]}]}, request=httpx.Request('POST', ai.URL))

    monkeypatch.setattr(ai.transport, 'post', success)
    monkeypatch.setattr(update_scores.time, 'time', lambda: now)
    assert summary(now)['counts']['eligible'] == 4
    update_scores.run_one()
    with Session() as s:
        hosts = {row.host_id for row in s.scalars(select(update_scores.UpdateScore).where(
            update_scores.UpdateScore.id.in_([item['id'] for item in sent])))}
    assert hosts == {'ready', 'expired', 'old-block', 'fresh'}
    after = summary(now)['counts']
    assert after['eligible'] == 0 and after['complete'] == 5


@pytest.mark.parametrize('change', ['held', 'priority', 'os'])
def test_context_change_counts_as_eligible_exactly_when_the_scheduler_rescores(admin, monkeypatch, change):
    # Peer review on #920: a context-only change leaves the old complete row in place,
    # but the scheduler binds a new identity and rescores the update.
    now = seed()
    with Session() as s:
        package = s.get(Package, 'done:secret-package')
        if change == 'held':
            package.held = not package.held
        elif change == 'priority':
            package.priority, package.priority_manual = 'security', True
        else:
            host = s.get(Host, 'done')
            host.inventory = {**host.inventory, 'os': 'ID=debian\nVERSION_ID=13'}
        s.commit()
    result = summary(now)['counts']
    assert result['complete'] == 0 and result['eligible'] == 5
    sent = []

    def capture(*args, **kwargs):
        sent.extend(item['id'] for item in json.loads(kwargs['json']['input']))
        raise httpx.ConnectError('fixture stops after capture')

    monkeypatch.setattr(ai.transport, 'post', capture)
    monkeypatch.setattr(update_scores.time, 'time', lambda: now)
    update_scores.run_one()
    with Session() as s:
        hosts = {row.host_id for row in s.scalars(select(update_scores.UpdateScore).where(
            update_scores.UpdateScore.id.in_(sent)))}
    assert len(set(sent)) == 5 and hosts == {'ready', 'expired', 'old-block', 'fresh', 'done'}


def test_summary_leaves_the_scheduler_memo_and_score_rows_untouched(admin, monkeypatch):
    monkeypatch.setattr(update_scores, 'cached_identity',
                        lambda *_: pytest.fail('One-pass status must not memoize package identities'))
    now = seed()
    with Session() as s:
        before = {row.id: (row.state, row.attempted, row.next_at) for row in s.scalars(select(update_scores.UpdateScore))}
    memo = dict(update_scores._MEMO)
    summary(now)
    assert update_scores._MEMO == memo
    with Session() as s:
        assert before == {row.id: (row.state, row.attempted, row.next_at)
                          for row in s.scalars(select(update_scores.UpdateScore))}


def test_payload_is_counts_only_and_admin_only(client):
    seed()
    login_as(client, 'reader', 'viewer')
    assert client.get(STATUS).status_code == 403
    client.post('/api/logout')
    login_as(client, 'ops', 'operator')
    assert client.get(STATUS).status_code == 403


def test_admin_endpoint_reports_counts_without_private_data(admin):
    seed()
    reply = admin.get(STATUS)
    assert reply.status_code == 200
    body = reply.json()
    text = json.dumps(body)
    for private in ('secret-package', 'private provider text', 'private-key', 'ready', 'fixture-model'):
        assert private not in text
    assert body['counts']['eligible'] == 4
    # The exact-identity pass runs only on this endpoint, not on every Settings load.
    assert 'ai_scoring_queue' not in admin.get('/api/settings').json()


@pytest.mark.parametrize('key_present', [True, False])
def test_queue_state_and_blocked_counts_use_one_saved_key(admin, key_present):
    seed()
    with Session() as session:
        saved_key = session.get(Setting, 'openai_key').value
        if not key_present:
            session.execute(delete(Setting).where(Setting.key == 'openai_key'))
            session.commit()

    reads = []
    sqlite = engine.dialect.name == 'sqlite'

    def observe(_connection, _cursor, statement, _parameters, context, _many):
        if not statement.lstrip().startswith('SELECT') or 'FROM settings' not in statement:
            return
        if not any('openai_key' in row.values() for row in context.compiled_parameters):
            return
        reads.append(statement)
        if sqlite and len(reads) == 1:
            # Change the stored key after the first read. This response must
            # use the same key observation for both the counts and the badge.
            with Session() as writer:
                if key_present:
                    writer.execute(delete(Setting).where(Setting.key == 'openai_key'))
                else:
                    writer.add(Setting(key='openai_key', value=saved_key))
                writer.commit()

    event.listen(engine, 'after_cursor_execute', observe)
    try:
        reply = admin.get(STATUS)
    finally:
        event.remove(engine, 'after_cursor_execute', observe)
    assert reply.status_code == 200
    result = reply.json()
    assert (result['scheduler'], result['counts']['blocked']) == (
        ('enabled', 1) if key_present else ('not_configured', 0)
    )
    assert len(reads) == 1

    if sqlite:
        refreshed = admin.get(STATUS)
        assert refreshed.status_code == 200
        result = refreshed.json()
        assert (result['scheduler'], result['counts']['blocked']) == (
            ('not_configured', 0) if key_present else ('enabled', 1)
        )


@pytest.mark.parametrize('changes, state', [({'ai_enabled': False}, 'ai_disabled'),
                                            ({'ai_updates_enabled': False}, 'scoring_disabled'),
                                            ({'ai_model': ''}, 'not_configured')])
def test_scheduler_state_explains_why_nothing_starts(admin, changes, state):
    now = seed()
    with Session() as s:
        row = s.get(Setting, 'config')
        row.value = {**row.value, **changes}
        s.commit()
    result = summary(now)
    assert result['scheduler'] == state
    if changes.get('ai_model') == '':
        # Without a saved signature no row counts as blocked under it.
        assert result['counts']['blocked'] == 0
