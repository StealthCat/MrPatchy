"""Scoring idle fleets must use bounded SQL round trips, without changing eligibility."""
import hashlib
import time
import pytest
from sqlalchemy import event,select
from app import ai,ai_policy,ai_runs,update_scores
from app.db import Session,Host,Package,Setting,engine
from app.security import seal


def seed(count,state='complete',completed=None):
    now=time.time()
    with Session() as s:
        hosts=[Host(id='bulk-'+str(i),name='Fixture',address='192.0.2.1',fingerprint='',inventory={'os':'ID=debian\nVERSION_ID=12'}) for i in range(2)]
        s.add_all(hosts)
        s.merge(Setting(key='config',value={'ai_enabled':True,'ai_updates_enabled':True,'ai_model':'fixture','ai_control_mode':'unthrottled'}))
        s.merge(Setting(key='openai_key',value={'encrypted':seal('fixture-key')}))
        packages=[Package(id=hosts[i%2].id+':pkg'+str(i//2).zfill(4),host_id=hosts[i%2].id,name='pkg'+str(i//2).zfill(4),installed='1',candidate='2',available_since=now-10000+i) for i in range(count)]
        s.add_all(packages);s.flush()
        for i,p in enumerate(packages):
            if completed is not None and i>=completed:continue
            s.add(update_scores.UpdateScore(id=update_scores.identity(hosts[i%2],p),host_id=p.host_id,name=p.name,installed='1',candidate='2',state=state,score=50 if state=='complete' else None,attempted=now-7000,next_at=now+600 if state=='deferred' else 0))
        s.commit()
        return [p.id for p in packages]


def measure(monkeypatch):
    statements=[]
    def observe(conn,cursor,statement,parameters,context,executemany):
        if statement.lstrip().upper().startswith('SELECT'):statements.append(statement)
    monkeypatch.setattr(ai,'request',lambda *a,**k:pytest.fail('Completed/deferred fleet must not call provider'))
    event.listen(engine,'before_cursor_execute',observe)
    started=time.perf_counter()
    try:update_scores.run_one()
    finally:event.remove(engine,'before_cursor_execute',observe)
    return len(statements),time.perf_counter()-started


def capture_assessments(monkeypatch):
    sent=[]
    def assess(payload,key):
        import json
        batch=json.loads(payload['input']);sent.extend(batch)
        return {'assessments':[{'id':r['id'],'score':50,'confidence':'low','explanation':'Fixture','limitations':'No advisory verification'} for r in batch]}
    monkeypatch.setattr(ai,'request',assess)
    return sent


def test_candidate_host_reads_only_load_scoring_inputs(admin):
    expected_order=seed(450,completed=0)
    with Session() as s:
        host=s.get(Host,'bulk-1')
        host.inventory={'package_manager':'rpm','os':'ID=almalinux\nVERSION_ID=9',
            'rpm_packages':[{'name':'pkg0000','arch':'x86_64','evr':'0:1-1'}],
            'files':{'/etc/yum.repos.d/example.repo':'[example]\n'}}
        package=s.get(Package,'bulk-1:pkg0000')
        package.name='pkg0000:x86_64'
        package.id='bulk-1:'+package.name
        expected_order[1]=package.id
        s.commit()

    host_selects=[]
    def observe(conn,cursor,statement,parameters,context,executemany):
        if statement.startswith('SELECT hosts.'):
            host_selects.append(statement.partition('\n')[0].strip())

    with Session() as s:
        event.listen(engine,'before_cursor_execute',observe)
        try:
            candidates=list(update_scores.scoring_candidates(s))
        finally:
            event.remove(engine,'before_cursor_execute',observe)
        assert host_selects==['SELECT hosts.id, hosts.inventory'],host_selects
        assert [package.id for package,*_ in candidates]==expected_order
        full_hosts={host.id:host for host in s.scalars(select(Host))}
        for package,host,key,score,deferred in candidates:
            full_host=full_hosts[package.host_id]
            assert host.inventory == {field: full_host.inventory[field]
                                      for field in ('os', 'package_manager')
                                      if field in full_host.inventory}
            assert update_scores.evidence(host,package)==update_scores.evidence(full_host,package)
            assert key==update_scores.identity(full_host,package)
            assert score is None and not deferred
        rpm_package,rpm_host,*_=candidates[1]
        assert update_scores.evidence(rpm_host,rpm_package)['installed']==['0:1-1']


def test_scoring_memo_survives_unrelated_inventory_refresh(admin, monkeypatch):
    seed(2, completed=0)
    with Session() as session:
        rpm_host = session.get(Host, 'bulk-1')
        rpm_host.inventory = {
            'package_manager': 'rpm',
            'os': 'ID=almalinux\nVERSION_ID=9',
            'rpm_packages': [{'name': 'pkg0000', 'arch': 'x86_64', 'evr': '0:1-1'}],
            'files': {'/etc/yum.repos.d/example.repo': '[example]\n'},
            'collected': 1,
        }
        rpm_package = session.get(Package, 'bulk-1:pkg0000')
        rpm_package.name = 'pkg0000:x86_64'
        rpm_package.id = 'bulk-1:' + rpm_package.name
        for package in session.scalars(select(Package)):
            host = session.get(Host, package.host_id)
            session.add(update_scores.UpdateScore(
                id=update_scores.identity(host, package), host_id=host.id,
                name=package.name, installed=package.installed,
                candidate=package.candidate, state='complete', score=50,
            ))
        session.commit()

    def candidates():
        with Session() as session:
            return {host.id: (key, score.state if score else None)
                    for _, host, key, score, _ in update_scores.scoring_candidates(session)}

    monkeypatch.setattr(update_scores, '_MEMO', {})
    original = candidates()
    assert set(original) == {'bulk-0', 'bulk-1'}
    assert all(state == 'complete' for _, state in original.values())
    memo = update_scores._MEMO.copy()
    with Session() as session:
        rpm_host = session.get(Host, 'bulk-1')
        rpm_host.inventory = {
            **rpm_host.inventory,
            'files': {'/etc/yum.repos.d/example.repo': '[example]\n# refreshed\n'},
            'os': rpm_host.inventory['os'] + '\nUNUSED_FIELD=ignored',
            'collected': 2,
        }
        apt_host = session.get(Host, 'bulk-0')
        apt_host.inventory = {**apt_host.inventory, 'status': 'unrelated dpkg data', 'collected': 2}
        session.commit()

    with monkeypatch.context() as patch:
        def unexpected(*args):
            pytest.fail('Unrelated inventory changes must reuse the warm scoring memo')

        patch.setattr(update_scores, 'identity', unexpected)
        patch.setattr(update_scores, 'version_index', unexpected)
        assert candidates() == original
        assert all(update_scores._MEMO[host_id] is entry for host_id, entry in memo.items())

    for changes in (
        {'rpm_packages': [{'name': 'pkg0000', 'arch': 'x86_64', 'evr': '0:1-2'}]},
        {'os': 'ID=almalinux\nVERSION_ID=10'},
        {'package_manager': 'apt'},
    ):
        with Session() as session:
            host = session.get(Host, 'bulk-1')
            before = host.inventory
            host.inventory = {**before, **changes}
            expected = update_scores.identity(host, session.get(Package, 'bulk-1:pkg0000:x86_64'))
            session.commit()
        current = candidates()
        assert expected != original['bulk-1'][0]
        assert current == {**original, 'bulk-1': (expected, None)}
        with Session() as session:
            session.get(Host, 'bulk-1').inventory = before
            session.commit()
        assert candidates() == original


def test_scoring_memo_retains_warm_hosts_above_capacity(admin, monkeypatch):
    seed(402)
    monkeypatch.setattr(update_scores, '_MEMO', {})
    monkeypatch.setattr(update_scores, '_MEMO_HOSTS', 1)
    original_index = update_scores.version_index
    builds = 0

    def version_index(inventory):
        nonlocal builds
        builds += 1
        return original_index(inventory)

    monkeypatch.setattr(update_scores, 'version_index', version_index)

    def candidates():
        with Session() as session:
            rows = list(update_scores.scoring_candidates(session))
            assert all(score and score.state == 'complete' for _, _, _, score, _ in rows)
            return {package.id: key for package, _, key, _, _ in rows}

    original = candidates()
    assert len(original) == 402
    builds = 0
    assert candidates() == original
    assert builds == 1
    assert set(update_scores._MEMO) == {'bulk-0'}
    warm = update_scores._MEMO['bulk-0']

    with Session() as session:
        for package in session.scalars(select(Package).where(Package.host_id == 'bulk-1')):
            package.available_since = 1
        session.commit()
        # The first chunk contains only the overflow host. Closing the iterator
        # here must not drop the retained host that is still eligible.
        partial = update_scores.scoring_candidates(session)
        assert next(partial)[1].id == 'bulk-1'
        partial.close()
    assert update_scores._MEMO['bulk-0'] is warm

    with Session() as session:
        session.get(Host, 'bulk-0').enabled = False
        session.commit()
    remaining = {package_id: key for package_id, key in original.items()
                 if package_id.startswith('bulk-1:')}
    assert candidates() == remaining
    assert not update_scores._MEMO

    builds = 0
    assert candidates() == remaining
    assert set(update_scores._MEMO) == {'bulk-1'}
    assert builds == 1
    assert candidates() == remaining
    assert builds == 1


@pytest.mark.parametrize('count',[100,1000])
@pytest.mark.parametrize('state',['complete','deferred'])
def test_idle_fleet_selects_scale_by_chunks_not_packages(admin,monkeypatch,count,state):
    seed(count,state)
    queries,elapsed=measure(monkeypatch)
    print(f'{count} {state} candidates: {queries} SELECTs, {elapsed:.4f}s')
    assert queries<=12+4*((count+199)//200),f'{queries} SELECTs for {count} idle candidates'
    with Session() as s:
        rows=list(s.scalars(select(update_scores.UpdateScore)))
        assert len(rows)==count and all(r.state==state for r in rows)
        assert not list(s.scalars(select(ai_runs.AIRun)))


def test_complete_current_scores_still_supersede_changed_deferred_history(admin,monkeypatch):
    seed(450)
    with Session() as s:
        current=list(s.scalars(select(update_scores.UpdateScore)))
        for row in current:
            s.add(update_scores.UpdateScore(id=hashlib.sha256(('stale'+row.id).encode()).hexdigest(),host_id=row.host_id,name=row.name,installed='0',candidate='1',state='deferred',next_at=time.time()+10000))
        s.commit()
    queries,_=measure(monkeypatch)
    assert queries<30
    with Session() as s:
        rows=list(s.scalars(select(update_scores.UpdateScore)))
        assert sum(r.state=='complete' for r in rows)==450
        assert sum(r.state=='superseded' and r.next_at==0 for r in rows)==450


def test_scoring_candidate_queries_only_load_scheduling_fields(admin):
    seed(450)
    score_reads=[]
    def observe(conn,cursor,statement,parameters,context,executemany):
        if statement.startswith('SELECT update_scores.'):
            score_reads.append(statement.partition('\n')[0].strip())

    with Session() as s:
        event.listen(engine,'before_cursor_execute',observe)
        try:
            candidates=list(update_scores.scoring_candidates(s))
        finally:
            event.remove(engine,'before_cursor_execute',observe)
        assert len(score_reads)==6,score_reads
        fields=('id','host_id','name','state','attempted','next_at','configuration')
        projection='SELECT '+', '.join('update_scores.'+field for field in fields)
        assert all(statement==projection for statement in score_reads),score_reads[0]
        assert len(candidates)==450 and all(row.state=='complete' for _,_,_,row,_ in candidates)


@pytest.mark.parametrize('count,completed',[(513,505),(1000,0)])
def test_new_candidates_after_multiple_completed_chunks_keep_oldest_order_and_batch_limit(admin,monkeypatch,count,completed):
    ids=seed(count,completed=completed);sent=capture_assessments(monkeypatch)
    update_scores.run_one()
    with Session() as s:
        expected=[update_scores.identity(s.get(Host,s.get(Package,p).host_id),s.get(Package,p)) for p in ids[completed:completed+5]]
        assert [r['id'] for r in sent]==expected
        assert all(s.get(update_scores.UpdateScore,identifier).state=='complete' for identifier in expected)
        last=s.get(Package,ids[-1])
        assert s.get(update_scores.UpdateScore,update_scores.identity(s.get(Host,last.host_id),last)) is None


def test_due_deferred_items_across_chunk_boundaries_are_not_starved(admin,monkeypatch):
    ids=seed(513,'deferred');due=[199,200,399,400,512];expected=[]
    with Session() as s:
        for i in due:
            p=s.get(Package,ids[i]);key=update_scores.identity(s.get(Host,p.host_id),p)
            expected.append(key);s.get(update_scores.UpdateScore,key).next_at=time.time()-1
        s.commit()
    sent=capture_assessments(monkeypatch);update_scores.run_one()
    assert [row['id'] for row in sent]==expected
    with Session() as s:
        assert sum(row.state=='deferred' for row in s.scalars(select(update_scores.UpdateScore)))==508


@pytest.mark.parametrize('outcome', ['complete', 'superseded', 'deferred', 'error', 'blocked'])
def test_scoring_batch_links_and_persists_outcomes_with_bounded_reads(admin, monkeypatch, outcome):
    seed(5, completed=0)
    if outcome in ('complete', 'superseded'):
        capture_assessments(monkeypatch)
        if outcome == 'superseded':
            assess = ai.request

            def replace_candidates(*args, **kwargs):
                with Session() as session:
                    for package in session.scalars(select(Package)):
                        package.candidate = '3'
                    session.commit()
                return assess(*args, **kwargs)

            monkeypatch.setattr(ai, 'request', replace_candidates)
    else:
        def reject(*args, **kwargs):
            if outcome == 'deferred':
                raise ai.AIError('Fixture wait', policy_wait=True, retry_after=600)
            if outcome == 'error':  # transient without a retry delay keeps the hourly error retry
                raise ai.AIError('Fixture provider error', transient=True)
            raise ai.AIError('Fixture provider error')  # non-transient: blocked until model/key change

        monkeypatch.setattr(ai, 'request', reject)

    score_reads = []

    def observe(conn, cursor, statement, parameters, context, executemany):
        query = statement.lower()
        if 'from update_scores' in query and 'where update_scores.id ' in query:
            score_reads.append(query)

    event.listen(engine, 'before_cursor_execute', observe)
    try:
        update_scores.run_one()
    finally:
        event.remove(engine, 'before_cursor_execute', observe)

    with Session() as session:
        run = session.scalars(select(ai_runs.AIRun)).one()
        rows = session.scalars(select(update_scores.UpdateScore)).all()
        assert run.state == {'superseded': 'complete', 'blocked': 'error'}.get(outcome, outcome)
        assert len(rows) == 5
        assert {row.run_id for row in rows} == {run.id}
        assert {row.state for row in rows} == {outcome}
        assert {row.score for row in rows} == ({50} if outcome == 'complete' else {None})
        assert all((row.next_at > time.time()) == (outcome == 'deferred') for row in rows)

    # Candidate identity and persisted host scope are still read separately.
    assert len(score_reads) == 4
    assert all('where update_scores.id in (' in query for query in score_reads)


def test_equal_age_candidates_keep_id_tiebreak_order_across_chunks(admin,monkeypatch):
    seed(413,completed=405)
    with Session() as s:
        for p in s.scalars(select(Package)):p.available_since=1000
        s.commit()
        ordered=list(s.scalars(select(Package).order_by(Package.id)))
        expected=[]
        for p in ordered:
            key=update_scores.identity(s.get(Host,p.host_id),p)
            if not s.get(update_scores.UpdateScore,key):expected.append(key)
        expected=expected[:5]
    sent=capture_assessments(monkeypatch);update_scores.run_one()
    assert [row['id'] for row in sent]==expected


def test_paused_and_inactive_hosts_stay_out_of_scoring_and_stale_supersession(admin,monkeypatch):
    seed(450,'deferred')
    with Session() as s:
        s.add(Setting(key='server-ai:bulk-0',value={'paused':True}))
        s.get(Host,'bulk-1').enabled=False
        s.commit()
    measure(monkeypatch)
    with Session() as s:
        assert all(r.state=='deferred' for r in s.scalars(select(update_scores.UpdateScore)))
        assert ai_policy.status(s,'bulk-0')['paused']


@pytest.mark.parametrize("evidence_changed", [False, True])
def test_scoring_sends_indexed_rpm_versions_and_rechecks_live_inventory(admin, monkeypatch, evidence_changed):
    seed(2, completed=0)
    with Session() as session:
        host = session.get(Host, "bulk-1")
        host.inventory = {
            "package_manager": "rpm",
            "os": 'ID=almalinux\nVERSION_ID="9"\nPRETTY_NAME="Fixture"\nID=almalinux',
            "files": {"/etc/example.repo": "private fixture marker"},
            "rpm_packages": [
                {"name": "pkg0000", "arch": "x86_64", "evr": "0:1.1-1"},
                {"name": "pkg0000", "arch": "aarch64", "evr": "0:0.1-1"},
                {"name": "pkg0000", "arch": "x86_64", "evr": "0:1.0-1"},
                {"name": "pkg0000", "arch": "x86_64", "evr": "0:1.1-1"},
            ],
        }
        package = session.get(Package, "bulk-1:pkg0000")
        package.name = "pkg0000:x86_64"
        package.id = "bulk-1:" + package.name
        expected_key = update_scores.identity(host, package)
        expected = {"id": expected_key, **update_scores.evidence(host, package)}
        assert expected["installed"] == ["0:1.0-1", "0:1.1-1"]
        session.commit()

    sent = capture_assessments(monkeypatch)
    if evidence_changed:
        provider = ai.request

        def change_inventory(*args, **kwargs):
            with Session() as session:
                host = session.get(Host, "bulk-1")
                records = host.inventory["rpm_packages"]
                host.inventory = {
                    **host.inventory, "rpm_packages": [
                        {**records[0], "evr": "0:1.2-1"}, *records[1:],
                    ],
                }
                session.commit()
            return provider(*args, **kwargs)

        monkeypatch.setattr(ai, "request", change_inventory)

    update_scores.run_one()
    actual, = [item for item in sent if item["package"] == "pkg0000:x86_64"]
    assert actual == expected
    with Session() as session:
        score = session.get(update_scores.UpdateScore, expected_key)
        assert score.state == ("superseded" if evidence_changed else "complete")
