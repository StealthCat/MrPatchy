import time
from sqlalchemy import select, func
from app import file_status, file_trust, incidents
from app.db import Session, Host, Audit
from app.incidents import Inspection
from test_file_status import setup, report, PATH, HASH


def test_signed_match_is_stored_once_and_get_is_read_only(client):
    setup()
    with Session() as s:
        host = s.get(Host, 'host-one')
        assert not any(row.get('trusted') for row in file_status.page(s, host)['items'])
        assert s.scalar(select(func.count()).select_from(file_trust.Trust)) == 0
        file_trust.record_snapshot(s, host)
        file_trust.record_snapshot(s, host)
        s.commit()
    with Session() as s:
        assert s.scalar(select(func.count()).select_from(file_trust.Trust)) == 1
        item = next(x for x in file_status.page(s, s.get(Host, 'host-one'))['items'] if x['path'] == PATH)
        assert item['trusted'] and item['trust_source'] == 'authenticated_repository'
        assert s.scalar(select(func.count()).select_from(Audit).where(
            Audit.action == 'automatically trust file')) == 1


def test_previous_match_cross_host_and_newer_mismatch(client):
    setup()
    with Session() as s:
        file_trust.record_snapshot(s, s.get(Host, 'host-one'))
        result = file_trust.assess(s, 'second', PATH, HASH, {})
        assert result['trusted'] and result['method'] == 'known_good_database'
        assert not file_trust.assess(s, 'second', PATH, 'f'*64, {}).get('trusted')
        # A local authenticated mismatch takes precedence over history elsewhere.
        mismatch = {PATH: {**file_status.repositories(s, 'host-one')[PATH], 'expected_sha256': 'f'*64}}
        assert file_trust.assess(s, 'second', PATH, HASH, mismatch)['status'] == 'changed'
        s.add(Inspection(id='newer', host_id='host-one', created=time.time()+1, report=report('f'*64)))
        s.flush()
        assert not file_trust.assess(s, 'second', PATH, HASH, {}).get('trusted')
        # Deleting the origin must not leave a self-sustaining chain of trust.
        s.delete(s.get(Inspection, 'vendor-one'));s.delete(s.get(Inspection, 'newer'));s.flush()
        assert not file_trust.assess(s, 'third', PATH, HASH, {}).get('trusted')


def test_unverified_observation_never_seeds_trust(client):
    setup()
    with Session() as s:
        for path, checksum in [(PATH, None), (PATH, 'bogus'), ('/unknown', HASH), (None, HASH)]:
            assert not file_trust.assess(s, 'empty', path, checksum, {}).get('trusted')
        assert s.scalar(select(func.count()).select_from(file_trust.Trust)) == 0


def test_cross_host_rechecks_only_the_requested_origin_path(client, monkeypatch):
    setup()
    with Session() as s:
        file_trust.record_snapshot(s, s.get(Host, 'host-one'))
        s.commit()

    unrelated = report()
    unrelated['vendor_manifest']['entries'][0]['path'] = PATH.upper()
    unrelated['vendor_authentication']['bundle_id'] = 'unrelated'
    checked = []
    validate = file_status.vendor.validate_authenticated

    def counted(manifest, proof, receipt):
        checked.append(proof['bundle_id'])
        return validate(manifest, proof, receipt)

    monkeypatch.setattr(file_status.vendor, 'validate_authenticated', counted)
    with Session() as s:
        s.add(Inspection(id='unrelated', host_id='host-one', created=time.time()+1,
                         report=unrelated))
        s.commit()
        result = file_trust.assess(s, 'second', PATH, HASH, {})
        assert result['trusted'] and result['method'] == 'known_good_database'
        assert checked == ['fixture']


def test_authenticated_inspection_stores_without_ai(client):
    with Session() as s:
        receipt = report();receipt.update(version=1, state='collected', packages=[], persistence=None)
        incidents.record_inspection(s, 'one', 'receipt', receipt, vendor_authenticated=True)
        s.commit()
    with Session() as s:
        saved = s.scalar(select(file_trust.Trust))
        assert saved.sha256 == HASH and saved.reference == {'host_id': 'one', 'inspection_id': 'receipt'}


def test_contextual_known_good_trust_is_stored_but_revocation_wins(client):
    from app import ai_assessments, known_good
    from app.db import Behavior
    from test_known_good import complete, retained
    with Session() as s:
        host = Host(id='host-one', name='One', address='192.0.2.1', fingerprint='')
        source = retained();s.add(source);known_good.publish(s, source)
        behavior = Behavior(id='new', host_id='host-one', evidence=complete(), verdict='low', analysis='safe')
        s.add_all([host, behavior]);s.flush()
        hit = known_good.lookup(s, behavior.evidence, source.model, [source.policy_hash])
        assessment = ai_assessments.record_reuse(s, behavior, hit)
        known_good.link_reuse(s, assessment, hit)
        file_trust.record_reuse(s, behavior, assessment, hit);s.commit()
        assert file_status.page(s, host)['items'][0]['trusted']
        assert not behavior.approved
        entry = s.get(known_good.Entry, hit['fingerprint']);entry.active=False;s.commit()
        assert not file_status.page(s, host)['items'][0].get('trusted')
        assert s.scalar(select(func.count()).select_from(file_trust.Trust)) == 1


def test_duplicate_observation_from_concurrent_writer_resolves_winner(client):
    """Session A's snapshot predates B's commit; retain must still return B's row."""
    reference = {'host_id': 'one', 'inspection_id': 'receipt'}
    key = file_trust.identity('one', PATH, HASH, 'authenticated_repository', reference)
    with Session() as a:
        assert a.get(file_trust.Trust, key) is None  # establishes A's read snapshot
        with Session() as b:
            file_trust.retain(b, 'one', PATH, HASH, 'authenticated_repository', reference)
            b.commit()
        row = file_trust.retain(a, 'one', PATH, HASH, 'authenticated_repository', reference)
        assert row is not None and row.id == key and row.reference == reference
        a.commit()
    with Session() as s:
        assert s.scalar(select(func.count()).select_from(file_trust.Trust)) == 1
        assert s.scalar(select(func.count()).select_from(Audit).where(
            Audit.action == 'automatically trust file')) == 1


def test_integrity_error_fallback_uses_current_read(client, monkeypatch):
    reference = {'host_id': 'one', 'inspection_id': 'receipt'}
    with Session() as b:
        winner = file_trust.retain(b, 'one', PATH, HASH, 'authenticated_repository', reference)
        b.commit()
        key = winner.id
    calls = []
    with Session() as a:
        original = a.get

        def stale_get(entity, ident, **kw):
            calls.append(kw)
            # Simulate a REPEATABLE READ snapshot: plain reads miss the winner.
            return original(entity, ident, **kw) if kw.get('with_for_update') else None
        monkeypatch.setattr(a, 'get', stale_get)
        row = file_trust.retain(a, 'one', PATH, HASH, 'authenticated_repository', reference)
        assert row.id == key and calls[-1].get('with_for_update')
        a.commit()
    with Session() as s:
        assert s.scalar(select(func.count()).select_from(file_trust.Trust)) == 1
        assert s.scalar(select(func.count()).select_from(Audit).where(
            Audit.action == 'automatically trust file')) == 1


def test_exact_path_is_not_crowded_out_by_newer_same_hash_paths(client):
    others = [f'/usr/lib/fixture/f{n:03}' for n in range(100)]
    receipt = report()
    receipt['vendor_manifest']['entries'] += [{'path': p, 'sha256': HASH, 'size': 4} for p in others]
    receipt['vendor_verification'].update(examined=101, scope_files=101)
    with Session() as s:
        s.add(Inspection(id='wide', host_id='origin', report=receipt));s.flush()
        proofs = file_status.repositories(s, 'origin')
        assert file_trust.assess(s, 'origin', PATH, HASH, proofs).get('trusted')
        for n, other in enumerate(others):
            row = file_trust.retain(s, 'origin', other, HASH, 'authenticated_repository',
                                    {'host_id': 'origin', 'inspection_id': 'wide'})
            row.created = time.time() + 10 + n
        s.flush()
        result = file_trust.assess(s, 'second', PATH, HASH, {})
        assert result['status'] == 'known_good' and result.get('trusted')
        # Case-distinct POSIX paths stay distinct identities on every database.
        assert file_trust.assess(s, 'third', PATH.upper(), HASH, {})['status'] == 'unassessed'


def test_older_snapshot_cannot_restore_trust_after_newer_same_artifact_mismatch(client):
    setup()
    with Session() as s:
        host = s.get(Host, 'host-one')
        host.telemetry = {**host.telemetry, 'hashed_at': time.time()}
        file_trust.record_snapshot(s, host);s.flush()
        assert file_trust.assess(s, 'second', PATH, HASH, {})['status'] == 'known_good'
        mismatch = report()
        mismatch['vendor_verification'].update(state='differences', findings=[{
            'path': PATH, 'status': 'content_differs', 'expected_sha256': HASH, 'observed_sha256': 'f'*64}])
        s.add(Inspection(id='mismatch', host_id='host-one', created=time.time()+5, report=mismatch))
        s.flush()
        assert file_trust.assess(s, 'second', PATH, HASH, {})['status'] == 'unassessed'
        # The origin's existing, older telemetry is processed again.
        file_trust.record_snapshot(s, host);s.flush()
        assert not [row for row in s.scalars(select(file_trust.Trust))
                    if row.reference.get('inspection_id') == 'mismatch']
        assert not file_trust.assess(s, 'third', PATH, HASH, {}).get('trusted')
        # Target clocks are not comparable to the receipt time: even a sweep
        # stamped well after the mismatch (e.g. 45s clock skew) cannot restore trust.
        host.telemetry = {**host.telemetry, 'hashed_at': time.time()+60}
        file_trust.record_snapshot(s, host);s.flush()
        assert not file_trust.assess(s, 'fourth', PATH, HASH, {}).get('trusted')
        # A newer authenticated matching inspection restores eligibility.
        s.add(Inspection(id='rematch', host_id='host-one', created=time.time()+20, report=report()))
        s.flush()
        file_trust.record_snapshot(s, host);s.flush()
        assert file_trust.assess(s, 'fifth', PATH, HASH, {}).get('trusted')
