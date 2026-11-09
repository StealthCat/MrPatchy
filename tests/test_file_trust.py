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
        host = Host(id='one', name='One', address='192.0.2.1', fingerprint='')
        source = retained();s.add(source);known_good.publish(s, source)
        behavior = Behavior(id='new', host_id='one', evidence=complete(), verdict='low', analysis='safe')
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
