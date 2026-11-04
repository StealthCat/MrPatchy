"""Read-only forecasts must not promise starts while response reviews block them."""
import time
import pytest
from app import install_times, operations, quarantine, process_response, repair_publication, service_monitor, ssh
from app.db import Session, Job
from app.identity import User
from test_fleet_observability import NOW, host, pkg, schedule


KINDS=('file response','process response','replacement publication','service monitoring')


def hold(s,host_id,kind,identifier='response',held=True):
    common=dict(id=identifier,host_id=host_id,hold=held)
    if kind=='file response':
        row=quarantine.Quarantine(**common,incident_id='',archive_id='',fingerprint='',evidence_digest='',plan={})
    elif kind=='process response':
        row=process_response.ProcessResponse(**common,quarantine_id='',observation_id='',fingerprint='',plan={})
    elif kind=='replacement publication':
        row=repair_publication.Publication(**common,quarantine_id='',stage_id='',expires=NOW+3600,actor='fixture',reason='fixture',fingerprint='',stage_report_digest='',plan={},before_state='prepared',before_hold=False)
    else:
        row=service_monitor.Watch(**common,actor='fixture',reason='fixture',revision='fixture')
    s.add(row);s.flush();return row


@pytest.mark.parametrize('kind',KINDS)
@pytest.mark.parametrize('queued',[True,False],ids=['queued','scheduled'])
def test_hold_blocks_forecast_until_independent_release(admin,monkeypatch,kind,queued):
    monkeypatch.setattr(ssh,'call',lambda *a,**k:pytest.fail('Forecast must never contact the target'))
    with Session() as s:
        h=host(s,NOW);p=pkg(s,h);schedule(s,h)
        if queued:s.add(Job(id='patch',host_id=h.id,action='patch',payload={'packages':[p.name+'='+p.candidate]}))
        response=hold(s,h.id,kind)
        assert operations.host_quarantined(s,h.id)
        result=install_times.Planner(s,h,NOW).for_package(p)
        assert result['at'] is None and result['state']=='waiting',result
        assert kind in result['reason'].lower() and 'review' in result['reason'].lower()
        assert response.hold is True  # A forecast has no response/release authority.
        # Simulate the resulting local state of a separately authorized release.
        response.hold=False;s.flush()
        result=install_times.Planner(s,h,NOW).for_package(p)
        assert result['at']==(NOW if queued else NOW+7200)
        assert result['state']==('queued' if queued else 'scheduled')


@pytest.mark.parametrize('kind',KINDS)
def test_other_host_and_released_holds_do_not_block(admin,kind):
    with Session() as s:
        h=host(s,NOW);p=pkg(s,h);schedule(s,h)
        hold(s,'another-host',kind,identifier='foreign')
        hold(s,h.id,kind,identifier='released',held=False)
        assert install_times.Planner(s,h,NOW).for_package(p)['at']==NOW+7200


def test_each_remaining_review_is_explained_and_not_released_by_forecast(admin):
    with Session() as s:
        h=host(s,NOW);p=pkg(s,h);schedule(s,h)
        rows=[hold(s,h.id,kind,identifier=str(i)) for i,kind in enumerate(KINDS)]
        for i,row in enumerate(rows):
            result=install_times.Planner(s,h,NOW).for_package(p)
            assert result['at'] is None
            assert all(kind in result['reason'].lower() for kind in KINDS[i:])
            assert all(item.hold for item in rows[i:])
            row.hold=False;s.flush()
        assert install_times.Planner(s,h,NOW).for_package(p)['at']==NOW+7200


def test_running_patch_keeps_known_running_status_under_new_hold(admin):
    with Session() as s:
        h=host(s,NOW);p=pkg(s,h)
        s.add(Job(id='patch',host_id=h.id,action='patch',state='running',payload={'packages':[p.name+'='+p.candidate]}))
        hold(s,h.id,'file response')
        result=install_times.Planner(s,h,NOW).for_package(p)
        assert result['state']=='installing' and result['at'] is None


def test_unscheduled_hold_still_explains_required_review(admin):
    with Session() as s:
        h=host(s,NOW);p=pkg(s,h);hold(s,h.id,'service monitoring')
        result=install_times.Planner(s,h,NOW).for_package(p)
        assert result['state']=='waiting' and result['at'] is None
        assert 'service monitoring' in result['reason'].lower()


def test_other_running_work_and_recovery_still_have_unknown_start(admin):
    with Session() as s:
        h=host(s,NOW);p=pkg(s,h);schedule(s,h)
        other=Job(id='other',host_id=h.id,action='repair',state='running',payload={});s.add(other);s.flush()
        assert install_times.Planner(s,h,NOW).for_package(p)['at'] is None
        other.state='recovery_required';s.flush()
        assert install_times.Planner(s,h,NOW).for_package(p)['at'] is None


@pytest.mark.parametrize('kind',KINDS)
@pytest.mark.parametrize('role',['viewer','operator','admin'])
def test_packages_api_reports_hold_without_operational_side_effects(admin,monkeypatch,kind,role):
    monkeypatch.setattr(ssh,'call',lambda *a,**k:pytest.fail('Read-only package request contacted target'))
    with Session() as s:
        h=host(s,time.time());p=pkg(s,h)
        s.add(Job(id='patch',host_id=h.id,action='patch',payload={'packages':[p.name+'='+p.candidate]}))
        hold(s,h.id,kind)
        s.get(User,'admin').role=role;s.commit()
    result=admin.get('/api/hosts/host-a/packages?updates=true')
    assert result.status_code==200
    forecast=result.json()[0]['installation']
    assert forecast['state']=='waiting' and forecast['at'] is None
    assert kind in forecast['reason'].lower()
    with Session() as s:
        assert s.get(Job,'patch').state=='queued'
        assert operations.host_quarantined(s,'host-a')
