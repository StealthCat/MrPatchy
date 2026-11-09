from datetime import datetime, timezone
import pytest

from app import os_lifecycle


def ts(value):
    return datetime.fromisoformat(value).replace(tzinfo=timezone.utc).timestamp()


def inventory(os_release, architecture='amd64', collected='2026-11-04T12:00:00'):
    return {'os': os_release, 'architecture': architecture, 'collected': ts(collected)}


def test_exact_vendor_release_phases_and_provenance():
    now = ts('2026-11-04T13:00:00')
    ubuntu = os_lifecycle.evaluate(inventory('ID=ubuntu\nVERSION_ID="24.04"'), now, 7200)
    assert ubuntu['state'] == 'standard'
    assert ubuntu['release'] == '24.04'
    assert ubuntu['standard_until'] == '2029-05-31'
    assert ubuntu['source']['url'] == 'https://ubuntu.com/about/release-cycle'
    assert ubuntu['source']['reviewed'] == '2026-11-04'

    debian = os_lifecycle.evaluate(inventory('ID=debian\nVERSION_ID="12"'), now, 7200)
    assert debian['state'] == 'extended'
    assert debian['coverage'] == 'debian_lts'
    assert debian['extended_until'] == '2028-06-30'
    assert debian['coverage_gaps'] == []


def test_subscription_architecture_derivative_and_freshness_fail_closed():
    now = ts('2026-11-04T13:00:00')
    ubuntu = os_lifecycle.evaluate(inventory('ID=ubuntu\nVERSION_ID=20.04'), now, 7200)
    assert ubuntu['state'] == 'extended'
    assert ubuntu['coverage'] == 'subscription_required'
    assert ubuntu['coverage_gaps'] == ['Ubuntu Pro entitlement is not observed by this inventory.']

    debian = os_lifecycle.evaluate(inventory('ID=debian\nVERSION_ID=12', 's390x'), now, 7200)
    assert debian['state'] == 'unknown'
    assert debian['coverage'] == 'architecture_unverified'

    derivative = os_lifecycle.evaluate(inventory('ID=raspbian\nVERSION_ID=12'), now, 7200)
    assert derivative['state'] == 'unknown'
    assert derivative['coverage'] == 'unsupported_distribution'

    stale = os_lifecycle.evaluate(inventory('ID=ubuntu\nVERSION_ID=24.04', collected='2026-11-01T00:00:00'), now, 7200)
    assert stale['state'] == 'unknown'
    assert stale['coverage'] == 'stale_inventory'

    future = os_lifecycle.evaluate(inventory('ID=ubuntu\nVERSION_ID=24.04', collected='2026-11-05T00:00:00'), now, 7200)
    assert future['state'] == 'unknown'
    assert future['coverage'] == 'stale_inventory'


def test_boundaries_are_inclusive_and_ended_is_explicit():
    on_last_day = os_lifecycle.evaluate(
        inventory('ID=debian\nVERSION_ID=12', collected='2028-06-30T00:00:00'),
        ts('2028-06-30T12:00:00'), 86400)
    assert on_last_day['state'] == 'extended'

    ended = os_lifecycle.evaluate(
        inventory('ID=debian\nVERSION_ID=12', collected='2028-07-01T00:00:00'),
        ts('2028-07-01T12:00:00'), 86400)
    assert ended['state'] == 'ended'
    assert ended['coverage'] == 'vendor_ended'


@pytest.mark.parametrize('value',[float('nan'),float('inf'),float('-inf'),10**1000])
def test_nonfinite_or_out_of_range_time_is_unknown(value):
    inv=inventory('ID=debian\nVERSION_ID=12')
    now=ts('2026-11-04T13:00:00')
    assert os_lifecycle.evaluate({**inv,'collected':value},now,7200)['state']=='unknown'
    assert os_lifecycle.evaluate(inv,value,7200)['state']=='unknown'
    assert os_lifecycle.evaluate(inv,now,value)['state']=='unknown'


def test_debian_id_raspberry_pi_derivative_is_not_debian_vendor_coverage():
    inv=inventory('ID=debian\nVERSION_ID=12','arm64')
    now=ts('2026-11-04T13:00:00')
    for extra in ({'status':'Package: raspberrypi-sys-mods\n'},
                  {'files':{'/etc/apt/sources.list':'deb https://archive.raspberrypi.org/debian bookworm main'}}):
        assert os_lifecycle.evaluate({**inv,**extra},now,7200)['state']=='unknown'


def test_ambiguous_or_oversized_vendor_identity_is_not_asserted():
    now=ts('2026-11-04T13:00:00')
    for os in ('ID=debian\nID=raspbian\nVERSION_ID=12','ID='+('x'*60000)+'\nVERSION_ID=12'):
        report=os_lifecycle.evaluate(inventory(os),now,7200)
        assert report['state']=='unknown'
        assert len(report['vendor'] or '')<=80 and len(report['release'] or '')<=80
