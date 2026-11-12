from app import rpi_eeprom as rpi

NOW = 1_800_000_000.0
UP = """BOOTLOADER: up to date
   CURRENT: Thu 29 Apr 2021 04:11:25 PM UTC (1619712685)
    LATEST: Thu 29 Apr 2021 04:11:25 PM UTC (1619712685)
   RELEASE: default (/lib/firmware/raspberrypi/bootloader/default)

  VL805_FW: Using bootloader EEPROM
     VL805: up to date
   CURRENT: 000138a1
    LATEST: 000138a1
"""


def res(output=UP, **kw):
    r = {'tool_present': True, 'exit_code': 0, 'output': output, 'observed_at': NOW - 60}
    r.update(kw)
    return r


def cls(r):
    return rpi.classify_collection(r, now=NOW)


def test_up_to_date_is_only_healthy_case():
    c = cls(res())
    assert c['status'] == 'verified_current' and c['healthy']
    assert not c['release_requires_review']


def test_update_available_by_epoch_and_text():
    newer = UP.replace('LATEST: Thu 29 Apr 2021 04:11:25 PM UTC (1619712685)',
                       'LATEST: Fri 01 Jan 2027 00:00:00 AM UTC (1819712685)')
    assert cls(res(newer))['status'] == 'update_available'
    assert cls(res('BOOTLOADER: update available\n', exit_code=1))['status'] == 'update_available'


def test_pending_update_awaits_reboot():
    out = UP + '*** UPDATE PENDING: reboot to apply ***\n'
    c = cls(res(out))
    assert c['status'] == 'pending_reboot' and not c['healthy']


def test_never_healthy_when_missing_empty_failed_or_stale():
    assert cls({'tool_present': False})['status'] == 'missing_tool'
    assert cls('junk')['status'] == 'missing_tool'
    for r in (res(''), res('garbage'), res(exit_code=None), res(exit_code=127),
              res(timed_out=True), res(exit_code=True)):
        c = cls(r)
        assert c['status'] == 'collection_failed' and not c['healthy']
    stale = cls(res(observed_at=NOW - 30 * 86400))
    assert stale['status'] == 'stale_unknown' and not stale['healthy']
    assert cls(res(observed_at=None))['status'] == 'stale_unknown'


def test_unsupported_model():
    c = cls(res('rpi-eeprom-update: this model does not have a boot EEPROM\n', exit_code=1))
    assert c['status'] == 'unsupported_model' and not c['healthy']


def test_experimental_release_stream_requires_review():
    out = UP.replace('RELEASE: default', 'RELEASE: latest')
    c = cls(res(out))
    assert c['release_requires_review'] is True
    assert cls(res(UP.replace('RELEASE: default', 'RELEASE: critical')))['release_requires_review'] is False


def test_vl805_timestamps_do_not_decide_bootloader():
    out = UP.replace('LATEST: 000138a1', 'LATEST: 000138ff (1999999999)')
    assert cls(res(out))['status'] == 'verified_current'


def test_service_state_reported_not_changed_and_no_execute_capability():
    assert cls(res(service_active=True))['auto_update_service_active'] is True
    assert cls(res(service_active='yes'))['auto_update_service_active'] is None
    caps = rpi.provider_capabilities()
    assert caps['status'] and not any(caps[k] for k in ('stage', 'execute', 'recovery', 'settings'))


def test_output_is_bounded():
    assert rpi.parse_status('x' * 10**6 + '\nBOOTLOADER: up to date')['bootloader_state'] is None
