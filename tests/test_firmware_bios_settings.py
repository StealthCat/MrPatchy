import copy

from app import firmware_bios_settings as fb


def s(**kw):
    base = {'id': 'SecureBoot', 'type': 'enumeration', 'current': 'enabled',
            'allowed': ['enabled', 'disabled'], 'read_only': False}
    base.update(kw)
    return base


def test_redact_hides_sensitive_values_without_mutating():
    items = [s(), {'id': 'SupervisorPassword', 'type': 'string', 'current': 'hunter2'}]
    before = copy.deepcopy(items)
    out = fb.redact(items)
    assert items == before
    assert out[0]['current'] == 'enabled'
    assert out[1]['current'] == fb.REDACTED and out[1]['redacted'] is True
    assert 'hunter2' not in repr(out)


def test_validate_value_types_and_ranges():
    assert fb.validate_value(s(), 'enabled') is None
    assert fb.validate_value(s(), 'bogus') == 'not_allowed_value'
    assert fb.validate_value(s(), 1) == 'type_mismatch'
    i = {'type': 'integer', 'min': 1, 'max': 5}
    assert fb.validate_value(i, 3) is None
    assert fb.validate_value(i, 9) == 'out_of_range'
    assert fb.validate_value(i, True) == 'type_mismatch'
    assert fb.validate_value({'type': 'weird'}, 1) == 'unknown_type'


def test_drift_states_and_secret_not_echoed():
    items = [s(current='disabled', pending='enabled'),
             {'id': 'AdminToken', 'type': 'string', 'current': 'abc'}]
    rows = {r['id']: r for r in fb.drift(items, {'SecureBoot': 'enabled', 'AdminToken': 'zzz', 'Missing': 1})}
    assert rows['SecureBoot']['state'] == 'drifted' and rows['SecureBoot']['reboot_pending']
    assert rows['AdminToken']['state'] == 'drifted' and 'current' not in rows['AdminToken']
    assert rows['Missing']['state'] == 'unknown'
    assert fb.drift([s()], {'SecureBoot': 'enabled'})[0]['state'] == 'ok'


def test_preview_blocks_and_binds():
    assert fb.preview(s(), 'disabled', True)['state'] == 'ready'
    assert fb.preview(s(read_only=True), 'disabled', True)['reasons'] == ['setting_locked']
    assert 'missing_privileges' in fb.preview(s(), 'disabled', False)['reasons']
    assert fb.preview(s(), 'enabled', True)['reasons'] == ['no_change']
    assert 'not_allowed_value' in fb.preview(s(), 'x', True)['reasons']
    assert 'sensitive_setting_manual_only' in fb.preview(
        {'id': 'BiosPassword', 'type': 'string', 'current': ''}, 'a', True)['reasons']


def test_recheck_requires_rereview_on_change():
    bound = fb.preview(s(), 'disabled', True)
    assert fb.recheck(bound, s(), True)['state'] == 'ready'
    assert fb.recheck(bound, s(current='disabled'), True)['reasons'] == ['no_change']
    assert fb.recheck(bound, s(pending='disabled'), True)['reasons'] == ['setting_changed']
    assert fb.recheck(bound, s(locked=True), True)['state'] == 'rereview'
    assert fb.recheck(bound, s(), False)['state'] == 'rereview'
