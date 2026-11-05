from app import firmware_inventory as fw

NOW = 1_800_000_000.0


def dev(**kw):
    base = {'DeviceId': 'abc', 'Guid': ['g1'], 'Name': 'UEFI', 'Version': '1.0',
            'Flags': ['updatable', 'internal'], 'Serial': 'SN123'}
    base.update(kw)
    return base


def result(devices, updates=None, **kw):
    r = {'tool_present': True, 'devices': {'Devices': devices},
         'updates': updates, 'observed_at': NOW - 60, 'catalog_refreshed_at': NOW - 60}
    r.update(kw)
    return r


def classify(r):
    return fw.classify_collection(r, now=NOW)


def test_missing_tool_and_malformed_are_never_healthy():
    assert classify({'tool_present': False})['status'] == 'missing_tool'
    assert classify({'tool_present': True, 'devices': None})['status'] == 'collection_failed'
    assert classify({'tool_present': True, 'devices': {'Devices': 'x'}})['status'] == 'collection_failed'
    assert classify('junk')['status'] == 'collection_failed'
    for r in (classify({'tool_present': False}), classify(result([]))):
        assert r['status'] not in fw.HEALTHY_STATUSES


def test_empty_device_list_is_no_vendor_support():
    assert classify(result([], updates={'Devices': []}))['status'] == 'no_vendor_support'


def test_update_available_from_update_listing_only():
    hist = {'Releases': [{'Version': '2.0'}]}  # historical, not an upgrade
    r = classify(result([dev(**hist)], updates={'Devices': []}))
    assert r['status'] == 'no_matching_release'
    up = {'Devices': [dev(Releases=[{'Version': '2.0', 'Checksum': ['sha1']}])]}
    r = classify(result([dev()], updates=up))
    assert r['status'] == 'update_available'
    assert r['devices'][0]['status'] == 'update_available'


def test_verified_current_requires_fresh_catalog_listing_installed_version():
    cur = dev(Releases=[{'Version': '1.0'}])
    assert classify(result([cur], updates={'Devices': []}))['status'] == 'verified_current'
    stale = result([cur], updates={'Devices': []}, catalog_refreshed_at=NOW - 10**8)
    assert classify(stale)['status'] == 'no_matching_release'
    unknown_updates = result([cur], updates=None)
    assert classify(unknown_updates)['status'] == 'stale_unknown'


def test_blocked_requirements_and_stale_and_unreachable():
    up = {'Devices': [dev(Releases=[{'Version': '2.0', 'Flags': ['blocked-version']}])]}
    assert classify(result([dev()], updates=up))['status'] == 'blocked_requirements'
    assert classify(result([dev()], updates=up, observed_at=NOW - 10**8))['status'] == 'stale_unknown'
    assert classify(result([dev(Flags=['unreachable'])], updates={'Devices': []}))['status'] == 'disconnected'
    assert classify(result([dev(Flags=['internal'])], updates={'Devices': []}))['status'] == 'no_vendor_support'


def test_unknown_fields_ignored_and_bounds_applied():
    d = fw.normalize_device(dev(Surprise={'x': 1}, Guid=['g'] * 100 + [f'h{i}' for i in range(100)]))
    assert 'Surprise' not in d and len(d['guids']) <= fw.MAX_GUIDS
    assert fw.normalize_device({'Name': 'no identity'}) is None
    assert fw.normalize_device('x') is None
    assert fw.normalize_release({'Summary': 'no version'}) is None


def test_serial_redacted_by_default():
    assert 'serial' not in fw.normalize_device(dev())
    assert fw.normalize_device(dev(), include_private=True)['serial'] == 'SN123'


def test_reconcile_does_not_transfer_identity():
    devices = [fw.normalize_device(dev(DeviceId='new'))]
    assert fw.reconcile_disconnected({'abc'}, devices) == {'abc'}


def test_capabilities_explicit():
    caps = fw.provider_capabilities('fwupd')
    assert set(caps) == set(fw.OPERATIONS)
    assert caps['enumerate'] and not caps['execute'] and not caps['settings']
    assert not any(fw.provider_capabilities('unknown').values())
