from app import firmware_policy as fp

NOW = 1_000_000.0


def layers(*ls):
    return list(ls)


def test_narrower_scope_wins_and_sources_recorded():
    p = fp.resolve_effective_policy(layers(
        {'scope': 'fleet', 'min_version': '1.2'},
        {'scope': 'host:a', 'min_version': '1.5'}), NOW)
    assert p['min_version'] == '1.5' and p['sources']['min_version'] == 'host:a'


def test_exclusion_is_sticky_and_unknown_version_never_meets_minimum():
    p = fp.resolve_effective_policy(layers(
        {'scope': 'fleet', 'excluded': True},
        {'scope': 'host', 'excluded': False}), NOW)
    assert fp.evaluate_device(p, '9.9', NOW)['state'] == 'excluded'
    q = fp.resolve_effective_policy(layers({'scope': 'f', 'min_version': '1.0'}), NOW)
    assert fp.evaluate_device(q, 'weird-build', NOW)['state'] == 'unknown_version'
    assert fp.evaluate_device(q, None, NOW)['compliant'] is False
    assert fp.evaluate_device(q, '1.0.0', NOW)['compliant'] is True
    assert fp.evaluate_device(q, '0.9.9', NOW)['reasons'] == ['below_minimum']


def test_no_requirement_and_conflicts_are_never_compliant():
    assert fp.evaluate_device(fp.resolve_effective_policy([], NOW), '1.0', NOW)['compliant'] is False
    p = fp.resolve_effective_policy(layers(
        {'scope': 'f', 'min_version': '2.0', 'pin_version': '1.0'}), NOW)
    assert 'pin_below_minimum' in p['conflicts']
    assert fp.evaluate_device(p, '2.0', NOW)['compliant'] is False


def test_exceptions_must_expire_and_deferral_expires():
    p = fp.resolve_effective_policy(layers(
        {'scope': 'f', 'min_version': '2.0', 'exception': {'reason': 'x'}}), NOW)
    assert p['exception'] is None
    live = fp.resolve_effective_policy(layers(
        {'scope': 'f', 'min_version': '2.0',
         'exception': {'expires_at': NOW + 10, 'reason': 'vendor bug'}}), NOW)
    assert fp.evaluate_device(live, '1.0', NOW)['state'] == 'excepted'
    assert fp.evaluate_device(live, '1.0', NOW + 11)['reasons'][0] == 'exception_expired'
    d = fp.resolve_effective_policy(layers(
        {'scope': 'f', 'min_version': '2.0', 'deferred_until': NOW + 5}), NOW)
    assert fp.evaluate_device(d, '1.0', NOW)['state'] == 'deferred'
    assert fp.evaluate_device(d, '1.0', NOW + 6)['state'] == 'noncompliant'


def _opt(**kw):
    base = {'enabled': True, 'devices': ['d1'], 'actions': ['install'],
            'releases': ['r1'], 'expires_at': NOW + 100}
    base.update(kw)
    return base


def test_unattended_requires_bounded_unexpired_scope_and_is_not_inherited():
    pol = fp.resolve_effective_policy(layers({'scope': 'f', 'unattended': _opt()}), NOW)
    assert fp.authorize_unattended(pol, 'd1', 'install', 'r1', NOW)['allowed']
    for args, blocker in ((('d2', 'install', 'r1'), 'device_not_in_scope'),
                          (('d1', 'stage', 'r1'), 'action_not_in_scope'),
                          (('d1', 'install', 'r2'), 'release_not_in_scope')):
        assert blocker in fp.authorize_unattended(pol, *args, NOW)['blockers']
    assert 'opt_in_expired' in fp.authorize_unattended(pol, 'd1', 'install', 'r1', NOW + 200)['blockers']
    for bad in (_opt(devices=[]), _opt(releases=[]), _opt(expires_at=None), _opt(actions=['flash'])):
        p = fp.resolve_effective_policy(layers({'scope': 'f', 'unattended': bad}), NOW)
        assert not fp.authorize_unattended(p, 'd1', 'install', 'r1', NOW)['allowed']
    # a narrower layer without its own opt-in does not restore a broader one
    # only when it explicitly declares unattended; absence inherits nothing extra
    off = fp.resolve_effective_policy(layers(
        {'scope': 'f', 'unattended': _opt()}, {'scope': 'h', 'unattended': {}}), NOW)
    assert not fp.authorize_unattended(off, 'd1', 'install', 'r1', NOW)['allowed']


def test_reboot_forbid_excluded_and_conflicts_block_unattended():
    p = fp.resolve_effective_policy(layers(
        {'scope': 'f', 'unattended': _opt(), 'reboot_rule': 'forbid'}), NOW)
    assert 'reboot_forbidden' in fp.authorize_unattended(p, 'd1', 'install', 'r1', NOW)['blockers']
    assert fp.resolve_effective_policy(layers({'scope': 'f', 'reboot_rule': 'bogus'}), NOW)['reboot_rule'] == 'manual'
    assert fp.parse_version('1.0') == fp.parse_version('1.0.0') and fp.parse_version('x') is None
