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
    # an explicit empty opt-in on the narrowest layer disables a broader one
    off = fp.resolve_effective_policy(layers(
        {'scope': 'f', 'unattended': _opt()}, {'scope': 'h', 'unattended': {}}), NOW)
    assert not fp.authorize_unattended(off, 'd1', 'install', 'r1', NOW)['allowed']


def test_reboot_forbid_excluded_and_conflicts_block_unattended():
    p = fp.resolve_effective_policy(layers(
        {'scope': 'f', 'unattended': _opt(), 'reboot_rule': 'forbid'}), NOW)
    assert 'reboot_forbidden' in fp.authorize_unattended(p, 'd1', 'install', 'r1', NOW)['blockers']
    assert fp.resolve_effective_policy(layers({'scope': 'f', 'reboot_rule': 'bogus'}), NOW)['reboot_rule'] == 'manual'
    assert fp.parse_version('1.0') == fp.parse_version('1.0.0') and fp.parse_version('x') is None


def _allowed(policy_layers, device='d1', release='r1', now=NOW):
    pol = fp.resolve_effective_policy(policy_layers, NOW)
    return fp.authorize_unattended(pol, device, 'install', release, now)


def test_overlong_scope_ids_are_rejected_not_truncated():
    # #507 review: truncation let an opt-in for a long ID authorize its 128-char prefix.
    long_dev, long_rel = 'd' * 128 + '-host-A', 'r' * 132
    for opt, dev, rel in ((_opt(devices=[long_dev]), 'd' * 128, 'r1'),
                          (_opt(devices=[long_dev]), long_dev, 'r1'),
                          (_opt(releases=[long_rel]), 'd1', 'r' * 128),
                          (_opt(releases=[long_rel]), 'd1', long_rel)):
        r = _allowed(layers({'scope': 'f', 'unattended': opt}), dev, rel)
        assert not r['allowed']
        assert r['blockers'][0] in ('devices_overlong_id', 'releases_overlong_id')
    exact = 'd' * 128
    assert _allowed(layers({'scope': 'f', 'unattended': _opt(devices=[exact])}), exact)['allowed']


def test_malformed_or_oversized_scope_lists_fail_closed():
    too_many = [f'd{i}' for i in range(fp.MAX_ITEMS)] + ['extra']
    for opt, reason in ((_opt(devices=too_many), 'devices_too_many_ids'),
                        (_opt(devices=['d1', 7]), 'devices_malformed_ids'),
                        (_opt(releases='r1'), 'releases_malformed_ids'),
                        ({k: v for k, v in _opt().items() if k != 'actions'}, 'unbounded_scope')):
        assert _allowed(layers({'scope': 'f', 'unattended': opt}))['blockers'] == [reason]
    p = fp.resolve_effective_policy(layers({'scope': 'f', 'approved_channels': ['x' * 129]}), NOW)
    assert 'approved_channels_overlong_id' in p['conflicts']


def test_non_finite_opt_in_expiry_is_rejected():
    for bad in (float('nan'), float('inf'), float('-inf')):
        r = _allowed(layers({'scope': 'f', 'unattended': _opt(expires_at=bad)}), now=NOW + 1e12)
        assert not r['allowed'] and r['blockers'] == ['expired_or_missing_expiry']
    p = fp.resolve_effective_policy(layers(
        {'scope': 'f', 'min_version': '2.0', 'exception': {'expires_at': float('inf')}}), NOW)
    assert p['exception'] is None


def test_malformed_deferral_and_exclusion_block_instead_of_being_dropped():
    for value in ('2099-01-01T00:00:00Z', float('nan'), float('inf'), True):
        r = _allowed(layers({'scope': 'f', 'unattended': _opt(), 'deferred_until': value}))
        assert not r['allowed'] and 'policy_conflict' in r['blockers']
        pol = fp.resolve_effective_policy(layers(
            {'scope': 'f', 'min_version': '1.0', 'deferred_until': value}), NOW)
        assert pol['conflicts'] == ['deferred_until_invalid']
        assert fp.evaluate_device(pol, '1.0', NOW)['compliant'] is False
    for value in ('true', 1, 'yes'):
        r = _allowed(layers({'scope': 'f', 'unattended': _opt(), 'excluded': value}))
        assert not r['allowed'] and 'policy_conflict' in r['blockers']
    assert _allowed(layers({'scope': 'f', 'unattended': _opt(), 'excluded': False}))['allowed']


def test_broader_opt_in_is_not_inherited_by_a_silent_narrower_layer():
    pol = fp.resolve_effective_policy(layers(
        {'scope': 'fleet', 'unattended': _opt()}, {'scope': 'host:a', 'min_version': '1.0'}), NOW)
    assert pol['unattended_source'] is None and pol['unattended']['enabled'] is False
    assert fp.authorize_unattended(pol, 'd1', 'install', 'r1', NOW)['blockers'] == ['not_opted_in']
    own = fp.resolve_effective_policy(layers(
        {'scope': 'fleet', 'unattended': _opt(devices=['d9'])}, {'scope': 'host:a', 'unattended': _opt()}), NOW)
    assert own['unattended_source'] == 'host:a'
    assert fp.authorize_unattended(own, 'd1', 'install', 'r1', NOW)['allowed']
