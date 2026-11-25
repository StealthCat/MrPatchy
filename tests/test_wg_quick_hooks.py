import hashlib

from app import wg_quick_hooks as wq

CONF = """[Interface]
Address = 10.0.0.1/24
PrivateKey = AAAA
PreUp = sysctl -w net.ipv4.ip_forward=1
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostUp = echo up %i
PreDown = logger going-down
PostDown = iptables -D FORWARD -i %i -j ACCEPT

[Peer]
PublicKey = BBBB
AllowedIPs = 10.0.0.2/32
"""


def _entry(name='wg0.conf', text=CONF, **kw):
    return dict({'name': name, 'type': 'file', 'text': text}, **kw)


def _run(*entries, enabled=('wg0',), **kw):
    kw.setdefault('family', 'debian')
    kw.setdefault('wireguard_tools_installed', True)
    directory = kw.pop('directory', None) or {'state': 'listed', 'entries': list(entries or [_entry()])}
    return wq.assess(directory, enabled_instances=None if enabled is None else list(enabled), **kw)


def _codes(result):
    return {g['code'] for g in result['gaps']}


def _commands(config, phase=None):
    return [h['command'] for h in config['hooks'] if phase is None or h['phase'] == phase]


def test_interface_hooks_run_as_root_in_phase_order_with_interface_substituted():
    result = _run()
    assert result['complete'] is True and result['gaps'] == []
    assert result['applicability'] == 'applicable' and result['runs_as'] == 'root'
    assert result['stops_on_failure'] is True and 'eval in a subshell' in result['shell']
    [config] = result['configs']
    assert config['outcome'] == 'interface' and config['interface'] == 'wg0' and config['at_boot'] is True
    assert [h['phase'] for h in config['hooks']] == ['PreUp', 'PostUp', 'PostUp', 'PreDown', 'PostDown']
    assert _commands(config, 'PostUp') == [
        'iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE',
        'echo up wg0']
    assert [h['order'] for h in config['hooks'] if h['phase'] == 'PostUp'] == [1, 2]
    assert [h['line'] for h in config['hooks']] == [4, 5, 6, 7, 8]
    first = config['hooks'][0]
    assert first['sha256'] == hashlib.sha256(b'sysctl -w net.ipv4.ip_forward=1').hexdigest()
    # Boot brings the interface up, so only the up hooks run at boot.
    assert [h['phase'] for h in result['boot_hooks']] == ['PreUp', 'PostUp', 'PostUp']
    assert all(h['interface'] == 'wg0' and h['path'] == '/etc/wireguard/wg0.conf' for h in result['boot_hooks'])
    assert result['origin'] == 'not_assessed' and 'not a safety verdict' in result['not_a_verdict']


def test_parse_rules_match_wg_quick_parse_options():
    text = (
        'postup = before any section is not a hook\n'
        '[INTERFACE]\n'
        '  preup\t=\techo "#not a comment" ; rm -rf /tmp/x\n'   # cut at the first '#' anywhere
        'PostUp=a=b==c\n'                                        # split at the first '='
        'PostUp\n'                                               # no '=' makes the key the value too
        'PreDown = \r\n'                                         # trimmed to an empty hook
        'Pre Up = not a key\n'
        '[Peer]\n'
        'PostDown = in a peer section\n'
        '[interface] # second section accumulates\n'
        'PostDown = %i%i\n'
        'PostDown = final line without newline'
    )
    parsed = wq.parse(text)
    assert parsed['error'] is None
    assert [h['value'] for h in parsed['hooks']['PreUp']] == ['echo "']
    assert [h['value'] for h in parsed['hooks']['PostUp']] == ['a=b==c', 'PostUp']
    assert [h['value'] for h in parsed['hooks']['PreDown']] == ['']
    assert [h['value'] for h in parsed['hooks']['PostDown']] == ['%i%i', 'final line without newline']
    assert [(m['key'], m['line']) for m in parsed['misplaced']] == [('PostUp', 1), ('PostDown', 9)]
    result = _run(_entry(name='x=y+z_.conf', text=text), enabled=['x=y+z_'])
    [config] = result['configs']
    assert _commands(config, 'PostDown') == ['x=y+z_x=y+z_', 'final line without newline']
    assert [m['key'] for m in config['misplaced_hooks']] == ['PostUp', 'PostDown']


def test_case_folding_is_ascii_only():
    # Under LC_ALL=C nocasematch folds ASCII only, so a non-ASCII lookalike is not the key.
    parsed = wq.parse('[Interface]\nPreUp = a\nPREİUP = b\nKey = c\n')
    assert [h['value'] for h in parsed['hooks']['PreUp']] == ['a']


def test_invalid_save_config_exits_before_any_hook():
    text = '[Interface]\nPreUp = echo one\nSaveConfig = yes\nPostUp = echo two\n'
    result = _run(_entry(text=text))
    [config] = result['configs']
    assert config['outcome'] == 'config_error' and config['error_line'] == 3 and config['hooks'] == []
    assert result['boot_hooks'] == [] and result['complete'] is True
    # Case-insensitive true/false are accepted; SaveConfig outside [Interface] is ignored.
    ok = _run(_entry(text='[Peer]\nSaveConfig = nope\n[Interface]\nSaveConfig = TRUE\nPreUp = x\n'))
    assert ok['configs'][0]['outcome'] == 'interface' and ok['configs'][0]['save_config'] is True


def test_file_names_and_entry_types():
    result = _run(
        _entry(name='wg0.conf'),
        _entry(name='abcdefghijklmnop.conf'),   # 16-character name is refused
        _entry(name='bad name.conf'),
        _entry(name='notes.txt'),
        _entry(name='wg0.conf.bak'),
        {'name': 'keys', 'type': 'directory'},
        {'name': 'pipe.conf', 'type': 'other'},
        _entry(name='link.conf', type='symlink', text='[Interface]\nPostUp = echo via link\n'),
        enabled=['wg0', 'link'],
    )
    outcomes = {c['name']: c['outcome'] for c in result['configs']}
    assert outcomes == {'wg0.conf': 'interface', 'abcdefghijklmnop.conf': 'name_invalid',
                        'bad name.conf': 'name_invalid', 'notes.txt': 'not_conf', 'wg0.conf.bak': 'not_conf',
                        'keys': 'directory', 'pipe.conf': 'not_plain_file', 'link.conf': 'interface'}
    assert 'echo via link' in [h['command'] for h in result['boot_hooks']]
    assert result['complete'] is True


def test_boot_enablement():
    disabled = _run(enabled=[])
    assert disabled['configs'][0]['at_boot'] is False and disabled['boot_hooks'] == []
    assert disabled['complete'] is True
    unknown = _run(enabled=None)
    assert unknown['configs'][0]['at_boot'] == 'unknown' and 'enablement_not_observed' in _codes(unknown)
    assert unknown['complete'] is True and unknown['boot_hooks'] == []
    missing = _run(enabled=['wg0', 'wg9'])
    assert 'instance_without_config' in _codes(missing) and missing['complete'] is True
    path_instance = _run(enabled=['-etc-vpn-office.conf-with-long-name'])
    assert 'instance_unresolved' in _codes(path_instance) and path_instance['complete'] is False
    malformed = wq.assess({'state': 'listed', 'entries': [_entry()]}, family='debian',
                          wireguard_tools_installed=True, enabled_instances='wg0')
    assert 'input_malformed' in _codes(malformed) and malformed['complete'] is False


def test_fail_closed_gaps():
    def codes(**kw):
        result = _run(**kw)
        assert result['complete'] is False
        return _codes(result)

    assert 'family_not_observed' in codes(family=None)
    assert 'family_unsupported' in codes(family='windows')
    assert 'implementation_not_observed' in codes(wireguard_tools_installed=None)
    assert 'directory_not_observed' in _codes(wq.assess(None, family='debian', wireguard_tools_installed=True,
                                                        enabled_instances=[]))
    assert 'directory_unreadable' in codes(directory={'state': 'unreadable'})
    assert 'listing_incomplete' in codes(directory={'state': 'listed', 'truncated': True, 'entries': [_entry()]})
    assert 'too_many_entries' in codes(directory={'state': 'listed', 'entries': [
        _entry(name=f'w{i}.conf') for i in range(wq.MAX_ENTRIES + 1)]})
    assert 'input_malformed' in codes(directory={'state': 'bogus'})
    assert 'input_malformed' in codes(directory={'state': 'listed', 'entries': [_entry(), _entry()]})
    assert 'file_not_read' in codes(directory={'state': 'listed', 'entries': [{'name': 'wg0.conf', 'type': 'file'}]})
    assert 'file_unreadable' in codes(directory={'state': 'listed', 'entries': [_entry(text=None)]})
    assert 'nul_byte' in codes(directory={'state': 'listed', 'entries': [_entry(text='[Interface]\nPreUp = a\0b\n')]})
    assert 'file_too_large' in codes(directory={'state': 'listed', 'entries': [
        _entry(text='#' * (wq.MAX_TEXT + 1))]})
    unresolved = _run(directory={'state': 'listed', 'entries': [_entry(text=None)]})
    assert unresolved['configs'][0]['outcome'] == 'unresolved' and unresolved['boot_hooks'] == []
    absent = _run(directory={'state': 'absent'}, enabled=[])
    assert absent['complete'] is True and absent['configs'] == []


def test_not_installed_is_not_applicable_and_bytes_are_accepted():
    result = _run(wireguard_tools_installed=False, enabled=[])
    assert result['applicability'] == 'not_applicable'
    text = b'[Interface]\nPostUp = echo \xff\n'
    raw = _run(_entry(text=text))
    [hook] = raw['configs'][0]['hooks']
    assert hook['sha256'] == hashlib.sha256(b'echo \xff').hexdigest()


def test_gap_list_is_bounded():
    entries = [{'name': f'w{i}.conf', 'type': 'file'} for i in range(wq.MAX_GAPS + 5)]
    result = _run(directory={'state': 'listed', 'entries': entries})
    assert len(result['gaps']) == wq.MAX_GAPS and result['gaps'][-1]['code'] == 'gaps_truncated'
    assert result['complete'] is False
