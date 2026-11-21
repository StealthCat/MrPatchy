"""Tests for the pure fail2ban jail contract (#1263).

Expected outcomes follow fail2ban 1.0.2 ``fail2ban/client`` (Ubuntu
``1.0.2-3ubuntu0.1``) ``jailsreader.py``, ``jailreader.py`` and
``configparserinc.py``.
"""
from app import fail2ban_jails as fj

B = '/etc/fail2ban'
DIRS = [B, B + '/jail.d', B + '/filter.d', B + '/action.d', B + '/filter.d/sshd.d',
        B + '/action.d/iptables-multiport.d', B + '/action.d/missing.d', B + '/filter.d/missing.d']
DEFS = {B + '/filter.d/sshd.conf': '[Definition]\nfailregex = x\n',
        B + '/action.d/iptables-multiport.conf': '[Definition]\nactionban = echo\n'}
JAIL_CONF = """[INCLUDES]
before = paths-debian.conf

[DEFAULT]
enabled = false
banaction = iptables-multiport
action_ = %(banaction)s[port="%(port)s", protocol="%(protocol)s"]
action = %(action_)s
port = 0:65535
protocol = tcp

[sshd]
port = ssh
filter = sshd

[recidive]
filter = sshd
"""


def run(files=None, dirs=DIRS):
    merged = dict(DEFS)
    merged.update(files or {})
    return fj.assess(merged, dirs)


def jail(result, name):
    return next(j for j in result['jails'] if j['jail'] == name)


def gaps(result):
    return {g['code'] for g in result['gaps']}


def test_stock_layout_enables_sshd_from_jail_d_with_banaction():
    r = run({B + '/jail.conf': JAIL_CONF, B + '/paths-debian.conf': '[DEFAULT]\nsshd_log = /var/log/auth.log\n',
             B + '/jail.d/defaults-debian.conf': '[sshd]\nenabled = true\n'})
    assert r['loaded_files'] == [B + '/paths-debian.conf', B + '/jail.conf', B + '/jail.d/defaults-debian.conf']
    sshd = jail(r, 'sshd')
    assert sshd['status'] == 'starts' and sshd['filter']['name'] == 'sshd'
    assert sshd['actions'] == [{'kind': 'command', 'name': 'iptables-multiport', 'actname': 'iptables-multiport',
                                'options': {'port': 'ssh', 'protocol': 'tcp'},
                                'files': [B + '/action.d/iptables-multiport.conf'], 'runs_as': 'root'}]
    assert jail(r, 'recidive')['status'] == 'not_started'
    assert r['reader_ok'] is True
    # Action and filter file contents are a follow-up slice, so this fails closed.
    assert gaps(r) == {'definitions_not_evaluated'} and not r['complete']
    assert r['origin'] == 'not_assessed' and r['verdict'] is None


def test_local_overrides_keep_known_values_and_python_actions_are_not_read():
    r = run({B + '/jail.conf': '[web]\nenabled = false\naction = iptables-multiport\n',
             B + '/jail.local': "[web]\nenabled = true\naction = %(known/action)s\n  mail.py[actname=m, dest='a,b']\n"})
    web = jail(r, 'web')
    assert [a['kind'] for a in web['actions']] == ['command', 'python']
    py = web['actions'][1]
    assert py['path'] == B + '/action.d/mail.py' and py['actname'] == 'm' and py['options'] == {'dest': 'a,b'}


def test_disabled_jails_without_definitions_are_complete():
    r = run({B + '/jail.conf': '[a]\nenabled = no\naction = missing\n', B + '/jail.local': '[b]\naction = x\n'})
    assert r['complete'] and r['gaps'] == []
    assert [j['status'] for j in r['jails']] == ['not_started', 'not_started']


def test_python_only_action_without_filter_is_complete():
    r = run({B + '/jail.conf': '[a]\nenabled = true\naction = hook.py\n'})
    assert r['complete'] and jail(r, 'a')['actions'][0]['runs_as'] == 'root'


def test_missing_action_or_filter_and_bad_specs_skip_only_that_jail():
    r = run({B + '/jail.conf': '[a]\nenabled = true\naction = missing\n[b]\nenabled = true\nfilter = missing\n'
             '[c]\nenabled = true\naction = bad[oops\n[d]\nenabled = true\naction = ok.py\n'})
    assert [jail(r, n)['config_error'] for n in 'abc'] == ['action_not_found', 'filter_not_found', 'invalid_action']
    assert jail(r, 'd')['status'] == 'starts' and r['reader_ok'] is True and r['complete']


def test_all_enabled_jails_failing_makes_reader_fail():
    r = run({B + '/jail.conf': '[a]\nenabled = true\naction = missing\n'})
    assert r['reader_ok'] is False


def test_conditional_section_suffixes_keys():
    r = run({B + '/jail.conf': '[a?backend=systemd]\nenabled = true\naction = x.py\n'})
    a = jail(r, 'a')
    assert a['enabled'] is False  # key became enabled?backend=systemd


def test_include_loop_through_local_sibling_fails_closed():
    r = run({B + '/jail.conf': '[a]\n', B + '/jail.local': '[INCLUDES]\nbefore = jail.conf\n'})
    assert 'include_limit' in gaps(r) and not r['complete'] and r['jails'] == []


def test_upstream_crashes_fail_closed():
    for text, code in (('[a]\nenabled = %(nope)s\n', 'interpolation_error'),
                       ('[a]\nenabled = 1\nenabled = 2\n', 'parse_error'),
                       ('enabled = 1\n', 'parse_error')):
        r = run({B + '/jail.conf': text})
        assert gaps(r) == {code} and not r['complete'] and r['jails'] == []


def test_known_reference_with_filter_is_unresolved():
    r = run({B + '/jail.conf': '[a]\nenabled = true\nfilter = sshd\naction = %(known/failregex)s.py\n'})
    assert gaps(r) == {'known_values_not_evaluated'}


def test_unobserved_and_invalid_inputs_fail_closed():
    assert gaps(fj.assess(None, None)) == {'file_not_observed'}
    assert 'file_not_observed' in gaps(fj.assess({B + '/jail.conf': '[a]\n'}, [B]))  # jail.d unlisted
    assert gaps(run({B + '/jail.conf': b'[a]\n\xff'})) == {'file_invalid_utf8'}
    assert gaps(run({B + '/jail.conf': '[a]\x00\n'})) == {'file_nul'}
    assert gaps(run({B + '/jail.conf': '[INCLUDES]\nbefore = ../x.conf\n'})) == {'path_traversal'}
    assert gaps(run({B + '/jail.conf': '[a]\n' + 'x = y\n' * 200000})) == {'too_large'}


def test_hidden_jail_d_files_and_crlf():
    r = run({B + '/jail.d/.hidden.conf': '[a]\nenabled = true\naction = x.py\n',
             B + '/jail.conf': '[b]\r\nenabled = true\r\naction = y.py\r\n'})
    assert [j['jail'] for j in r['jails']] == ['b'] and r['complete']
