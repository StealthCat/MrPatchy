"""Pure authorized_keys options contract (#895)."""
import base64
import calendar
import hashlib
import struct

import pytest

from app import authorized_keys as ak


def blob(key_type='ssh-ed25519', payload=b'\x00' * 32, embedded=None):
    name = (embedded or key_type).encode()
    return struct.pack('>I', len(name)) + name + struct.pack('>I', len(payload)) + payload


def key(key_type='ssh-ed25519', payload=b'\x00' * 32, embedded=None):
    return key_type + ' ' + base64.b64encode(blob(key_type, payload, embedded)).decode()


def fingerprint(raw):
    return 'SHA256:' + base64.b64encode(hashlib.sha256(raw).digest()).decode().rstrip('=')


def one(line, **kw):
    entries = ak.parse_text(line, **kw)['entries']
    assert len(entries) == 1
    return entries[0]


def test_plain_key_identity_and_comment_without_raw_material():
    rec = one(key() + ' admin@laptop')
    assert rec['status'] == 'accepted'
    assert rec['key_type'] == 'ssh-ed25519'
    assert rec['fingerprint'] == fingerprint(blob())
    assert rec['comment'] == 'admin@laptop'
    assert rec['command'] is None
    assert rec['permissions'] == dict.fromkeys(ak.PERMISSIONS, True)
    assert base64.b64encode(blob()).decode() not in repr(rec)


def test_comments_blank_lines_and_crlf_are_skipped():
    text = '# header\n\n   # indented comment\r\n' + key() + ' c\r\n'
    entries = ak.parse_text(text)['entries']
    assert [(e['line'], e['comment']) for e in entries] == [(4, 'c')]


def test_forced_command_is_verbatim_with_escaped_quote_and_literal_backslash():
    line = r'command="/usr/bin/backup --tag \"nightly\" C:\tmp | sh",no-pty ' + key()
    rec = one(line)
    assert rec['status'] == 'accepted'
    assert rec['command'] == r'/usr/bin/backup --tag "nightly" C:\tmp | sh'
    assert rec['command_runs_via'] == 'account_shell_-c'
    assert rec['permissions']['pty'] is False
    assert rec['options'] == ['command', 'no-pty']


def test_quoted_whitespace_and_commas_stay_inside_options():
    line = 'from="10.0.0.0/8,!10.0.0.5",command="echo a, b  c" ' + key() + ' svc'
    rec = one(line)
    assert rec['from'] == ['10.0.0.0/8,!10.0.0.5']
    assert rec['command'] == 'echo a, b  c'
    assert rec['comment'] == 'svc'


def test_restrict_is_sequential_and_later_flags_reenable():
    rec = one('restrict,pty,port-forwarding ' + key())
    assert rec['restrict'] is True
    assert rec['permissions'] == {'pty': True, 'port_forwarding': True, 'agent_forwarding': False,
                                  'x11_forwarding': False, 'user_rc': False}
    # A permission granted before restrict is removed by it.
    assert one('pty,restrict ' + key())['permissions']['pty'] is False


def test_option_names_are_case_insensitive():
    rec = one('No-X11-Forwarding,COMMAND="id" ' + key())
    assert rec['permissions']['x11_forwarding'] is False
    assert rec['command'] == 'id'


@pytest.mark.parametrize('options,kind', [
    ('bogus-option', 'unknown_option'),
    ('command=id', 'missing_quote'),
    ('command="id', 'unbalanced_quotes'),
    ('command="a",command="b"', 'duplicate_option'),
    ('principals="a",principals="b"', 'duplicate_option'),
    ('expiry-time="2026"', 'invalid_expiry'),
    ('expiry-time="20261340"', 'invalid_expiry'),
    ('tunnel="eth0"', 'invalid_tunnel'),
    ('environment="=x"', 'invalid_environment'),
    ('no-pty,', 'bad_option_syntax'),
    ('command', 'missing_value'),
])
def test_lines_sshd_would_reject_are_invalid_with_reason(options, kind):
    rec = one(options + ' ' + key())
    assert rec['status'] == 'invalid'
    assert rec['reject_kind'] == kind
    assert rec['reason']
    assert rec['command'] is None


def test_bad_key_material_is_invalid():
    assert one('ssh-ed25519 !!!notbase64')['reject_kind'] == 'bad_key'
    assert one('ssh-ed25519')['reject_kind'] == 'bad_key'
    assert one(key('ssh-ed25519', embedded='ssh-rsa'))['reject_kind'] == 'key_type_mismatch'


def test_unknown_key_type_is_a_gap_not_accepted():
    rec = one('command="id" future-key-type AAAA')
    assert rec['status'] == 'unknown'
    assert rec['gaps'][0]['kind'] == 'unknown_key_type'


def test_value_options_are_reported():
    line = ('environment="PATH=/opt/bin",permitopen="db:5432",permitlisten="localhost:8080",'
            'principals="ops,deploy",tunnel="0",cert-authority,verify-required ' + key('ssh-rsa', b'\x01' * 64))
    rec = one(line)
    assert rec['status'] == 'accepted'
    assert rec['environment'] == ['PATH=/opt/bin']
    assert rec['permitopen'] == ['db:5432']
    assert rec['permitlisten'] == ['localhost:8080']
    assert rec['principals'] == 'ops,deploy'
    assert rec['tunnel'] == '0'
    assert rec['cert_authority'] is True and rec['verify_required'] is True
    assert {g['kind'] for g in rec['gaps']} == {'environment_requires_sshd_config'}


def test_expiry_utc_local_and_unevaluated():
    now = calendar.timegm((2026, 11, 15, 12, 0, 0))
    assert one('expiry-time="20261101Z" ' + key(), now=now)['status'] == 'expired'
    assert one('expiry-time="202612010000Z" ' + key(), now=now)['status'] == 'accepted'
    # Local time far in the past is expired in any zone.
    assert one('expiry-time="20260101" ' + key(), now=now)['status'] == 'expired'
    near = one('expiry-time="20261115" ' + key(), now=now)
    assert near['status'] == 'accepted'
    assert near['gaps'][0]['kind'] == 'expiry_timezone_unknown'
    assert one('expiry-time="20261101Z" ' + key())['gaps'][0]['kind'] == 'expiry_unevaluated'
    # sshd keeps the earliest of several expiry-time options.
    both = one('expiry-time="20300101Z",expiry-time="20261101Z" ' + key(), now=now)
    assert both['expiry_time'] == '20261101Z' and both['status'] == 'expired'


def test_first_valid_line_wins_and_later_duplicates_are_shadowed():
    text = '\n'.join(['bogus ' + key(), 'command="/bin/first" ' + key(), 'command="/bin/later" ' + key()])
    invalid, first, later = ak.parse_text(text)['entries']
    assert invalid['status'] == 'invalid'
    assert first['precedence'] == 'first' and first['command'] == '/bin/first'
    assert later['status'] == 'shadowed' and later['shadowed_by_line'] == 2


def test_earlier_from_restriction_makes_precedence_conditional():
    text = 'from="10.0.0.1" ' + key() + '\ncommand="/bin/other" ' + key()
    _, later = ak.parse_text(text)['entries']
    assert later['status'] == 'accepted'
    assert later['precedence'] == 'conditional'
    assert later['gaps'][0]['kind'] == 'precedence_depends_on_source'


def test_assess_files_gaps_caps_and_summary():
    result = ak.assess([
        {'path': '/root/.ssh/authorized_keys', 'account': 'root',
         'text': 'command="/tmp/x" ' + key() + '\n' + key('ssh-rsa', b'\x02' * 64) + '\nbad ' + key()},
        {'path': '/home/a/.ssh/authorized_keys', 'account': 'a', 'error': 'Permission denied'},
        {'path': '/home/b/.ssh/authorized_keys', 'account': 'b', 'text': 'x' * (ak.MAX_FILE_BYTES + 1)},
        {'path': '/home/c/.ssh/authorized_keys', 'account': 'c', 'text': key(), 'truncated': True},
    ])
    assert result['contract_version'] == ak.CONTRACT_VERSION
    statuses = [f['status'] for f in result['files']]
    assert statuses == ['assessed', 'unknown', 'unknown', 'unknown']
    assert [f['gaps'][0]['kind'] for f in result['files'][1:]] == ['unreadable', 'oversized', 'oversized']
    assert result['summary'] == {'files': 4, 'unassessed_files': 3, 'keys': 3, 'accepted': 2,
                                 'forced_commands': 1, 'invalid': 1, 'expired': 0, 'shadowed': 0, 'unknown': 0}


def test_line_and_option_caps_are_explicit():
    long_line = 'command="' + 'a' * (ak.MAX_LINE_CHARS) + '" ' + key()
    assert one(long_line)['reject_kind'] == 'over_cap'
    many = ','.join(['no-pty'] * (ak.MAX_OPTIONS + 1)) + ' ' + key()
    assert one(many)['reject_kind'] == 'over_cap'
    text = '\n'.join([key()] * (ak.MAX_LINES + 1))
    parsed = ak.parse_text(text)
    assert len(parsed['entries']) == ak.MAX_LINES
    assert parsed['gaps'][0]['kind'] == 'over_cap'
    files = ak.assess([{'path': f'/f{i}', 'text': ''} for i in range(ak.MAX_FILES + 1)])
    assert len(files['files']) == ak.MAX_FILES and files['gaps'][0]['kind'] == 'over_cap'


def test_real_openssh_public_key_from_cryptography_matches_fingerprint():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
    public = ed25519.Ed25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode()
    rec = one('restrict,command="rsync --server" ' + public + ' backup')
    assert rec['status'] == 'accepted'
    assert rec['fingerprint'] == fingerprint(base64.b64decode(public.split()[1]))
    assert rec['permissions'] == dict.fromkeys(ak.PERMISSIONS, False)


def test_environment_name_follows_openssh_alnum_underscore_rule():
    assert one('environment="1X=y" ' + key())['environment'] == ['1X=y']
    assert one('environment="A-B=y" ' + key())['reject_kind'] == 'invalid_environment'
