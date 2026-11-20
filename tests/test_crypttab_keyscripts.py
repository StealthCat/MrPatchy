"""Tests for the pure crypttab keyscript contract (#1225).

Expected outcomes follow debian/functions, debian/cryptdisks-functions and
debian/initramfs/scripts/local-top/cryptroot in Ubuntu cryptsetup
2.7.0-1ubuntu4 and 2.8.4-1ubuntu4.

The live differential at the end sources the real ``debian/functions`` from a
cryptsetup source package under dash. Point ``CRYPTSETUP_FUNCTIONS`` at that
file to run it; it needs root because ``[ -x ]`` follows root's rules.
"""
import os
import random
import shutil
import stat
import subprocess

import pytest

from app import crypttab_keyscripts as ck

EXEC = {'type': 'file', 'executable': True}
NOEXEC = {'type': 'file', 'executable': False}
MISSING = {'type': 'missing'}
PATHS = {
    '/lib/cryptsetup/scripts/passdev': EXEC,
    '/lib/cryptsetup/scripts/decrypt_keyctl': EXEC,
    '/lib/cryptsetup/checks/blkid': EXEC,
    '/usr/local/sbin/getkey': EXEC,
    '/usr/local/sbin/notexec': NOEXEC,
    '/usr/local/sbin/gone': MISSING,
    '/usr/local/sbin/dir': {'type': 'directory'},
    '/boot/hdr.img': NOEXEC,
}


def run(text, **kw):
    kw.setdefault('paths', PATHS)
    return ck.evaluate(text, **kw)


def by_name(result):
    return {e['name']: e for e in result['entries']}


def codes(result):
    return [g['code'] for g in result['gaps']]


def test_relative_keyscript_resolves_under_scripts_dir_and_execs_with_key_field():
    result = run('cryptroot UUID=abc /dev/disk/by-label/usb:/keys/root.key luks,keyscript=passdev\n')
    assert result['complete'] and not result['gaps']
    entry = by_name(result)['cryptroot']
    assert entry['status'] == 'accepted' and entry['boot'] == 'boot'
    assert entry['unlock']['method'] == 'keyscript' and entry['unlock']['relative_resolved'] is True
    assert entry['unlock']['argv'] == ['/lib/cryptsetup/scripts/passdev', '/dev/disk/by-label/usb:/keys/root.key']
    assert 'CRYPTTAB_KEY' in entry['unlock']['environment'] and entry['unlock']['user'] == 'root'
    assert result['programs'] == [{
        'name': 'cryptroot', 'line': 1, 'kind': 'unlock', 'method': 'keyscript',
        'program': '/lib/cryptsetup/scripts/passdev',
        'argv': ['/lib/cryptsetup/scripts/passdev', '/dev/disk/by-label/usb:/keys/root.key'],
        'user': 'root', 'boot': 'boot', 'origin': 'not_assessed'}]
    assert result['authorizes_response'] is False and result['origin'] == 'not_assessed'
    assert result['not_observed']


def test_none_key_without_keyscript_runs_askpass_with_prompt_and_keyfile_runs_nothing():
    result = run('home /dev/sda3 none luks\nswap /dev/sda2 /dev/urandom swap,cipher=aes-xts-plain64,size=256\n')
    entries = by_name(result)
    assert entries['home']['unlock']['argv'] == ['/lib/cryptsetup/askpass', 'Please unlock disk home: ']
    assert 'CRYPTTAB_KEY' not in entries['home']['unlock']['environment']
    assert entries['swap']['unlock']['method'] == 'keyfile' and entries['swap']['unlock']['program'] is None
    assert [p['name'] for p in result['programs']] == ['home']


def test_keyscript_set_to_askpass_with_a_key_reaches_exec_of_empty_string():
    result = run('d /dev/sdb /key luks,keyscript=/lib/cryptsetup/askpass\n',
                 paths={**PATHS, '/lib/cryptsetup/askpass': EXEC})
    entry = by_name(result)['d']
    assert entry['unlock']['method'] == 'exec_fails' and entry['unlock']['program'] is None
    none = run('d /dev/sdb none luks,keyscript=/lib/cryptsetup/askpass\n',
               paths={**PATHS, '/lib/cryptsetup/askpass': EXEC})
    assert by_name(none)['d']['unlock']['method'] == 'askpass'


def test_keyscript_must_be_an_executable_regular_file_or_the_entry_is_rejected():
    for target in ('/usr/local/sbin/notexec', '/usr/local/sbin/gone', '/usr/local/sbin/dir'):
        entry = by_name(run(f'd /dev/sdb arg keyscript={target}\n'))['d']
        assert entry['status'] == 'rejected' and entry['invalid_option'] == f'keyscript={target}', target
        assert entry['unlock'] is None
    for bad in ('keyscript', 'keyscript='):
        assert by_name(run(f'd /dev/sdb arg luks,{bad}\n'))['d']['status'] == 'rejected'


def test_any_invalid_option_rejects_the_entry_even_after_a_valid_keyscript():
    for bad in ('size=0', 'size=x', 'offset=-1', 'tries=', 'cipher', 'hash=', 'tmp=', 'checkargs', 'header=',
                'header=/missing/hdr', 'check=/usr/local/sbin/notexec'):
        result = run(f'd /dev/sdb arg keyscript=/usr/local/sbin/getkey,{bad}\n',
                     paths={**PATHS, '/missing/hdr': MISSING})
        entry = by_name(result)['d']
        assert entry['status'] == 'rejected', bad
        assert result['programs'] == [] and result['complete'], bad


def test_valid_numeric_flags_aliases_and_unknown_options():
    result = run('d /dev/sdb arg read-only,key-slot=1,size=0256,offset=0,tmp,checkargs=,bogus,=x,,'
                 'x-initrd.attach,keyscript=/usr/local/sbin/getkey,\n')
    entry = by_name(result)['d']
    assert entry['status'] == 'accepted'
    assert entry['options']['readonly'] is True and entry['options']['keyslot'] == '1'
    assert entry['options']['tmp'] == 'ext4' and entry['options']['checkargs'] == ''
    assert [i['option'] for i in entry['ignored_options']] == ['bogus', '=x', '', 'x-initrd.attach']


def test_later_keyscript_replaces_earlier_but_every_value_is_validated():
    entry = by_name(run('d /dev/sdb arg keyscript=passdev,keyscript=/usr/local/sbin/getkey\n'))['d']
    assert entry['unlock']['program'] == '/usr/local/sbin/getkey'
    assert entry['unlock']['relative_resolved'] is False
    rejected = by_name(run('d /dev/sdb arg keyscript=/usr/local/sbin/gone,keyscript=passdev\n'))['d']
    assert rejected['status'] == 'rejected'


def test_option_words_keep_spaces_so_a_spaced_keyscript_is_an_ignored_unknown_option():
    result = run('d\t/dev/sdb  arg   luks, keyscript=/usr/local/sbin/getkey  \n')
    entry = by_name(result)['d']
    assert entry['options_raw'] == 'luks, keyscript=/usr/local/sbin/getkey'
    assert entry['unlock']['method'] == 'keyfile'
    assert entry['ignored_options'] == [{'option': ' keyscript=/usr/local/sbin/getkey', 'reason': 'unknown_option'}]


def test_check_runs_after_unlock_only_on_the_cryptdisks_path():
    text = 'd /dev/sdb none luks,check,checkargs=ext4\ne /dev/sdc none luks,check=/usr/local/sbin/getkey\n'
    entries = by_name(run(text))
    assert entries['d']['check']['argv'] == ['/lib/cryptsetup/checks/blkid', '<unlocked device>', 'ext4']
    assert entries['e']['check']['argv'] == ['/usr/local/sbin/getkey', '<unlocked device>']
    initramfs = by_name(run(text, context='initramfs'))
    assert initramfs['d']['check'] is None and initramfs['d']['boot'] == 'initramfs'
    dropped = by_name(run(text, cryptdisks_check=''))['d']
    assert dropped['check'] is None and dropped['ignored_options'][0]['reason'] == 'check_default_empty'
    unknown = run(text, cryptdisks_check=None)
    assert by_name(unknown)['d']['status'] == 'unresolved' and not unknown['complete']
    assert 'check_default_not_observed' in codes(unknown)


def test_noauto_and_noearly_gate_the_cryptdisks_boot_path():
    entries = by_name(run('a /dev/sdb none noauto\nb /dev/sdc none noearly\n'))
    assert entries['a']['boot'] == 'manual_only' and entries['b']['boot'] == 'not_early'


def test_line_splitting_comments_missing_fields_and_unterminated_last_line():
    text = ('# comment\n\n   \n  #indented comment\nonly /dev/sdb\n'
            'ok /dev/sdc none\nlast /dev/sdd none keyscript=/usr/local/sbin/getkey')
    result = run(text)
    entries = by_name(result)
    assert entries['only'] == {**entries['only'], 'status': 'skipped', 'reason': 'missing_fields'}
    assert entries['ok']['status'] == 'accepted'
    assert entries['last']['status'] == 'skipped' and entries['last']['reason'] == 'unterminated_last_line'
    assert [p['name'] for p in result['programs']] == ['ok'] and result['complete']
    assert ck.split_line('  a\t b  c  d  e \t') == ('a', 'b', 'c', 'd  e')


def test_fail_closed_inputs():
    assert run(None)['complete'] is False and codes(run(None)) == ['text_not_observed']
    assert codes(run(b'd /dev/sdb none\x00\n')) == ['binary']
    assert codes(run(b'd /dev/sdb \xff none\n')) == ['invalid_utf8']
    assert codes(run('x' * (ck.MAX_TEXT + 1))) == ['over_limit']
    assert codes(run('d /dev/sdb none\n' * (ck.MAX_LINES + 1))) == ['lines_over_limit']
    escaped = run('my\\040disk /dev/sdb none keyscript=/usr/local/sbin/getkey\n')
    assert by_name(escaped)['my\\040disk']['status'] == 'unresolved' and not escaped['complete']
    globbed = run('d /dev/sdb none keyscript=/usr/local/sbin/get*\n')
    assert codes(globbed) == ['glob_not_modeled'] and by_name(globbed)['d']['status'] == 'unresolved'
    unobserved = run('d /dev/sdb none keyscript=/opt/unknown\n')
    assert codes(unobserved) == ['path_not_observed'] and unobserved['programs'] == []
    relative = run('d /dev/sdb none header=hdr.img\n')
    assert codes(relative) == ['relative_header']
    with pytest.raises(ValueError):
        ck.evaluate('', context='systemd')


def test_definitely_invalid_option_wins_over_an_unobserved_path():
    result = run('d /dev/sdb none keyscript=/opt/unknown,size=0\n')
    assert by_name(result)['d']['status'] == 'rejected' and result['complete']


# --- live differential against the real debian/functions -------------------------------------------------

FUNCTIONS = os.environ.get('CRYPTSETUP_FUNCTIONS')
RUNNER = r'''
set -u
. "$FUNCTIONS"
_get_crypt_type() { return 1; }
cb() {
    if crypttab_parse_options --export --missing-path=fail --quiet; then
        printf 'A|%s|%s|%s|%s\n' "$CRYPTTAB_NAME" "${CRYPTTAB_OPTION_keyscript-<unset>}" \
            "${CRYPTTAB_OPTION_check-<unset>}" "${CRYPTTAB_OPTION_checkargs-<unset>}"
    else
        printf 'R|%s\n' "$CRYPTTAB_NAME"
    fi
}
crypttab_foreach_entry cb
'''


def _facts(paths):
    facts = {}
    for path in paths:
        try:
            st = os.stat(path)
        except FileNotFoundError:
            facts[path] = {'type': 'missing'}
            continue
        kind = 'file' if stat.S_ISREG(st.st_mode) else 'directory' if stat.S_ISDIR(st.st_mode) else 'other'
        facts[path] = {'type': kind, 'executable': bool(st.st_mode & 0o111)}
    return facts


@pytest.mark.skipif(not FUNCTIONS or shutil.which('dash') is None or os.geteuid() != 0,
                    reason='set CRYPTSETUP_FUNCTIONS to debian/functions; needs dash and root')
def test_live_differential_against_debian_functions(tmp_path):
    root = tmp_path / 'r'
    (root / 'dir').mkdir(parents=True)
    for name, mode in (('exec', 0o755), ('noexec', 0o644), ('xonly', 0o100)):
        (root / name).write_text('#!/bin/sh\n')
        (root / name).chmod(mode)
    (root / 'link').symlink_to(root / 'exec')
    (root / 'dangling').symlink_to(root / 'nowhere')
    targets = [str(root / n) for n in ('exec', 'noexec', 'xonly', 'link', 'dangling', 'dir', 'missing')]
    paths = _facts(targets)
    pool = ([f'keyscript={t}' for t in targets] + [f'check={t}' for t in targets]
            + [f'header={t}' for t in targets]
            + ['keyscript', 'keyscript=', 'check', 'checkargs', 'checkargs=', 'checkargs=-v', 'luks', 'plain',
               'size=256', 'size=0', 'size=007', 'offset=0', 'offset=x', 'tries=3', 'tries=', 'key-slot=2',
               'read-only', 'tmp', 'tmp=', 'tmp=xfs', 'cipher', 'cipher=aes', 'hash=', 'bogus', 'bogus=1', '',
               '=v', 'noauto', 'x-initrd.attach', ' keyscript=' + targets[0], 'swap', 'discard'])
    rng = random.Random(1225)
    empty_cwd = tmp_path / 'cwd'
    empty_cwd.mkdir()
    mismatches = 0
    cases = 600
    for case in range(cases):
        lines = []
        for index in range(rng.randint(1, 6)):
            shape = rng.random()
            name = f'n{case}_{index}'
            opts = ','.join(rng.choice(pool) for _ in range(rng.randint(0, 4)))
            if rng.random() < 0.1:
                opts += ','
            key = rng.choice(['none', '/key', 'arg:x'])
            sep = rng.choice([' ', '\t', '  ', ' \t '])
            if shape < 0.07:
                lines.append(f'# {name} /dev/x none {opts}')
            elif shape < 0.12:
                lines.append(f'{name} /dev/x')
            else:
                lines.append(f'{rng.choice(["", " ", chr(9)])}{name}{sep}/dev/x{sep}{key}{sep}{opts}'
                             f'{rng.choice(["", " ", chr(9)])}')
        text = '\n'.join(lines) + ('\n' if rng.random() < 0.85 else '')
        tab = tmp_path / 'crypttab'
        tab.write_text(text)
        proc = subprocess.run(['dash', '-c', RUNNER], capture_output=True, text=True, cwd=empty_cwd, check=True,
                              env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'FUNCTIONS': FUNCTIONS,
                                   'TABFILE': str(tab), 'CRYPTDISKS_CHECK': str(root / 'exec')})
        shell = [line for line in proc.stdout.splitlines() if line]
        model = ck.evaluate(text, paths=paths, cryptdisks_check=str(root / 'exec'))
        mine = []
        for entry in model['entries']:
            if entry['status'] == 'accepted':
                options = entry['options']
                mine.append('A|{}|{}|{}|{}'.format(entry['name'], options.get('keyscript', '<unset>'),
                                                   options.get('check', '<unset>'),
                                                   options.get('checkargs', '<unset>')))
            elif entry['status'] == 'rejected':
                mine.append(f'R|{entry["name"]}')
            else:
                assert entry['status'] == 'skipped', entry
        if shell != mine:
            mismatches += 1
            print(text, shell, mine, sep='\n')
    assert mismatches == 0
