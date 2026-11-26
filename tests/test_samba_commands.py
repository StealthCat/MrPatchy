"""Samba smb.conf command contract (#1580).

Expected values replay ``testparm -s -v`` from Ubuntu 24.04 ``samba 2:4.19.5`` on the
same fixtures, and a native ``smbd -F`` run (guest connection with ``smbclient``) that
showed ``root preexec``/``root postexec`` writing uid 0, ``preexec`` writing the guest
uid 65534 and an ``available = no`` share refusing the tree connect without running its
command. Further native runs (#1581 review) showed that smbd adds ``IPC$`` from the final
``[global]`` defaults and runs its inherited ``root preexec`` as uid 0 and ``preexec`` as
the guest uid on every connection, that an explicit ``[IPC$]`` keeps its creation-time
snapshot and is forced available, and that ``force user = root``, ``force user = daemon``
and ``admin users = nobody`` ran ``preexec`` as uid 0, 1 and 0. ``test_live_testparm_differential`` repeats the comparison when ``testparm`` is
installed.
"""
import shutil
import subprocess

import pytest

from app import samba_commands as sc


def cmds(result, share=None):
    return {(c['share'], c['parameter']): c['command'] for c in result['commands'] if share is None or c['share'] == share}


def test_names_synonyms_sections_and_global_defaults():
    text = ('# comment\n; comment2\n[global]\n   Root PreExec = /bin/echo global-root\n'
            '   rootpostexec = /bin/gpost\n   EXEC = /bin/userpre\n   add user script = /usr/sbin/useradd %u\n'
            '[share1]\n   path = /srv/s1\n   root preexec = /bin/s1 \\\n       continued arg\n'
            '   preexec close = yes\n[Share1]\n   postexec = /bin/s1post\n[homes]\n   browseable = no\n'
            '[off]\n   available = no\n   root preexec=/bin/off\n[global]\n   root_preexec = /bin/underscore\n')
    r = sc.analyze(text)
    assert r['loads'] and r['complete'] and r['authorizes_response'] is False and r['origin'] == 'not_assessed'
    got = cmds(r)
    assert got[('share1', 'root preexec')] == '/bin/s1 continued arg'
    assert got[('share1', 'root postexec')] == '/bin/gpost'  # inherited [global] default
    assert got[('share1', 'preexec')] == '/bin/userpre'      # exec is a synonym
    assert got[('share1', 'postexec')] == '/bin/s1post'      # [Share1] reopens share1
    assert got[('homes', 'root preexec')] == '/bin/echo global-root'
    assert got[(None, 'add user script')] == '/usr/sbin/useradd %u'
    assert '/bin/underscore' not in got.values()             # underscores are not ignored
    pre = next(c for c in r['commands'] if c['share'] == 'share1' and c['parameter'] == 'preexec')
    assert pre['account'] == 'connecting_user' and pre['refuses_connection_on_failure'] is True
    off = next(c for c in r['commands'] if c['share'] == 'off')
    assert off['share_available'] is False and off not in r['root_commands']
    homes = next(c for c in r['commands'] if c['share'] == 'homes' and c['parameter'] == 'root preexec')
    assert homes['template'] == 'homes' and homes['account'] == 'root' and homes['line'] == 4


def test_share_snapshots_defaults_when_created():
    text = ('[global]\nroot preexec = /bin/g1\n[early]\npath = /srv/e\n[global]\nroot preexec = /bin/g2\n'
            'postexec = /bin/gp\n[late]\npath = /srv/l\n[early]\ncomment = reopened\n')
    got = cmds(sc.analyze(text))
    assert got[('early', 'root preexec')] == '/bin/g1' and ('early', 'postexec') not in got
    assert got[('late', 'root preexec')] == '/bin/g2' and got[('late', 'postexec')] == '/bin/gp'


def test_line_handling_matches_tini():
    text = ('root preexec = /bin/top\t\tx  \t y\r\n[cont]\r\npath=/c\nroot preexec = /bin/a\\\nb   \\\n   c\n'
            'postexec = x \\ y\npreexec = "/bin/quoted arg"   \n[ sp  ace ] trailing junk\n'
            'root postexec = /bin/a    b\tc   ; not comment # nor this\npreexec = a=b\ngarbage without equals\n'
            '[s]\npath=/s\n# root preexec = /bin/commented\n  ;root postexec = /bin/c2\nroot postexec = a \\\n# not comment\n')
    r = sc.analyze(text)
    got = cmds(r)
    assert got[('cont', 'root preexec')] == '/bin/ab c'
    assert got[('cont', 'postexec')] == 'x \\ y'
    assert got[('cont', 'preexec')] == '"/bin/quoted arg"'
    assert got[(' sp ace ', 'root postexec')] == '/bin/a b\tc ; not comment # nor this'
    assert got[(' sp ace ', 'preexec')] == 'a=b'
    assert got[(' sp ace ', 'root preexec')] == '/bin/top\tx y'  # top-of-file is [global]
    assert got[('s', 'root postexec')] == 'a # not comment'
    assert got[('s', 'root preexec')] == '/bin/top\tx y'


def test_spaced_global_header_and_global_only_parameter_in_share():
    r = sc.analyze('[ GLOBALS ]\nroot preexec = /bin/g\n[s]\npath=/s\nadd user script = /bin/au\n'
                   'Root   PreExec   Close = YES\n')
    got = cmds(r)
    assert got[('s', 'root preexec')] == '/bin/g' and (None, 'add user script') not in got
    assert any('ignored by Samba' in n for n in r['notes'])
    assert r['commands'][0]['refuses_connection_on_failure'] is True


@pytest.mark.parametrize('text', [
    '[s]\npath=/s\navailable = maybe\nroot preexec=/bin/x\n',
    '[s]\npath=/s\n = x\nroot preexec=/bin/x\n',
    '[s]\npath=/s\nroot preexec=/bin/x\n[s5\n',
])
def test_samba_rejects_whole_file(text):
    r = sc.analyze(text)
    assert r['loads'] is False and r['commands'] == [] and r['root_commands'] == [] and r['reject_reason']


def test_include_is_textual_and_missing_include_is_skipped():
    text = ('[s2]\npath = /srv/s2\ninclude = /etc/samba/inc.conf\npostexec = /bin/after-include\n'
            '[s3]\npath=/s3\ninclude = /etc/samba/missing.conf\ninclude = /etc/samba/nohdr.conf\n')
    r = sc.analyze(text, {'/etc/samba/inc.conf': '[incs]\npath=/srv/i\nroot postexec = /bin/inc\n',
                          '/etc/samba/missing.conf': None,
                          '/etc/samba/nohdr.conf': 'root postexec = /bin/noheader\n'})
    got = cmds(r)
    assert got[('incs', 'postexec')] == '/bin/after-include' and ('s2', 'postexec') not in got
    assert got[('incs', 'root postexec')] == '/bin/inc'
    assert got[('s3', 'root postexec')] == '/bin/noheader'
    src = next(c for c in r['commands'] if c['share'] == 's3')
    assert (src['file'], src['line']) == ('/etc/samba/nohdr.conf', 1)
    assert r['complete'] and any('absent' in n for n in r['notes'])


def test_self_include_exceeds_depth_and_rejects():
    r = sc.analyze('[s]\npath=/s\ninclude = /etc/samba/smb.conf\n',
                   {'/etc/samba/smb.conf': '[s]\npath=/s\ninclude = /etc/samba/smb.conf\n'})
    assert r['loads'] is False and 'include depth' in r['reject_reason']


@pytest.mark.parametrize('line, code', [
    ('include = /etc/samba/%m.conf', 'substituted_include'),
    ('include = registry', 'registry_configuration'),
    ('include = conf.d/x.conf', 'relative_include'),
    ('include = /etc/samba/unseen.conf', 'unobserved_include'),
    ('copy = homes', 'share_copy'),
])
def test_blocking_gaps(line, code):
    r = sc.analyze(f'[s]\npath=/s\n{line}\n')
    assert r['complete'] is False and [g['code'] for g in r['gaps']] == [code]


@pytest.mark.parametrize('text, code', [
    ('[global]\nconfig file = /etc/samba/%m.conf\n', 'alternate_configuration'),
    ('[global]\nconfig backend = registry\n', 'alternate_configuration'),
    ('[s]\npath=/s\x00\n', 'nul_byte'),
    ('[s]\npath=/s\ud800\n', 'invalid_utf8'),
    ('#' * (sc.MAX_TEXT_BYTES + 1), 'input_too_large'),
])
def test_input_gaps(text, code):
    r = sc.analyze(text)
    assert r['complete'] is False and r['gaps'][0]['code'] == code


def test_unobserved_config_and_not_evaluated_parameters():
    assert sc.analyze(None)['gaps'][0]['code'] == 'unobserved_config'
    r = sc.analyze('[global]\nconfig backend = file\nmessage command = /bin/msg %s\ndns update command = /bin/dns\n'
                   '[p]\npath=/p\nprint command = lpr %s\n')
    assert r['complete'] and r['configured_not_evaluated'] == ['dns update command', 'print command']
    msg = r['commands'][0]
    assert msg['parameter'] == 'message command' and msg['account'] == 'guest'


@pytest.mark.skipif(shutil.which('testparm') is None, reason='testparm not installed')
def test_live_testparm_differential(tmp_path):
    inc = tmp_path / 'inc.conf'
    inc.write_text('[incs]\nroot postexec = /bin/inc\n')
    text = (f'[global]\nroot preexec = /bin/g1\n EXEC = /bin/e \\ \n  more\nadd user script = /bin/au %u\n'
            f'[a]\npath=/a\npostexec = a  b\t\tc\n[ globals ]\nroot preexec = /bin/g2\n[B]\npath=/b\n'
            f'include = {inc}\npreexec = /bin/after\n[a]\nroot postexec = /bin/ra\n')
    conf = tmp_path / 'smb.conf'
    conf.write_text(text)
    r = sc.analyze(text, {str(inc): inc.read_text()}, config_path=str(conf))
    got = cmds(r)
    for share in r['shares']:
        if share in ('IPC$', 'ADMIN$'):
            continue  # testparm does not add the implicit IPC shares
        for param in sc.SHARE_COMMANDS:
            out = subprocess.run(['testparm', '-s', '-v', '--section-name', share, '--parameter-name', param,
                                  str(conf)], capture_output=True, text=True, check=True).stdout.rstrip('\n')
            assert out == got.get((share, param), ''), (share, param)


def test_implicit_ipc_share_takes_final_global_defaults():
    text = ("[global]\nroot preexec = /bin/g1\n[fu]\npath=/s\nroot preexec =\n"
            "[global]\nroot preexec = /bin/g2\npreexec = /bin/gpre\n")
    r = sc.analyze(text)
    got = cmds(r)
    assert ('fu', 'root preexec') not in got
    assert got[('IPC$', 'root preexec')] == '/bin/g2' and got[('IPC$', 'preexec')] == '/bin/gpre'
    ipc = [c for c in r['root_commands'] if c['share'] == 'IPC$']
    assert len(ipc) == 1 and ipc[0]['implicit_share'] is True and ipc[0]['line'] == 7
    assert r['complete']
    # Only [global]: the review's case where no ordinary share inherits the command.
    only = sc.analyze('[global]\nroot preexec = /bin/only\n')
    assert [(c['share'], c['account']) for c in only['root_commands']] == [('IPC$', 'root')]


def test_explicit_ipc_section_keeps_snapshot_and_is_forced_available():
    text = ("[IPC$]\nroot preexec = /bin/explicit\navailable = no\n"
            "[global]\nforce user = root\npreexec = /bin/gpre\n[plain]\npath=/s\n")
    r = sc.analyze(text)
    got = cmds(r)
    assert got[('IPC$', 'root preexec')] == '/bin/explicit' and ('IPC$', 'preexec') not in got
    ipc = next(c for c in r['commands'] if c['share'] == 'IPC$')
    assert ipc['share_available'] is True and ipc['implicit_share'] is False
    plain = next(c for c in r['commands'] if c['share'] == 'plain')
    assert plain['account'] == 'root' and plain['forced_user'] == 'root' and plain in r['root_commands']


def test_admin_share_only_with_asu_support():
    assert ('ADMIN$', 'root preexec') not in cmds(sc.analyze('[global]\nroot preexec = /bin/g\n'))
    r = sc.analyze('[global]\nenable asu support = yes\nroot preexec = /bin/g\n')
    assert cmds(r)[('ADMIN$', 'root preexec')] == '/bin/g'
    assert sc.analyze('[global]\nenable asu support = perhaps\n')['loads'] is False


def test_force_user_and_admin_users_accounts():
    text = ("[fu]\npath=/s\nforce user = root\npreexec = /bin/fu\nroot postexec = /bin/rp\n"
            "[adm]\npath=/s\nadmin users = nobody @wheel\npreexec = /bin/adm\n"
            "[dmn]\npath=/s\nforce user = daemon\npostexec = /bin/dmn\n"
            "[toor]\npath=/s\nforce user = toor\npreexec = /bin/toor\n"
            "[plain]\npath=/s\npreexec = /bin/plain\n")
    passwd = 'root:x:0:0::/root:/bin/sh\ndaemon:x:1:1::/:/bin/false\ntoor:x:0:0::/root:/bin/sh\n'
    r = sc.analyze(text, passwd_text=passwd)
    by = {c['share']: c for c in r['commands'] if c['parameter'] in ('preexec', 'postexec')}
    assert by['fu']['account'] == 'root' and by['toor']['account'] == 'root'
    assert by['dmn']['account'] == 'forced_user' and by['dmn']['forced_user'] == 'daemon'
    assert by['adm']['account'] == 'connecting_user' and by['adm']['root_for_admin_users'] == 'nobody @wheel'
    assert by['plain']['account'] == 'connecting_user' and by['plain']['root_for_admin_users'] is None
    roots = {(c['share'], c['parameter']) for c in r['root_commands']}
    assert roots == {('fu', 'preexec'), ('fu', 'root postexec'), ('toor', 'preexec'), ('adm', 'preexec')}
    assert r['complete']


@pytest.mark.parametrize('value, passwd', [
    ('daemon', None),             # no /etc/passwd captured: uid unknown
    ('ghost', 'root:x:0:0::/:/bin/sh\n'),
    ('%U', 'root:x:0:0::/:/bin/sh\n'),
])
def test_unresolved_force_user_is_blocking(value, passwd):
    r = sc.analyze(f'[s]\npath=/s\nforce user = {value}\npreexec = /bin/x\n', passwd_text=passwd)
    cmd = next(c for c in r['commands'] if c['share'] == 's')
    assert cmd['account'] == 'not_assessed' and r['complete'] is False
    assert {g['code'] for g in r['gaps']} == {'unresolved_force_user'}
