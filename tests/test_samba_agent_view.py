"""Agent-reduced Samba files evaluate exactly like the full files (#1580 increment 3).

Agents cannot import the controller. They build tini.c logical lines from the hashed bytes of every regular
file under /etc/samba with their own copy of the app/samba_commands line rules and keep only section
headers, the parameters the contract tracks and the line Samba rejects a file at. The controller validates
those lines and runs the contract on them. These tests compare that path with the contract run on the full
original text, over the contract's own fixtures and a seeded random grammar.
"""
import copy
import random
import time

import pytest

from app import persistence, startup_inventory as si
from app import samba_commands as sc
from target import agent

CONF = '/etc/samba/smb.conf'
SECRET = 'hunter2-not-real'


def _report(text, path=CONF):
    report = agent.parse_smb_conf(text.encode('utf-8') if isinstance(text, str) else text)
    persistence.validate_samba(report, path)
    return report


def _comparable(result):
    return {k: result[k] for k in ('loads', 'reject_reason', 'commands', 'root_commands', 'shares',
                                   'configured_not_evaluated', 'notes', 'gaps', 'complete')}


def _same(main, includes=None):
    includes = includes or {}
    full = sc.analyze(main, includes)
    reduced = sc.analyze(si.samba_lines(_report(main)),
                         {p: (None if t is None else si.samba_lines(_report(t, p))) for p, t in includes.items()})
    assert _comparable(reduced) == _comparable(full)
    return full


FIXTURES = [
    ('# comment\n; comment2\n[global]\n   Root PreExec = /bin/echo global-root\n'
     '   rootpostexec = /bin/gpost\n   EXEC = /bin/userpre\n   add user script = /usr/sbin/useradd %u\n'
     '[share1]\n   path = /srv/s1\n   root preexec = /bin/s1 \\\n       continued arg\n'
     '   preexec close = yes\n[Share1]\n   postexec = /bin/s1post\n[homes]\n   browseable = no\n'
     '[off]\n   available = no\n   root preexec=/bin/off\n[global]\n   root_preexec = /bin/underscore\n'),
    ('root preexec = /bin/top\t\tx  \t y\r\n[cont]\r\npath=/c\nroot preexec = /bin/a\\\nb   \\\n   c\n'
     'postexec = x \\ y\npreexec = "/bin/quoted arg"   \n[ sp  ace ] trailing junk\n'
     'root postexec = /bin/a    b\tc   ; not comment # nor this\npreexec = a=b\ngarbage without equals\n'
     '[s]\npath=/s\n# root preexec = /bin/commented\n  ;root postexec = /bin/c2\nroot postexec = a \\\n# not comment\n'),
    '[ GLOBALS ]\nroot preexec = /bin/g\n[s]\npath=/s\nadd user script = /bin/au\nRoot   PreExec   Close = YES\n',
    '[s]\npath=/s\navailable = maybe\nroot preexec=/bin/x\n',
    '[s]\npath=/s\n = x\nroot preexec=/bin/x\n',
    '[s]\npath=/s\nroot preexec=/bin/x\n[s5\nroot postexec = /bin/after\n',
    '[global]\nroot preexec = /bin/g\npreexec = /bin/p\nenable asu support = yes\n[IPC$]\navailable = no\n',
    '[s]\nforce user = root\nadmin users = @wheel\npreexec = /bin/p\npostexec = /bin/q\ncopy = homes\n',
    '[global]\nconfig backend = registry\nprint command = lpr %s\ndfree command = /bin/df\n[p]\nmagic script = m.sh\n',
    '[s]\npath=/s\ninclude = /etc/samba/%m.conf\ninclude = registry\ninclude = conf.d/x.conf\n',
    'root preexec = ends with backslash at eof \\',
    '',
]


@pytest.mark.parametrize('text', FIXTURES)
def test_reduced_lines_match_full_text(text):
    _same(text)


def test_includes_absent_and_unobserved_match_full_text():
    main = ('[s2]\npath = /srv/s2\ninclude = /etc/samba/inc.conf\npostexec = /bin/after-include\n'
            '[s3]\npath=/s3\ninclude = /etc/samba/missing.conf\ninclude = /etc/samba/nohdr.conf\n'
            'include = /etc/samba/unseen.conf\n')
    full = _same(main, {'/etc/samba/inc.conf': '[incs]\npath=/srv/i\nroot postexec = /bin/inc\n',
                        '/etc/samba/missing.conf': None,
                        '/etc/samba/nohdr.conf': 'root postexec = /bin/noheader\n'})
    assert [g['code'] for g in full['gaps']] == ['unobserved_include']
    _same('[s]\ninclude = /etc/samba/smb.conf\n', {CONF: '[s]\ninclude = /etc/samba/smb.conf\n'})


BOOLEANS = ('available', 'preexec close', 'root preexec close', 'enable asu support')


def _random_text(rng):
    names = ['root preexec', 'ROOT  PREEXEC', 'preexec', 'exec', 'postexec', 'root postexec', 'available',
             'preexec close', 'root preexec close', 'force user', 'admin users', 'add user script', 'panic action',
             'path', 'comment', 'workgroup', 'passdb backend', 'copy', 'print command', 'enable asu support']
    values = ['/bin/x', '/bin/a  b', 'yes', 'no', 'root', '%U', '', 'a=b', ' padded ', '\\\nnext']
    lines = []
    for _ in range(rng.randint(0, 25)):
        roll = rng.random()
        if roll < 0.01:
            lines.append(rng.choice(['[broken', '=x', 'available = maybe']))  # Samba rejects the whole file
        elif roll < 0.15:
            lines.append(rng.choice(['[global]', '[s]', '[S]', '[homes]', '[IPC$]', '[ x ] tail']))
        elif roll < 0.25:
            lines.append(rng.choice(['# c', '; c', '', '   ', 'no equals', '\t\t']))
        else:
            sep = rng.choice(['=', ' = ', '\t=\t', '  =  '])
            name = rng.choice(names)
            value = rng.choice(['yes', 'No', 'TRUE', '0']) if name.lower() in BOOLEANS else rng.choice(values)
            lines.append(rng.choice(['', ' ', '\t']) + name + sep + value
                         + rng.choice(['', ' ', '\\']))
    return rng.choice(['\n', '\r\n']).join(lines) + rng.choice(['', '\n'])


@pytest.mark.parametrize('seed', range(4))
def test_seeded_random_grammar_matches_full_text(seed):
    rng = random.Random(1580 + seed)
    for _ in range(300):
        _same(_random_text(rng))


def test_agent_tracks_exactly_the_contract_parameters():
    assert set(agent.SAMBA_KEYS) == set(sc.TRACKED_NAMES)
    assert {k for k in agent.SAMBA_KEYS if k in agent.SAMBA_COMMAND_KEYS} == {
        k for k in sc.TRACKED_NAMES if sc.command_parameter(k)}


def test_other_lines_are_dropped_and_commands_redacted():
    text = (f'[global]\nworkgroup = W\nldap admin dn = cn=admin password={SECRET}\n'
            f'root preexec = /bin/notify --password={SECRET} %S\nforce user = svc\n'
            f'user1:1000:{SECRET}:ABCDEF:[U          ]:LCT-0:\n')
    report = _report(text)
    assert SECRET not in repr(report) and report['dropped'] == 3
    assert [i['op'] for i in report['lines']] == ['section', 'set', 'set']
    command = report['lines'][1]
    assert command['redacted'] is True and '[REDACTED]' in command['value']
    assert report['lines'][2] == {'line': 5, 'op': 'set', 'name': 'force user', 'value': 'svc', 'redacted': False}


@pytest.mark.parametrize('data, error', [(b'[s]\nroot preexec = /x\x00\n', 'nul_byte'), (b'[s]\n\xff\n', 'invalid_utf8')])
def test_nul_and_non_utf8_files_are_not_parsed(data, error):
    report = _report(data)
    assert report == {'parsed': False, 'error': error, 'lines': [], 'dropped': 0, 'truncated': False}
    assert [g['code'] for g in sc.analyze(si.samba_lines(report))['gaps']] == [error]


def test_line_limit_truncates():
    report = _report('[s]\n' + 'root preexec = /x\n' * (agent.SAMBA_LINE_LIMIT + 5))
    assert report['truncated'] is True and len(report['lines']) == agent.SAMBA_LINE_LIMIT


def _valid():
    return _report('[s]\nroot preexec = /bin/x --token=abc\npath = /s\n[t\n')


@pytest.mark.parametrize('mutate', [
    lambda r: r['lines'].append({'line': 99, 'op': 'section', 'name': 'late'}),
    lambda r: r['lines'][1].update(name='path'),
    lambda r: r['lines'][1].update(name='workgroup'),
    lambda r: r['lines'][1].update(name=' root preexec'),
    lambda r: r['lines'][1].update(line=1),
    lambda r: r['lines'][1].update(value='x\ny'),
    lambda r: r['lines'][1].update(value='x' * 4097),
    lambda r: r['lines'][0].update(name='a]b'),
    lambda r: r['lines'][2].update(reason='other'),
    lambda r: r['lines'][1].update(extra=1),
    lambda r: r.update(parsed=False),
    lambda r: r.update(error='nul_byte'),
    lambda r: r.update(dropped=-1),
    lambda r: r.pop('truncated'),
])
def test_validation_rejects_reports_agents_do_not_produce(mutate):
    report = _valid()
    mutate(report)
    with pytest.raises(ValueError):
        persistence.validate_samba(report, CONF)


def test_validation_rejects_redaction_flags_on_non_commands_and_paths_outside_samba():
    report = _report('[s]\nforce user = svc\n')
    report['lines'][1]['redacted'] = True
    with pytest.raises(ValueError):
        persistence.validate_samba(report, CONF)
    with pytest.raises(ValueError):
        persistence.validate_samba(_report('[s]\n'), '/etc/sambax/smb.conf')


def _entry(path, text=None, kind='regular', samba=True):
    row = {'path': path, 'kind': kind, 'uid': 0, 'gid': 0, 'mode': 0o644, 'size': 1, 'mtime_ns': 0}
    if kind == 'regular':
        row['sha256'] = '0' * 64
        if samba:
            row['samba'] = _report(text, path)
    else:
        row['target'] = '/elsewhere'
    return row


def _inventory(*entries, state='collected'):
    inventory = {'state': state, 'entries': list(entries), 'missing_roots': [], 'scope': ['/etc/samba'], 'gaps': [],
                 'skipped': 0}
    persistence.validate(inventory)
    return inventory


def test_view_evaluates_includes_absent_files_and_never_authorizes():
    inventory = _inventory(
        _entry(CONF, '[global]\nroot preexec = /bin/audit %S\ninclude = /etc/samba/shares.conf\n'
                     'include = /etc/samba/gone.conf\ninclude = /opt/outside.conf\n'),
        _entry('/etc/samba/shares.conf', '[data]\npath = /srv/data\npreexec = /bin/log %u\npreexec close = yes\n'))
    view = si.samba_view(inventory)
    assert view['authorizes_response'] is False and view['origin'] == 'not_assessed' and view['loads'] is True
    got = {(c['share'], c['parameter']): (c['command'], c['account'], c['file'], c['line']) for c in view['commands']}
    assert got[('data', 'root preexec')] == ('/bin/audit %S', 'root', CONF, 2)
    assert got[('data', 'preexec')] == ('/bin/log %u', 'connecting_user', '/etc/samba/shares.conf', 3)
    assert got[('IPC$', 'root preexec')][1] == 'root'
    assert view['shares'] == ['IPC$', 'data'] and view['root_commands'] == 2
    assert any('gone.conf is absent' in n for n in view['notes'])
    codes = [g['code'] for g in view['gaps'] if g['blocking']]
    assert codes == ['unobserved_include'] and view['complete'] is False
    # The same file in an incomplete collection is not known to be absent.
    partial = si.samba_view(_inventory(*copy.deepcopy(inventory['entries']), state='incomplete'))
    assert [g['code'] for g in partial['gaps'] if g['blocking']] == ['unobserved_include', 'unobserved_include']


def test_older_agent_symlink_truncated_and_rejected_files_are_explained():
    old = si.samba_view(_inventory(_entry(CONF, '[s]\ninclude = /etc/samba/old.conf\n'),
                                   _entry('/etc/samba/old.conf', samba=False),
                                   _entry('/etc/samba/link.conf', kind='symlink')))
    blocking = [(g['code'], g.get('path')) for g in old['gaps'] if g['blocking']]
    assert ('not_reported_by_agent', '/etc/samba/old.conf') in blocking
    assert ('symlink_not_followed', '/etc/samba/link.conf') in blocking
    assert ('unobserved_include', None) in blocking
    rejected = si.samba_view(_inventory(_entry(CONF, '[s]\nroot preexec = /bin/x\n[broken\n')))
    assert rejected['loads'] is False and rejected['commands'] == [] and ':3: section header without ]' in rejected['reject_reason']
    rows = si.catalog_rows(_inventory(_entry(CONF, '[s]\n'), _entry('/etc/samba/lmhosts', samba=False)))
    label = next(r['label'] for r in rows if r['id'] == 'samba')
    assert '1 parsed file' in label and 'not reported by this agent version' in label


def test_agent_parses_the_hashed_bytes_without_running_anything(tmp_path, monkeypatch):
    marker = tmp_path / 'ran'
    root = tmp_path / 'samba'
    root.mkdir()
    (root / 'smb.conf').write_text(f'[global]\nroot preexec = touch {marker}\ninclude = {root}/shares.conf\n'
                                   f'ldap admin dn = cn=x,password={SECRET}\n')
    (root / 'shares.conf').write_text('[data]\npath = /srv/data\npostexec = /bin/done %u\n')
    (root / 'smbpasswd').write_text(f'user:1000:{SECRET}:{SECRET}:[U ]:LCT-0:\n')
    (root / 'link.conf').symlink_to(root / 'smb.conf')
    monkeypatch.setattr(agent, 'PERSISTENCE_ROOTS', (str(root),))
    monkeypatch.setattr(agent, 'PERSISTENCE_FILES', ())
    monkeypatch.setattr(agent, 'SAMBA_DIR', str(root))
    result = agent.persistence_inventory(time.monotonic() + 5, cron_jobs=True)
    assert not marker.exists() and SECRET not in repr(result)
    rows = {r['path']: r for r in result['entries']}
    assert 'samba' not in rows[str(root / 'link.conf')]
    assert rows[str(root / 'smbpasswd')]['samba']['lines'] == []
    inventory = eval(repr(result).replace(str(root), '/etc/samba'))  # noqa: S307 - repr of plain literals produced above
    inventory['scope'] = ['/etc/samba']
    persistence.validate(inventory)
    view = si.samba_view(inventory)
    got = {(c['share'], c['parameter']): c['command'] for c in view['commands']}
    assert got[('data', 'root preexec')] == f"touch {str(marker).replace(str(root), '/etc/samba')}"
    assert got[('data', 'postexec')] == '/bin/done %u'
    page_rows = [r for r in [si.samba_state(e) for e in inventory['entries']] if r]
    assert 'parsed' in page_rows
    without = agent.persistence_inventory(time.monotonic() + 5, cron_jobs=False)
    assert all('samba' not in r for r in without['entries'])
