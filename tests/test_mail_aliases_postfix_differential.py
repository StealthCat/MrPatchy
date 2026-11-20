"""Live differentials for the Postfix aliases contract (#1215).

Two tiers, both skipped when the binaries are absent:

* ``postalias`` tier: builds each generated aliases file with the real
  ``postalias`` and dumps it with ``postalias -s``. The keys, lowercase folding,
  first-value-wins duplicates, skipped lines and joined continuation text
  must match ``mail_aliases.resolve``. Runs as any user when ``postalias`` is
  on ``PATH``.
* ``local(8)`` tier: delivers through a running Postfix. ``sendmail -bv``
  reports which targets ``local(8)`` delivers to a command or a file, and real
  deliveries of ``|id -un`` show the run-as user. This tier rewrites the
  system ``/etc/aliases`` and ``main.cf`` and restores them, so it needs root
  and ``MRPATCHY_POSTFIX_DIFFERENTIAL=1``.

Recorded against Postfix 3.8.6 (Ubuntu 3.8.6-1ubuntu0.1).
"""
import os
import random
import re
import shutil
import subprocess
import time
from pathlib import Path

import pytest

from app import mail_aliases as ma

POSTALIAS = shutil.which('postalias') or (os.path.exists('/usr/sbin/postalias') and '/usr/sbin/postalias')
ROOT = {'trusted': True, 'user': 'root'}

KEYS = ['root', 'Root', 'ROOT', 'backup', 'Backup', '"odd name"', '"Q\\"k"', 'a.b', 'x@y', 'a%b', 'a,b',
        'list-x', 'm_1', '"MiXed"']
VALUES = ['root', '"|/usr/bin/x arg"', '|/opt/h', '/var/log/f', '~/mbox', '~bob/m', ':include:/etc/l',
          ':INCLUDE:/x', 'user@remote.example', '"|/bin/a\\"b"', 'b (note)', '"q, comma"', 'a b', '<x@y>',
          '[1.2.3.4]', '"|cmd"  ', '\\|/esc']
SEPARATORS = [', ', ',', ' , ', ',\n  ', ',\n\t', ',\n# c\n  ', ',\n\n ']


def generate(rng):
    lines = []
    for _ in range(rng.randint(1, 6)):
        roll = rng.random()
        if roll < 0.06:
            lines.append('# comment')
        elif roll < 0.10:
            lines.append('   ' + rng.choice(VALUES))
        elif roll < 0.13:
            lines.append('')
        elif roll < 0.16:
            lines.append(rng.choice(KEYS))
        else:
            value = ''
            for i in range(rng.randint(0, 3)):
                value += (rng.choice(SEPARATORS) if i else rng.choice([' ', '\t', '', '  '])) + rng.choice(VALUES)
            lines.append(rng.choice(KEYS) + rng.choice([':', ' :', ': ']) + value)
    return '\n'.join(lines) + rng.choice(['\n', ''])


def postalias_dump(text, workdir):
    # A non-default config directory costs ~2 s per call, so use the system
    # one when it exists; only the default database type is read from it.
    config = []
    if not Path('/etc/postfix/main.cf').exists():
        (workdir / 'config').mkdir(exist_ok=True)
        (workdir / 'config' / 'main.cf').write_text('myhostname = diff.example\n')
        config = ['-c', str(workdir / 'config')]
    source = workdir / 'aliases'
    source.write_text(text)
    subprocess.run([POSTALIAS, *config, f'hash:{source}'], check=True, capture_output=True)
    out = subprocess.run([POSTALIAS, *config, '-s', f'hash:{source}'],
                         check=True, capture_output=True, text=True).stdout
    dump = {}
    for line in out.splitlines():
        key, _, value = line.partition(':\t')
        if key != '@' and not key.startswith('YP_'):
            dump[key] = value
    return dump


def targets_of_stored_value(value):
    entry = next(e for e in ma.resolve({'observed': True, 'text': f'k: {value}\n', 'owner': ROOT})['entries']
                 if e.get('name') == 'k')
    return entry.get('targets')


def mismatches(text, workdir):
    dump = postalias_dump(text, workdir)
    result = ma.resolve({'observed': True, 'text': text, 'owner': ROOT})
    names = {e['name']: e for e in result['entries'] if 'name' in e and e['status'] != 'duplicate_ignored'}
    problems = []
    if any(e.get('reason') == 'complex_key_not_modeled' for e in result['entries']):
        # The contract leaves complex keys unresolved (a gap), so only check
        # that every name it does report really is a key.
        if not set(names) <= set(dump):
            problems.append(('keys', sorted(names), sorted(dump)))
    elif set(names) != set(dump):
        problems.append(('keys', sorted(names), sorted(dump)))
    for name, entry in names.items():
        if name in dump and targets_of_stored_value(dump[name]) != entry.get('targets'):
            problems.append(('value', name, dump[name], entry.get('targets')))
    return problems


@pytest.mark.skipif(not POSTALIAS, reason='postalias not installed')
def test_generated_aliases_match_real_postalias(tmp_path):
    rng = random.Random(1215)
    failures = []
    for _ in range(int(os.environ.get('MRPATCHY_POSTALIAS_CASES', '400'))):
        text = generate(rng)
        problems = mismatches(text, tmp_path)
        if problems:
            failures.append((text, problems))
    assert failures == []


@pytest.mark.skipif(not POSTALIAS, reason='postalias not installed')
@pytest.mark.parametrize('text', [
    'Root: "|/first"\nroot: "|/second"\n',
    'a: b,\n# comment inside\n\n   "|/run me"\n  # indented comment\nc: d\n',
    '   "|/orphan"\nx: y\n',
    'no colon here\n: value\nname:\na, b: c\na@example.com: c\na%b: c\nok: yes\n',
    '"odd name": "|/bin/a\\"b"\n',
    'esc: \\|/esc\n',
])
def test_fixed_cases_match_real_postalias(tmp_path, text):
    assert mismatches(text, tmp_path) == []


# --- local(8) tier --------------------------------------------------------

LIVE = (os.environ.get('MRPATCHY_POSTFIX_DIFFERENTIAL') == '1' and POSTALIAS
        and hasattr(os, 'geteuid') and os.geteuid() == 0 and shutil.which('sendmail'))
DOMAIN = 'diff.example'
LIVE_ALIASES = """postmaster: root
c1: "|/usr/bin/x arg", /var/tmp/f1, ~/mbox, ~bob/m, nosuchuser, "|cmd"
c2: |/opt/h
c3: "/tmp/sp ace"
c4: \\|/esc
c5: "q, comma", :include:/etc/nonexistent-mrpatchy
Mixed: "|/first"
mixed: "|/second"
"""


@pytest.fixture
def live_postfix(tmp_path):
    if not LIVE:
        pytest.skip('set MRPATCHY_POSTFIX_DIFFERENTIAL=1 and run as root with Postfix installed')
    saved = {p: Path(p).read_bytes() for p in ('/etc/aliases', '/etc/postfix/main.cf') if Path(p).exists()}
    settings = {'myhostname': DOMAIN, 'mydestination': '$myhostname, localhost', 'inet_interfaces': 'loopback-only',
                'inet_protocols': 'ipv4', 'alias_maps': 'hash:/etc/aliases', 'alias_database': 'hash:/etc/aliases',
                'maillog_file': '/var/log/postfix-mrpatchy-diff.log'}
    subprocess.run(['postconf', '-e'] + [f'{k}={v}' for k, v in settings.items()], check=True, capture_output=True)
    if subprocess.run(['postfix', 'status'], capture_output=True).returncode != 0:
        subprocess.run(['postfix', 'start'], check=True, capture_output=True)
    try:
        yield Path(settings['maillog_file'])
    finally:
        for path, data in saved.items():
            Path(path).write_bytes(data)
        subprocess.run(['newaliases'], capture_output=True)
        subprocess.run(['postfix', 'reload'], capture_output=True)


def install(aliases, **main_cf):
    Path('/etc/aliases').write_text(aliases)
    subprocess.run(['newaliases'], check=True, capture_output=True)
    if main_cf:
        subprocess.run(['postconf', '-e'] + [f'{k}={v}' for k, v in main_cf.items()], check=True, capture_output=True)
    subprocess.run(['postfix', 'reload'], check=True, capture_output=True)
    time.sleep(1)


def verify_report(*names):
    """Run ``sendmail -bv`` and return the unfolded per-recipient report lines."""
    mailbox = Path('/var/mail/root')
    mailbox.write_text('')
    subprocess.run(['sendmail', '-bv', *names], input=b'', check=True, capture_output=True)
    for _ in range(100):
        if 'Message-Id' in mailbox.read_text(errors='replace'):
            break
        time.sleep(0.2)
    time.sleep(0.5)
    text = mailbox.read_text(errors='replace')
    section = text.split('Content-Description: Notification', 1)[-1].split('\n--', 1)[0]
    return [line for line in re.sub(r'\n[ \t]+', ' ', section).splitlines() if line.startswith('<')]


def delivered(lines):
    found = []
    for line in lines:
        match = re.match(r'<[^>]*> \(expanded from <([^>]*)>\): delivery via local: delivers to (command|file): (.*)$',
                         line)
        if match:
            found.append((match.group(1).lower(), match.group(2), match.group(3)))
    return sorted(found)


def contract_deliveries(aliases, **source):
    result = ma.resolve({'observed': True, 'text': aliases, 'owner': ROOT, **source})
    out = []
    for entry in result['entries']:
        for target in entry.get('targets', []) if entry.get('status') != 'duplicate_ignored' else []:
            if target.get('allowed') and target.get('kind') in ('command', 'file', 'home_file'):
                out.append((entry['name'], 'command' if target['kind'] == 'command' else 'file', target['value']))
    return sorted(out)


def test_local_delivers_exactly_the_contract_command_and_file_targets(live_postfix):
    install(LIVE_ALIASES, allow_mail_to_commands='alias, forward', allow_mail_to_files='alias, forward')
    names = ['c1', 'c2', 'c3', 'c4', 'c5', 'mixed']
    expected = contract_deliveries(LIVE_ALIASES)
    assert expected == [('c1', 'command', '/usr/bin/x arg'), ('c1', 'command', 'cmd'), ('c1', 'file', '/var/tmp/f1'),
                        ('c2', 'command', '/opt/h'), ('c3', 'file', '/tmp/sp ace'), ('c4', 'command', '/esc'),
                        ('mixed', 'command', '/first')]
    assert delivered(verify_report(*names)) == expected
    install(LIVE_ALIASES, allow_mail_to_commands='forward', allow_mail_to_files='forward')
    report = verify_report(*names)
    assert delivered(report) == contract_deliveries(
        LIVE_ALIASES, allow_mail_to_commands='forward', allow_mail_to_files='forward') == []
    assert any('mail to command is restricted' in line for line in report)
    install(LIVE_ALIASES, allow_mail_to_commands='alias, forward', allow_mail_to_files='alias, forward')


@pytest.mark.parametrize('privs,owner,expected', [
    ('nobody', 'root', 'nobody'),
    ('daemon', 'root', 'daemon'),
    ('nobody', 'daemon', 'daemon'),
])
def test_commands_run_as_the_contract_user(live_postfix, privs, owner, expected):
    # The probe exits 1, so local(8) bounces the message and logs the command
    # output (the run-as user) without the test needing a writable directory.
    tag = f'RUNAS-{privs}-{owner}'
    aliases = f'postmaster: root\nprobe: "|echo {tag}=$(/usr/bin/id -un); exit 1"\n'
    install(aliases, default_privs=privs)
    shutil.chown('/etc/aliases.db', user=owner)
    subprocess.run(['postfix', 'reload'], check=True, capture_output=True)
    time.sleep(1)
    pattern = re.compile(re.escape(tag) + r'=(\S+)')
    try:
        subprocess.run(['sendmail', 'probe'], input=b'Subject: probe\n\nprobe\n', check=True)
        actual = []
        for _ in range(100):
            log = live_postfix.read_text(errors='replace') if live_postfix.exists() else ''
            actual = pattern.findall(log)[-1:]
            if actual:
                break
            time.sleep(0.2)
    finally:
        shutil.chown('/etc/aliases.db', user='root')
        subprocess.run(['postconf', '-e', 'default_privs=nobody'], capture_output=True)
        if live_postfix.exists():
            live_postfix.write_text('')
    contract = ma.resolve({'observed': True, 'text': aliases, 'default_privs': privs,
                           'owner': {'trusted': owner == 'root', 'user': owner}})
    assert [e['run_as'] for e in contract['executions']] == [expected] == actual
