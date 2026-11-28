"""Agent-side PostgreSQL statement reduction, controller validation and Startup Files evaluation (#1597 increment 3)."""
from __future__ import annotations

import copy
import random
import time

import pytest

from app import persistence, startup_inventory
from app import postgresql_commands as pc
from target import agent

PG = '/etc/postgresql'
CONF = '/etc/postgresql/16/main/postgresql.conf'
CONFD = '/etc/postgresql/16/main/conf.d'
SECRET = 'hunter2-not-real'


def reduced(text, path=CONF):
    return agent.parse_postgresql(text.encode(), path)


def rebuilt(text, path=CONF):
    return startup_inventory.postgresql_text(reduced(text, path))


def comparable(result):
    out = {k: result[k] for k in ('data_directory', 'auto_conf', 'has_errors', 'server_starts', 'files_read', 'settings',
                                  'commands', 'libraries', 'gaps', 'complete')}
    out['start_blocker'] = result.get('start_blocker')
    out['dynamic_library_path'] = result.get('dynamic_library_path')
    # 'near' quotes the rejected text, which the agent does not retain; everything else must match.
    out['errors'] = [{k: v for k, v in e.items() if k != 'near'} for e in result['errors']]
    return out


def both(texts, directories=None, config=CONF, data_dir=None):
    raw = {p: {'state': 'regular', 'text': t} for p, t in texts.items()}
    built = {p: {'state': 'regular', 'text': rebuilt(t, p)} for p, t in texts.items()}
    first = pc.assess(raw, config_file=config, data_dir=data_dir, directories=directories)
    second = pc.assess(built, config_file=config, data_dir=data_dir, directories=directories)
    return first, second


STOCK_LIKE = f'''# Debian-style postgresql.conf
data_directory = '/var/lib/postgresql/16/main'\t\t# use data in another directory
hba_file = '/etc/postgresql/16/main/pg_hba.conf'
port = 5432
max_connections = 100
ssl = on
ssl_cert_file = '/etc/ssl/certs/ssl-cert-snakeoil.pem'
ssl_passphrase_command = '/usr/local/bin/pass --token={SECRET} %p'
shared_buffers = 128MB
wal_level = replica
archive_mode = ON
ARCHIVE_COMMAND = 'test ! -f /mnt/arch/%f && cp %p /mnt/arch/%f'
shared_preload_libraries = 'pg_stat_statements, "my lib", auth_delay'
primary_conninfo = 'host=db password={SECRET}'
datestyle 'iso, mdy'
timezone = Etc/UTC
random_page_cost = 1.1
effective_io_concurrency 0x10
include_dir = 'conf.d'
include_if_exists = 'missing.conf'
include = '/etc/postgresql/16/main/extra.conf'
this is = not valid
'''
EXTRA = r'''restore_command = 'cp /mnt/arch/%f "%p" # it''s quoted \' \\ \n\101'
recovery_end_command = 'bad %x'
local_preload_libraries = 'unterminated "list'
dynamic_library_path = '$libdir:/opt/pg'
archive_library = ''
'''
CONFD_FILE = '''session_preload_libraries = auto_explain
ssl_passphrase_command_supports_reload = true
'''


def test_rebuilt_text_evaluates_exactly_like_the_captured_text():
    directories = {CONFD: {'state': 'present', 'entries': [{'name': '10-local.conf', 'kind': 'file'},
                                                          {'name': '.hidden.conf', 'kind': 'file'},
                                                          {'name': 'sub.conf', 'kind': 'dir'}]}}
    # Redaction intentionally changes a credential-bearing command, so equivalence is checked without one.
    texts = {CONF: STOCK_LIKE.replace(f' --token={SECRET}', ''), '/etc/postgresql/16/main/extra.conf': EXTRA,
             CONFD + '/10-local.conf': CONFD_FILE}
    first, second = both(texts, directories)
    assert comparable(first) == comparable(second)
    commands = {c['setting']: c for c in second['commands']}
    assert commands['archive_command']['active'] is False and commands['recovery_end_command']['placeholder_error']
    assert first['has_errors'] and first['server_starts'] is False
    assert [r['library'] for r in second['libraries'] if r['setting'] == 'shared_preload_libraries'] == ['pg_stat_statements', 'my lib', 'auth_delay']
    # Without the syntax error the server starts and the evaluation is still identical.
    texts[CONF] = texts[CONF].replace('this is = not valid\n', '')
    first, second = both(texts, directories)
    assert comparable(first) == comparable(second) and second['server_starts'] is True
    assert {c['setting']: c['active'] for c in second['commands']}['archive_command'] is True


_FRAGMENTS = [
    "archive_mode = on", "archive_mode = always", "archive_mode off", "archive_mode = 'maybe'", "Archive_Mode=TRUE",
    "wal_level = minimal", "wal_level = 'logical'", "wal_level=hot_standby",
    "archive_command = 'cp %p /a/%f'", "archive_command = 'x %z'", "archive_command = '%'", "archive_command=''",
    "archive_command = '/bin/run\\ttab\\001 \\'q\\' ''q'' \\\\'", "archive_library = 'basic_archive'",
    "restore_command 'cp /a/%f %p'", "recovery_end_command = 'echo %r'", "archive_cleanup_command = 'pg_archivecleanup /a %r'",
    "ssl = off", "ssl = 'yes'", "ssl = o", "ssl_passphrase_command = 'echo %p'", "ssl_passphrase_command_supports_reload = on",
    "shared_preload_libraries = 'a,b'", "shared_preload_libraries = '\"x,y\", z'", "shared_preload_libraries = 'a,'",
    "session_preload_libraries = foo", "local_preload_libraries = '$libdir/plugins/x'", "dynamic_library_path = '/opt'",
    "data_directory = '/var/lib/postgresql/16/main'", "data_directory = 'rel'", "data_directory = ''",
    "work_mem = 4MB", "port 5432", "search_path = '\"$user\", public'", "x.y = 1", "custom.secret = 'hunter2-not-real'",
    "random_page_cost = 1.5e0", "n = -0x1f", "listen_addresses = '*'", "log_line_prefix = '%m [%p] '",
    "include_if_exists = 'nope.conf'", "include_if_exists = 'other.conf'", "include = 'other.conf'", "include_dir = 'conf.d'",
    "include = ''", "include_dir 'missing.d'",
    "= value", "name =", "a b c", "'quoted' = 1", "foo.conf = 1", "name = 'unterminated", "name = foo.conf", "@bad", "x = 1 2",
    "# comment only", "", "   ", "\t# indented comment", "archive_command = 'a' # trailing",
]


def _random_text(rng):
    lines = []
    for _ in range(rng.randint(0, 25)):
        line = rng.choice(_FRAGMENTS)
        if rng.random() < 0.2:
            line = line.upper() if '=' not in line else line.split('=', 1)[0].upper() + '=' + line.split('=', 1)[1]
        if rng.random() < 0.1:
            line = ' \t' + line + ' \r'
        lines.append(line)
    return '\n'.join(lines) + ('\n' if rng.random() < 0.8 else '')


@pytest.mark.parametrize('seed', range(8))
def test_seeded_differential_against_the_contract(seed):
    rng = random.Random(1597 + seed)
    for _ in range(150):
        texts = {CONF: _random_text(rng)}
        if rng.random() < 0.6:
            texts['/etc/postgresql/16/main/other.conf'] = _random_text(rng)
        directories = None
        if rng.random() < 0.6:
            texts[CONFD + '/a.conf'] = _random_text(rng)
            directories = {CONFD: {'state': 'present', 'entries': [{'name': 'a.conf', 'kind': 'file'}]}}
        data_dir = rng.choice([None, '/var/lib/postgresql/16/main'])
        if data_dir and rng.random() < 0.5:
            texts['/var/lib/postgresql/16/main/postgresql.auto.conf'] = _random_text(rng)
        first, second = both(texts, directories, data_dir=data_dir)
        assert comparable(first) == comparable(second), texts


def test_lexer_port_matches_the_contract_tokens():
    rng = random.Random(16)
    alphabet = "ab_Z09.-:/'\\=# \t\r\n\x80\xe9+e%\"x"
    for _ in range(400):
        text = ''.join(rng.choice(alphabet) for _ in range(rng.randint(0, 40)))
        buf = text.encode('utf-8')
        names = {pc._EOL: 'eol', pc._ID: 'id', pc._QID: 'qid', pc._STRING: 'string', pc._USTRING: 'ustring',
                 pc._INT: 'int', pc._REAL: 'real', pc._EQ: 'eq', pc._ERR: 'err', None: None}
        assert [(names[k], r, n) for k, r, n in pc._tokens(buf)] == list(agent._pg_tokens(buf)), text
        quoted = b"'" + buf.replace(b"'", b"''").replace(b'\n', b'') + b"'"
        assert agent._pg_deescape(quoted) == pc._deescape(quoted)


def test_values_outside_the_contract_are_dropped_and_commands_redacted():
    report = reduced(STOCK_LIKE)
    assert SECRET not in repr(report)
    names = [i.get('name') or i.get('directive') or i['op'] for i in report['statements']]
    assert 'primary_conninfo' not in names and 'hba_file' not in names and report['dropped'] == 10
    passphrase = next(i for i in report['statements'] if i.get('name') == 'ssl_passphrase_command')
    assert passphrase['redacted'] is True and '%p' in passphrase['value']
    assert next(i for i in report['statements'] if i['op'] == 'error')['line'] == STOCK_LIKE.splitlines().index('this is = not valid') + 1
    assert sum(i['op'] == 'error' for i in report['statements']) == 1
    persistence.validate_postgresql(report, CONF)


@pytest.mark.parametrize('data', [b'archive_command = x\x00\n', b'archive_command = \xff\n'])
def test_nul_and_non_utf8_files_are_not_parsed(data):
    assert agent.parse_postgresql(data, CONF) == {'parsed': False, 'statements': [], 'truncated': False, 'dropped': 0}


def test_syntax_error_limit_and_statement_limit():
    many = reduced('=\n' * 150 + "archive_command = 'after'\n")
    assert sum(i['op'] == 'error' for i in many['statements']) == 100 and not many['truncated']
    raw, built = both({CONF: '=\n' * 150 + "archive_command = 'after'\n"})
    assert comparable(raw) == comparable(built) and raw['commands'] == []
    long = reduced(''.join('archive_mode = on\n' for _ in range(agent.POSTGRESQL_STATEMENT_LIMIT + 5)))
    assert long['truncated'] and len(long['statements']) == agent.POSTGRESQL_STATEMENT_LIMIT
    huge = reduced("archive_command = '" + 'x' * (agent.POSTGRESQL_VALUE_LIMIT + 1) + "'\n")
    assert huge['truncated'] and huge['statements'] == []


def _row(path, text):
    data = text.encode()
    return {'path': path, 'kind': 'regular', 'uid': 0, 'gid': 0, 'mode': 0o644, 'size': len(data), 'mtime_ns': 1,
            'sha256': '0' * 64, 'postgresql': agent.parse_postgresql(data, path)}


def _inventory(files, state='collected'):
    return {'scope': [PG], 'entries': [_row(p, t) for p, t in files.items()], 'gaps': [], 'missing_roots': [],
            'skipped': 0, 'entries_examined': len(files), 'state': state}


MALFORMED = [
    lambda r: r.update(extra=1),
    lambda r: r.update(parsed='yes'),
    lambda r: r.update(dropped=-1),
    lambda r: r.update(parsed=False),
    lambda r: r['statements'].append({'line': 1, 'op': 'error'}),
    lambda r: r['statements'][0].update(op='open'),
    lambda r: r['statements'][0].update(line=0),
    lambda r: r['statements'][1].update(line=r['statements'][0]['line']),
    lambda r: r['statements'][0].update(name='primary_conninfo'),
    lambda r: r['statements'][0].update(value=None),
    lambda r: r['statements'][0].update(value='x' * 5000),
    lambda r: r['statements'][0].update(redacted='no'),
    lambda r: r['statements'][0].update(name='archive_mode', redacted=True),
    lambda r: r['statements'][2].update(directive='include_shell'),
    lambda r: r['statements'][2].pop('listing'),
    lambda r: r['statements'][1].update(listing=None),
    lambda r: r['statements'][2].update(listing={'state': 'present'}),
    lambda r: r['statements'][2].update(listing={'state': 'gone', 'entries': []}),
    lambda r: r['statements'][2].update(listing={'state': 'absent', 'entries': [{'name': 'a.conf', 'kind': 'file'}]}),
    lambda r: r['statements'][2].update(listing={'state': 'present', 'entries': [{'name': 'a/b', 'kind': 'file'}]}),
    lambda r: r['statements'][2].update(listing={'state': 'present', 'entries': [{'name': 'a', 'kind': 'link'}]}),
    lambda r: r['statements'][2].update(listing={'state': 'present', 'entries': [{'name': 'a', 'kind': 'file'}] * 2}),
    lambda r: r['statements'][2].update(listing={'state': 'present', 'entries': [{'name': str(i), 'kind': 'file'} for i in range(300)]}),
    lambda r: r['statements'].extend({'line': 10 + i, 'op': 'error'} for i in range(101)),
]


@pytest.mark.parametrize('mutate', MALFORMED)
def test_validation_rejects_malformed_reports(mutate):
    report = reduced("archive_command = 'cp %p /a/%f'\ninclude = 'x.conf'\ninclude_dir = 'conf.d'\n")
    persistence.validate_postgresql(copy.deepcopy(report), CONF)
    broken = copy.deepcopy(report)
    mutate(broken)
    with pytest.raises(ValueError):
        persistence.validate_postgresql(broken, CONF)


def test_validation_rejects_statements_outside_postgresql_and_on_symlinks():
    with pytest.raises(ValueError):
        persistence.validate_postgresql(reduced(''), '/etc/postgresql-common/createcluster.conf')
    inventory = _inventory({CONF: "archive_mode = on\n"})
    persistence.validate(inventory)
    link = inventory['entries'][0]
    link.update(kind='symlink', target='/srv/x')
    del link['sha256']
    with pytest.raises(ValueError):
        persistence.validate(inventory)
    assert 'postgresql' not in persistence.metadata(_row(CONF, ''))


def test_view_evaluates_includes_and_an_observed_empty_conf_d():
    inventory = _inventory({CONF: "data_directory = '/var/lib/postgresql/16/main'\narchive_mode = on\n"
                                  "archive_command = 'cp %p /a/%f'\ninclude_dir = 'conf.d'\ninclude_if_exists = 'gone.conf'\n"
                                  "include = 'local.conf'\n",
                            '/etc/postgresql/16/main/local.conf': "shared_preload_libraries = 'pg_cron'\n"})
    inventory['entries'][0]['postgresql']['statements'][3]['listing'] = {'state': 'present', 'entries': []}
    persistence.validate(inventory)
    view = startup_inventory.postgresql_view(inventory, CONF)
    assert view['server_starts'] is True and view['errors'] == []
    assert [(c['setting'], c['active']) for c in view['commands']] == [('archive_command', True)]
    assert view['commands'][0]['invocation'] == ['/bin/sh', '-c', 'cp %p /a/%f']
    assert [(r['setting'], r['library']) for r in view['libraries']] == [('shared_preload_libraries', 'pg_cron')]
    assert view['files'] == [CONF, '/etc/postgresql/16/main/local.conf']
    assert [g['code'] for g in view['gaps']] == ['auto_conf_not_observed']
    assert view['complete'] is False and view['origin'] == 'not_assessed' and view['authorizes_response'] is False


def test_strict_include_of_an_absent_file_is_a_start_error_only_from_a_complete_collection():
    texts = {CONF: "include = 'local.conf'\narchive_mode = on\narchive_command = 'x %p'\n"}
    view = startup_inventory.postgresql_view(_inventory(texts), CONF)
    assert view['server_starts'] is False and view['errors'][0]['reason'] == 'could_not_open_file'
    assert all(c['active'] is False for c in view['commands'])
    incomplete = startup_inventory.postgresql_view(_inventory(texts, state='incomplete'), CONF)
    assert any(g['code'] == 'file_unknown' and g['path'].endswith('local.conf') for g in incomplete['gaps'])


def test_unparsed_truncated_symlinked_outside_and_older_agent_files_stay_unobserved():
    texts = {CONF: "include = 'a.conf'\ninclude = 'b.conf'\ninclude = 'link.conf'\ninclude = '/srv/outside.conf'\n"
                   "include_dir = '/srv/conf.d'\n",
             '/etc/postgresql/16/main/a.conf': ''}
    inventory = _inventory(texts)
    old = {k: v for k, v in _row('/etc/postgresql/16/main/b.conf', '').items() if k != 'postgresql'}
    truncated = _row('/etc/postgresql/16/main/a.conf', '')
    truncated['postgresql']['truncated'] = True
    inventory['entries'][1] = truncated
    inventory['entries'].append(old)
    inventory['entries'].append({'path': '/etc/postgresql/16/main/link.conf', 'kind': 'symlink', 'uid': 0, 'gid': 0,
                                 'mode': 0o777, 'size': 4, 'mtime_ns': 1, 'target': '/srv/x.conf'})
    persistence.validate(inventory)
    view = startup_inventory.postgresql_view(inventory, CONF)
    codes = {(g['code'], g.get('path')) for g in view['gaps']}
    assert ('statements_truncated', '/etc/postgresql/16/main/a.conf') in codes
    assert ('file_unknown', '/etc/postgresql/16/main/a.conf') in codes
    assert ('file_unknown', '/etc/postgresql/16/main/b.conf') in codes
    assert ('file_unknown', '/etc/postgresql/16/main/link.conf') in codes
    assert ('file_unknown', '/srv/outside.conf') in codes and ('directory_not_observed', '/srv/conf.d') in codes
    assert view['errors'] == []
    assert startup_inventory.postgresql_state(old) == 'not_reported'
    assert startup_inventory.postgresql_state(_row(CONF, 'a\x00')) == 'unparsed'
    labels = {r['id']: r['label'] for r in startup_inventory.catalog_rows(inventory)}
    assert labels['postgresql'].endswith('· 2 parsed files · not reported by this agent version')


def test_agent_parses_the_hashed_bytes_without_running_anything(tmp_path, monkeypatch):
    marker = tmp_path / 'ran'
    root = tmp_path / 'postgresql'
    cluster = root / '16' / 'main'
    (cluster / 'conf.d').mkdir(parents=True)
    (cluster / 'postgresql.conf').write_text(
        f"data_directory = '/var/lib/postgresql/16/main'\narchive_mode = on\narchive_command = 'touch {marker} %p'\n"
        f"primary_conninfo = 'password={SECRET}'\ninclude_dir = 'conf.d'\n")
    (cluster / 'pg_hba.conf').write_text(f'host all all 0.0.0.0/0 scram-sha-256 # {SECRET}\n')
    (cluster / 'link.conf').symlink_to(cluster / 'postgresql.conf')
    monkeypatch.setattr(agent, 'PERSISTENCE_ROOTS', (str(root),))
    monkeypatch.setattr(agent, 'PERSISTENCE_FILES', ())
    monkeypatch.setattr(agent, 'POSTGRESQL_DIR', str(root))
    result = agent.persistence_inventory(time.monotonic() + 5, cron_jobs=True)
    assert not marker.exists() and SECRET not in repr(result)
    rows = {r['path']: r for r in result['entries']}
    assert 'postgresql' not in rows[str(cluster / 'link.conf')]
    include = rows[str(cluster / 'postgresql.conf')]['postgresql']['statements'][-1]
    assert include['listing'] == {'state': 'present', 'entries': []}
    text = repr(result).replace(str(root), PG)
    inventory = eval(text)  # noqa: S307 - repr of plain literals produced above
    inventory['scope'] = [PG]
    persistence.validate(inventory)
    view = startup_inventory.postgresql_view(inventory, CONF)
    assert [c['command'] for c in view['commands']] == [f"touch {str(marker).replace(str(root), PG)} %p"]
    assert view['server_starts'] is True and [g['code'] for g in view['gaps']] == ['auto_conf_not_observed']
    without = agent.persistence_inventory(time.monotonic() + 5, cron_jobs=False)
    assert all('postgresql' not in r for r in without['entries'])


def test_startup_rows_carry_the_view_only_for_main_configuration_files():
    inventory = _inventory({CONF: "archive_mode = on\n", '/etc/postgresql/16/main/pg_hba.conf': 'local all all peer\n'})
    hba = inventory['entries'][1]['postgresql']
    assert hba['parsed'] and [i['op'] for i in hba['statements']] == ['error'] and 'peer' not in repr(hba)
    assert startup_inventory.POSTGRESQL_MAIN.fullmatch(CONF)
    assert not startup_inventory.POSTGRESQL_MAIN.fullmatch('/etc/postgresql/16/main/conf.d/postgresql.conf')
