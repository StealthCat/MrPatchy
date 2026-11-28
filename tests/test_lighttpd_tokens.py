"""Agent-side lighttpd token reduction, controller validation and Startup Files evaluation (#1603 increment 3)."""
from __future__ import annotations

import copy
import random
import time

import pytest

from app import lighttpd_commands as lc
from app import persistence, startup_inventory
from target import agent

from tests.test_lighttpd_commands import NATIVE, PHP, REC, STOCK

CONF = '/etc/lighttpd/lighttpd.conf'
AVAILABLE = '/etc/lighttpd/conf-available/15-fastcgi-php.conf'
ENABLED = '/etc/lighttpd/conf-enabled/15-fastcgi-php.conf'
SECRET = 'hunter2-not-real'
DEBIAN = STOCK.replace('include_shell "/usr/share/lighttpd/create-mime.conf.pl"\n', '').replace(
    'include_shell "/usr/share/lighttpd/use-ipv6.pl " + server.port\n', '')
FIELDS = ('commands', 'gaps', 'notes', 'files', 'root_commands', 'complete', 'config_accepted', 'command_sha256',
          'server_user', 'server_uid', 'server_gid')


def rebuilt(text):
    return startup_inventory.lighttpd_text(agent.parse_lighttpd(text.encode()))


def comparable(result):
    return {k: result[k] for k in FIELDS}


def strings(report):
    return [value for kind, value, _ in report['tokens'] if kind == 'str']


def test_rebuilt_text_evaluates_exactly_like_the_captured_text():
    files = {'/srv/lt/inc/a.conf': f'include_shell "{REC} inc a"\n'}
    kwargs = dict(config_path='/srv/lt/lighttpd.conf', globs={'/srv/lt/inc/*.conf': ['/srv/lt/inc/a.conf']},
                  include_shell_output={f'{REC} inc top 8089': 'var.s_top = 1\n', f'{REC} inc a': 'var.s_a = 1\n'},
                  passwd_text='www-data:x:33:33::/:/bin/false\n', group_text='www-data:x:33:\n')
    raw = lc.evaluate(files={'/srv/lt/lighttpd.conf': NATIVE, **files}, **kwargs)
    again = lc.evaluate(files={'/srv/lt/lighttpd.conf': rebuilt(NATIVE), **{p: rebuilt(t) for p, t in files.items()}}, **kwargs)
    assert comparable(again) == comparable(raw) and raw['complete'] and len(raw['commands']) == 6
    for text in (STOCK, PHP, STOCK + PHP):
        files = {CONF: text}
        assert comparable(lc.evaluate(files={CONF: rebuilt(text)})) == comparable(lc.evaluate(files=files))


_FRAGMENTS = (
    'server.username = "www-data"\n', 'server.groupname = "www-data"\n', 'server.port = 8080\n',
    'server.document-root = "/var/www/html"\n', 'server.pid-file = "/run/lighttpd.pid"\n',
    'server.errorlog = "|/usr/bin/logger -t err"\n', 'server.errorlog := "/var/log/lighttpd/error.log"\n',
    'server.errorlog-use-syslog = "enable"\n', 'server.breakagelog = "|/usr/local/bin/rotate \\"quoted\\" arg"\n',
    'accesslog.filename = "|/usr/bin/cronolog /var/log/%Y.log"\n', 'accesslog.filename += "x"\n',
    'var.base = "/srv"\n', 'var.log = var.base + "/log"\n', 'accesslog.filename = "|" + var.log + "/rot.sh"\n',
    'server.modules = ( "mod_access", "mod_fastcgi", )\n', 'server.modules += ( "mod_accesslog" )\n',
    'server.tag = "x" + server.port\n', 'include_shell "/usr/share/lighttpd/use-ipv6.pl " + server.port\n',
    'include_shell "/usr/share/lighttpd/create-mime.conf.pl"\n', 'include "conf-enabled/*.conf"\n',
    'include "/etc/lighttpd/missing.conf"\n', 'include env.HOME + "/x.conf"\n',
    'fastcgi.server = ( ".php" => (( "bin-path" => "/usr/bin/php-cgi -c /etc/php.ini", "socket" => "/run/php.sock",'
    ' "max-procs" => 2, "bin-environment" => ( "PHP_FCGI_CHILDREN" => "4" ) )) )\n',
    'fastcgi.server += ( "/app" => (( "bin-path" => var.base + "/app.fcgi", "host" => "127.0.0.1", "port" => 9000 )) )\n',
    'scgi.server = ( "/s" => ( "local" => ( "bin-path" => "/srv/scgi", "socket" => "/run/s" ) ) )\n',
    '$HTTP["host"] == "example.org" {\n  accesslog.filename = "|/usr/bin/vhostlog"\n  server.document-root = "/srv/x"\n}\n',
    '$HTTP["url"] =~ "^/cgi" { fastcgi.server = ( ".cgi" => (( "bin-path" => "/srv/cgi.fcgi" )) ) } else {\n'
    '  server.errorlog = "|/bin/other" }\n',
    'global { var.g = "/global" }\n', 'mimetype.assign = ( ".html" => "text/html", ".txt" => "text/plain" )\n',
    'alias.url = ( "/doc/" => "/usr/share/doc/" )\n', 'server.tag = "multi\nline \\"tag\\""\n',
    'url.rewrite-once = ( "^/(.*)" => "/index.php?$1" )\n', 'server.max-fds = 2048\n',
    'ref.x = server.document-root + "/x"\n', 'server.errorlog = server.document-root\n',
    '# comment "with quotes"\n', '\n\n',
)
_BROKEN = ('server.port = 80 ;\n', 'x = "unterminated\n', '$ = 1\n', "x = 'single'\n", 'server.port = = 1\n',
           'server.port = 80\nserver.port = 81\n', '}\n', '$HTTP["host"] == "a" {\n', 'x = ( "a" "b" )\n')


def _text(rng, broken):
    parts = [rng.choice(_FRAGMENTS) for _ in range(rng.randint(0, 12))]
    if broken:
        parts.insert(rng.randint(0, len(parts)), rng.choice(_BROKEN))
    return ''.join(parts)


@pytest.mark.parametrize('seed', range(1200))
def test_seeded_differential_against_the_contract(seed):
    rng = random.Random(seed)
    text = _text(rng, broken=seed % 3 == 0)
    files = {CONF: text, '/etc/lighttpd/conf-enabled/a.conf': 'accesslog.filename = "|/bin/a"\n'}
    globs = {'/etc/lighttpd/conf-enabled/*.conf': ['/etc/lighttpd/conf-enabled/a.conf']}
    raw = lc.evaluate(files=files, globs=globs, passwd_text='www-data:x:33:33::/:/bin/false\n', group_text='www-data:x:33:\n')
    report = agent.parse_lighttpd(text.encode())
    persistence.validate_lighttpd(report, CONF)
    again = lc.evaluate(files={**files, CONF: startup_inventory.lighttpd_text(report)}, globs=globs,
                        passwd_text='www-data:x:33:33::/:/bin/false\n', group_text='www-data:x:33:\n')
    assert comparable(again) == comparable(raw), text
    assert not any(startup_inventory.LIGHTTPD_DROPPED in row['command'] for row in again['commands']), text


@pytest.mark.parametrize('seed', range(300))
def test_agent_lexer_matches_the_contract_lexer(seed):
    rng = random.Random(seed)
    alphabet = 'ab.$_=+:~!^()[]{},>#" \\\n\t19HTTPx'
    text = ''.join(rng.choice(alphabet) for _ in range(rng.randint(0, 60)))
    try:
        expected = [list(t) for t in lc.tokenize(text)]
    except lc.ConfigError as error:
        expected = error.line
    got = agent._lighttpd_tokens(text)
    assert (got[2] if isinstance(got, tuple) else got) == expected, text


def test_values_outside_the_contract_are_dropped_and_kept_strings_redacted():
    text = (f'auth.backend.ldap.bind-pw = "{SECRET}"\nserver.document-root = "/srv/{SECRET}"\n'
            f'fastcgi.server = ( ".php" => (( "bin-path" => "/usr/bin/php-cgi", "socket" => "/run/{SECRET}",'
            f' "bin-environment" => ( "DB_PASSWORD" => "{SECRET}" ) )) )\n'
            f'accesslog.filename = "|/usr/bin/ship --password {SECRET}"\n'
            f'mysql-vhost.pass = "{SECRET}"\nssl.pemfile = "/etc/lighttpd/{SECRET}.pem"\n')
    report = agent.parse_lighttpd(text.encode())
    persistence.validate_lighttpd(report, CONF)
    assert SECRET not in repr(report) and report['redacted'] and report['dropped'] == 7
    assert '/usr/bin/php-cgi' in strings(report) and 'DB_PASSWORD' not in strings(report)
    assert '|/usr/bin/ship --password [REDACTED]' in strings(report)
    result = lc.evaluate(files={CONF: startup_inventory.lighttpd_text(report)})
    assert [r['command'] for r in result['commands']] == ['/usr/bin/php-cgi', '/usr/bin/ship --password [REDACTED]']


@pytest.mark.parametrize('text', [
    # Review of 37ac1b4: a drop-mode value that is not a well-formed rhs fell through to the bare-string branch.
    f'mysql-vhost.pass = "pw1" "{SECRET}"\n',
    f'mysql-vhost.pass "{SECRET}"\n',
    f'auth.backend.plain.userfile = [ "{SECRET}" ]\n',
    f'"{SECRET}"\n',
    f'server.port = 80 "{SECRET}"\n',
    f'x = $HTTP["{SECRET}"] == "{SECRET}"\n',
    f'include "a.conf" "{SECRET}"\n',
    f'$HTTP["host"] == "a" "{SECRET}" {{ }}\n',
    f'$HTTP["host"] "{SECRET}" == "a" {{ }}\n',
    f'( "{SECRET}" )\n',
    # bin-path nested in bin-environment is an environment value, not the backend program.
    f'fastcgi.server = ( ".php" => (( "bin-environment" => ( "bin-path" => "{SECRET}" ) )) )\n',
    f'fastcgi.server = ( ".php" => (( "bin-environment" => ( "{SECRET}" => "x" ) )) )\n',
    f'scgi.server = ( "/s" => ( "local" => ( "x" => ( "max-procs" => "{SECRET}" ) ) ) )\n',
])
def test_bare_strings_outside_contract_positions_are_dropped(text):
    report = agent.parse_lighttpd(text.encode())
    persistence.validate_lighttpd(report, CONF)
    assert report['parsed'] and SECRET not in repr(report) and report['dropped'] >= 1


def test_contract_positions_for_bare_strings_are_kept():
    text = ('include "conf-enabled/*.conf"\ninclude env.HOME + "/x.conf"\n'
            'include_shell "/usr/share/lighttpd/use-ipv6.pl " + server.port\n'
            '$HTTP["host"] == "a" + var.x { } else $HTTP["url"] =~ "^/b" { }\n'
            'server.port = 1\n$SERVER["socket"] == ":443" { }\n'
            'fastcgi.server = ( ".php" => ( "localhost" => ( "bin-path" => "/srv/p", "max-procs" => 2 ) ) )\n')
    report = agent.parse_lighttpd(text.encode())
    assert strings(report) == ['conf-enabled/*.conf', '/x.conf', '/usr/share/lighttpd/use-ipv6.pl ', 'host', 'a',
                               'url', '^/b', 'socket', ':443', '.php', 'localhost', 'bin-path', '/srv/p', 'max-procs']
    assert report['dropped'] == 0


@pytest.mark.parametrize('data', [b'a\x00b', b'\xff\xfe', b'#' * (1024 * 1024 + 1)])
def test_nul_non_utf8_and_over_limit_files_are_not_parsed(data):
    assert agent.parse_lighttpd(data) == {'parsed': False, 'tokens': [], 'truncated': False, 'dropped': 0, 'redacted': False}


@pytest.mark.parametrize('text,token', [
    ('x = 1\ny = "open\n\n', ['error', 'unterminated_string', 4]),
    ('x = 1\n\n$ = 2\n', ['error', 'bad_conditional', 3]),
    ('x = 1 ;\n', ['char', ';', 1]),
    ('x = 1\n\x0b\n', ['char', '�', 2]),
    ('x = ²\n', ['char', '�', 1]),
])
def test_lexing_gaps_keep_their_code_and_line(text, token):
    report = agent.parse_lighttpd(text.encode())
    assert report['tokens'] == [token]
    persistence.validate_lighttpd(report, CONF)
    result = lc.evaluate(files={CONF: startup_inventory.lighttpd_text(report)})
    blocking = [(g['code'], g.get('line')) for g in result['gaps'] if g['blocking']]
    assert not result['config_accepted'] and blocking == [('parse_error', token[2])]


def test_over_limit_tokens_and_strings_truncate_and_the_view_blocks():
    many = agent.parse_lighttpd(('x = 1\n' * 1500).encode())
    assert many['truncated'] and len(many['tokens']) == agent.LIGHTTPD_TOKEN_LIMIT
    long = agent.parse_lighttpd(('accesslog.filename = "|' + 'a' * 2000 + '"\nserver.port = 1\n').encode())
    assert long['truncated'] and long['tokens'] == [['word', 'accesslog.filename', 1], ['op', '=', 1]]
    for report in (many, long):
        persistence.validate_lighttpd(report, CONF)
    inventory = _inventory({CONF: 'x = 1\n'})
    inventory['entries'][0]['lighttpd'] = long
    view = startup_inventory.lighttpd_view(inventory)
    assert any(g['code'] == 'statements_truncated' and g['blocking'] for g in view['gaps']) and not view['config_complete']


def _set(report, index, value):
    report['tokens'][index] = value
    return report


GOOD = 'accesslog.filename = "|/bin/x"\nserver.document-root = "/srv"\n'


@pytest.mark.parametrize('mutate', [
    lambda r: r.pop('redacted'),
    lambda r: r.update(extra=1),
    lambda r: r.update(parsed='yes'),
    lambda r: r.update(dropped=-1),
    lambda r: r.update(dropped=0),
    lambda r: r.update(parsed=False),
    lambda r: _set(r, 2, ['str', 'a\x00', 1]),
    lambda r: _set(r, 2, ['str', 'ends\\', 1]),
    lambda r: _set(r, 2, ['str', 'x' * 1025, 1]),
    lambda r: _set(r, 5, ['drop', 'kept anyway', 2]),
    lambda r: _set(r, 0, ['word', 'bad word', 1]),
    lambda r: _set(r, 0, ['word', 'a' * 300, 1]),
    lambda r: _set(r, 1, ['op', ';', 1]),
    lambda r: _set(r, 1, ['cond', '$http', 1]),
    lambda r: _set(r, 1, ['int', True, 1]),
    lambda r: _set(r, 1, ['int', -1, 1]),
    lambda r: _set(r, 1, ['shell', 'x', 1]),
    lambda r: _set(r, 1, ['op', '=']),
    lambda r: _set(r, 3, ['word', 'server.document-root', 0]),
    lambda r: _set(r, 5, ['drop', None, 1]),
    lambda r: _set(r, 5, ['str', 'a\nb\nc', 2]),
    lambda r: _set(r, 0, ['error', 'unterminated_string', 1]),
    lambda r: r.update(tokens=[['error', 'other', 1]], dropped=0),
    lambda r: r.update(tokens=[['char', 'a', 1]], dropped=0),
    lambda r: r.update(tokens=[['char', '(', 1]], dropped=0),
    lambda r: r.update(tokens=[['char', '\n', 1]], dropped=0),
    lambda r: r.update(tokens=[['int', 1, 1]] * 4001, dropped=0),
])
def test_validation_rejects_malformed_reports(mutate):
    report = agent.parse_lighttpd(GOOD.encode())
    persistence.validate_lighttpd(copy.deepcopy(report), CONF)
    mutate(report)
    with pytest.raises(ValueError):
        persistence.validate_lighttpd(report, CONF)


@pytest.mark.parametrize('path', ['/etc/lighttpd/lighttpd.conf.bak', '/etc/lighttpd', '/etc/lighttpdx/a.conf', '/srv/lighttpd.conf'])
def test_validation_rejects_tokens_outside_lighttpd_configuration(path):
    with pytest.raises(ValueError):
        persistence.validate_lighttpd(agent.parse_lighttpd(GOOD.encode()), path)
    inventory = _inventory({CONF: GOOD})
    inventory['entries'][0]['kind'] = 'symlink'
    inventory['entries'][0]['target'] = 'x'
    with pytest.raises(ValueError):
        persistence.validate(inventory)


def _row(path, text):
    row = {'path': path, 'kind': 'regular', 'uid': 0, 'gid': 0, 'mode': 0o644, 'size': len(text), 'mtime_ns': 1, 'sha256': 'a' * 64}
    if persistence.lighttpd_reads(path):
        row['lighttpd'] = agent.parse_lighttpd(text.encode())
    return row


def _link(path, target):
    return {'path': path, 'kind': 'symlink', 'uid': 0, 'gid': 0, 'mode': 0o777, 'size': len(target), 'mtime_ns': 1, 'target': target}


def _inventory(texts, state='collected', links=()):
    return {'scope': ['/etc/lighttpd'], 'state': state, 'entries': [_row(p, t) for p, t in texts.items()] + [_link(*l) for l in links],
            'gaps': [] if state == 'collected' else ['/etc/lighttpd/x: PermissionError'], 'skipped': 0 if state == 'collected' else 1,
            'missing_roots': []}


def test_debian_layout_follows_conf_enabled_symlinks_from_a_complete_collection():
    inventory = _inventory({CONF: STOCK, AVAILABLE: PHP, '/etc/lighttpd/conf-available/10-ssl.conf': 'ssl.pemfile = "/etc/x.pem"\n',
                            '/etc/lighttpd/server.pem': '-----BEGIN PRIVATE KEY-----\n'},
                           links=[(ENABLED, '../conf-available/15-fastcgi-php.conf')])
    persistence.validate(inventory)
    assert 'lighttpd' not in inventory['entries'][3]
    view = startup_inventory.lighttpd_view(inventory)
    rows = [(c['kind'], c['command'], c['account'], c['source']) for c in view['commands']]
    assert rows == [('include_shell', '/usr/share/lighttpd/create-mime.conf.pl', 'invoking_user', CONF),
                    ('include_shell', '/usr/share/lighttpd/use-ipv6.pl 80', 'invoking_user', CONF),
                    ('fastcgi', '/usr/bin/php-cgi', 'www-data', ENABLED)]
    assert [f['path'] for f in view['files']] == [CONF, ENABLED] and view['config_accepted']
    blocking = {g['code'] for g in view['gaps'] if g['blocking']}
    assert blocking == {'include_shell_output_not_captured', 'passwd_not_captured', 'group_not_captured'}
    assert view['complete'] is False and view['config_complete'] is False
    assert view['authorizes_response'] is False and view['origin'] == 'not_assessed'
    # /etc/passwd is not captured, so www-data's UID is unknown and the backend is counted as possibly privileged.
    assert view['root_commands'] == [0, 1, 2] and view['commands'][2]['uid'] is None
    assert any(g['code'] == 'environment_assumed' and not g['blocking'] for g in view['gaps'])
    # Without include_shell or an account, a complete collection evaluates with only non-blocking notes.
    plain = startup_inventory.lighttpd_view(_inventory({CONF: 'include "conf-enabled/*.conf"\n', AVAILABLE: PHP},
                                                       links=[(ENABLED, '../conf-available/15-fastcgi-php.conf')]))
    assert plain['config_complete'] and [c['argv'] for c in plain['commands']] == [['/usr/bin/php-cgi']]
    assert plain['commands'][0]['account'] == 'invoking_user' and plain['root_commands'] == [0]


def test_rpm_layout_resolves_variable_includes_and_nested_globs():
    conf = ('var.conf_dir = "/etc/lighttpd"\nvar.log_root = "/var/log/lighttpd"\ninclude var.conf_dir + "/modules.conf"\n'
            'server.errorlog = "|/usr/bin/logger -t lighttpd"\n')
    modules = 'include "conf.d/*.conf"\n'
    fcgi = 'fastcgi.server = ( ".php" => (( "bin-path" => "/usr/bin/php-cgi", "socket" => var.log_root + "/php.socket" )) )\n'
    inventory = _inventory({CONF: conf, '/etc/lighttpd/modules.conf': modules, '/etc/lighttpd/conf.d/fastcgi.conf': fcgi,
                            '/etc/lighttpd/conf.d/.hidden.conf': 'accesslog.filename = "|/bin/hidden"\n',
                            '/etc/lighttpd/conf.d/notes.txt': 'not configuration\n'})
    persistence.validate(inventory)
    view = startup_inventory.lighttpd_view(inventory)
    assert [c['command'] for c in view['commands']] == ['/usr/bin/php-cgi', '/usr/bin/logger -t lighttpd']
    assert view['config_complete'] and [f['path'] for f in view['files']] == [CONF, '/etc/lighttpd/modules.conf', '/etc/lighttpd/conf.d/fastcgi.conf']
    # Fedora's stock file writes conf_dir for var.conf_dir. The #1603 contract resolves only the literal key, so
    # that is reported as an unresolved, blocking reference rather than guessed (follow-up on #1603).
    short = startup_inventory.lighttpd_view(_inventory({CONF: conf.replace('include var.conf_dir', 'include conf_dir'),
                                                        '/etc/lighttpd/modules.conf': modules}))
    assert any(g['code'] == 'unresolved_reference' and g['blocking'] and g['name'] == 'conf_dir' for g in short['gaps'])


def test_incomplete_collections_outside_paths_and_unresolved_links_stay_unobserved():
    for state, texts, links, code in (
        ('incomplete', {CONF: 'include "conf-enabled/*.conf"\n'}, (), 'unobserved_glob'),
        ('collected', {CONF: 'include "/usr/share/lighttpd/extra.conf"\n'}, (), 'unobserved_file'),
        ('collected', {CONF: 'include "conf-enabled/*.conf"\n'}, [(ENABLED, '/usr/share/lighttpd/x.conf')], 'unobserved_file'),
        ('collected', {CONF: 'include "linked/*.conf"\n'}, [('/etc/lighttpd/linked', '/srv')], 'unobserved_glob'),
        ('collected', {CONF: 'include "conf-enabled/[!a]*.conf"\n'}, (), 'unobserved_glob'),
        ('collected', {CONF: 'include "*/x.conf"\n'}, (), 'unobserved_glob'),
        ('collected', {CONF: 'include "sub"\n', '/etc/lighttpd/sub/a.conf': 'x = 1\n'}, (), 'unobserved_file'),
    ):
        inventory = _inventory(texts, state=state, links=links)
        persistence.validate(inventory)
        view = startup_inventory.lighttpd_view(inventory)
        assert not view['config_complete'] and any(g['code'] == code and g['blocking'] for g in view['gaps']), (texts, links)
    # An absent plain include in a complete collection rejects the configuration, as lighttpd does.
    missing = startup_inventory.lighttpd_view(_inventory({CONF: 'include "missing.conf"\naccesslog.filename = "|/bin/x"\n'}))
    assert not missing['config_accepted'] and any(g['code'] == 'include_not_found' for g in missing['gaps'])
    assert missing['commands'][0]['starts'] is False and missing['root_commands'] == []


def test_a_command_built_from_a_value_another_file_set_is_flagged():
    inventory = _inventory({CONF: 'server.document-root = "/srv/www"\ninclude "conf-enabled/*.conf"\n',
                            '/etc/lighttpd/conf-enabled/a.conf': 'accesslog.filename = "|/bin/log " + server.document-root\n'})
    view = startup_inventory.lighttpd_view(inventory)
    assert view['commands'][0]['command'] == '/bin/log ' + startup_inventory.LIGHTTPD_DROPPED
    assert any(g['code'] == 'value_not_retained' and g['blocking'] and g['source'] == '/etc/lighttpd/conf-enabled/a.conf' for g in view['gaps'])


def test_older_agents_unparsed_files_and_catalog_labels_are_explained():
    old = {k: v for k, v in _row(AVAILABLE, '').items() if k != 'lighttpd'}
    inventory = _inventory({CONF: 'include "conf-available/*.conf"\n'})
    inventory['entries'].append(old)
    persistence.validate(inventory)
    assert startup_inventory.lighttpd_state(old) == 'not_reported'
    assert startup_inventory.lighttpd_state(_row(AVAILABLE, 'a\x00')) == 'unparsed'
    assert startup_inventory.lighttpd_state(_row('/etc/lighttpd/server.pem', 'x')) is None
    view = startup_inventory.lighttpd_view(inventory)
    assert any(g['code'] == 'unobserved_file' and g['path'] == AVAILABLE for g in view['gaps'])
    labels = {r['id']: r['label'] for r in startup_inventory.catalog_rows(inventory)}
    assert labels['lighttpd'].endswith('· 1 parsed file · not reported by this agent version')


def test_agent_parses_the_hashed_bytes_without_running_anything(tmp_path, monkeypatch):
    marker = tmp_path / 'ran'
    root = tmp_path / 'lighttpd'
    (root / 'conf-available').mkdir(parents=True)
    (root / 'conf-enabled').mkdir()
    (root / 'lighttpd.conf').write_text(f'include_shell "/usr/bin/touch {marker}"\ninclude "conf-enabled/*.conf"\n'
                                        f'auth.backend.ldap.bind-pw = "{SECRET}"\n')
    (root / 'conf-available' / '15-fastcgi-php.conf').write_text(f'fastcgi.server = ( ".php" => (( "bin-path" => "/usr/bin/touch {marker}" )) )\n')
    (root / 'conf-enabled' / '15-fastcgi-php.conf').symlink_to('../conf-available/15-fastcgi-php.conf')
    (root / 'server.pem').write_text(f'-----BEGIN PRIVATE KEY-----\n{SECRET}\n')
    monkeypatch.setattr(agent, 'PERSISTENCE_ROOTS', (str(root),))
    monkeypatch.setattr(agent, 'PERSISTENCE_FILES', ())
    monkeypatch.setattr(agent, 'LIGHTTPD_DIR', str(root))
    result = agent.persistence_inventory(time.monotonic() + 5, cron_jobs=True)
    assert not marker.exists() and SECRET not in repr(result)
    rows = {r['path']: r for r in result['entries']}
    assert 'lighttpd' not in rows[str(root / 'server.pem')] and 'lighttpd' not in rows[str(root / 'conf-enabled' / '15-fastcgi-php.conf')]
    assert all('lighttpd' in rows[str(root / n)] for n in ('lighttpd.conf', 'conf-available/15-fastcgi-php.conf'))
    inventory = eval(repr(result).replace(str(root), '/etc/lighttpd'))  # noqa: S307 - repr of plain literals produced above
    inventory['scope'] = ['/etc/lighttpd']
    persistence.validate(inventory)
    view = startup_inventory.lighttpd_view(inventory)
    assert [(c['kind'], c['command']) for c in view['commands']] == [('include_shell', f'/usr/bin/touch {marker}'),
                                                                    ('fastcgi', f'/usr/bin/touch {marker}')]
    without = agent.persistence_inventory(time.monotonic() + 5, cron_jobs=False)
    assert all('lighttpd' not in r for r in without['entries'])


def test_metadata_comparisons_ignore_parsed_tokens():
    row = _row(CONF, STOCK)
    assert 'lighttpd' not in persistence.metadata(row) and persistence.metadata(row)['sha256'] == row['sha256']


# Referenced credential values (coordinator hold on 7dc74e3): a reference must not pull a credential-bearing
# setting's value into the report; a command built from one is shown with a blocking value_not_retained gap.
@pytest.mark.parametrize('key', ['auth.backend.ldap.bind-pw', 'auth.backend.mysql.pass', 'mysql-vhost.pass',
                                 'secdownload.secret', 'ssl.privkey', 'var.db_password', 'var.api-token',
                                 'var.SecretKey', 'server.credential'])
def test_referenced_credential_values_are_not_retained(key):
    text = f'{key} = "{SECRET}"\nvar.a = {key}\naccesslog.filename = "|/bin/log " + {key}\n'
    report = agent.parse_lighttpd(text.encode())
    persistence.validate_lighttpd(report, CONF)
    assert SECRET not in repr(report) and report['dropped'] >= 1
    view = startup_inventory.lighttpd_view(_inventory({CONF: text}))
    assert SECRET not in repr(view)
    assert view['commands'][0]['command'] == '/bin/log ' + startup_inventory.LIGHTTPD_DROPPED
    assert any(g['code'] == 'value_not_retained' and g['blocking'] for g in view['gaps'])


def test_referenced_ordinary_values_and_var_values_are_still_kept():
    text = ('server.document-root = "/srv/www"\nvar.base = "/opt/app"\n'
            'accesslog.filename = "|/bin/log " + server.document-root + var.base\n')
    report = agent.parse_lighttpd(text.encode())
    assert strings(report)[:2] == ['/srv/www', '/opt/app']
    view = startup_inventory.lighttpd_view(_inventory({CONF: text}))
    assert view['commands'][0]['command'] == '/bin/log /srv/www/opt/app'
    assert not any(g['code'] == 'value_not_retained' for g in view['gaps'])
