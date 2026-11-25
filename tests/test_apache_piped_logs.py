"""Tests for the pure Apache httpd piped-log program contract (#1502)."""
from __future__ import annotations

import pytest

from app import apache_piped_logs as apl

ROOT = '/etc/apache2'
MAIN = f'{ROOT}/apache2.conf'
ENV = {'APACHE_LOG_DIR': '/var/log/apache2', 'APACHE_RUN_USER': 'www-data'}


def run(main, files=None, includes=None, defines=None, environment=None, root=ROOT, config=MAIN):
    return apl.evaluate({'server_root': root, 'config_file': config, 'files': {config: main, **(files or {})},
                         'includes': includes or {}, 'defines': defines or [],
                         'environment': ENV if environment is None else environment})


def progs(result):
    return [(p['directive'], p['server'], p['invocation'], p['argv']) for p in result['programs']]


def codes(result):
    return {g['code'] for g in result['gaps']}


def test_debian_layout_resolves_vhost_piped_logs_and_skips_files():
    main = ('# Debian apache2.conf excerpt\n'
            'Mutex file:${APACHE_LOCK_DIR} default\n'
            'User ${APACHE_RUN_USER}\n'
            'ErrorLog ${APACHE_LOG_DIR}/error.log\n'
            'IncludeOptional mods-enabled/*.load\n'
            'Include ports.conf\n'
            'LogFormat "%h %l %u %t \\"%r\\" %>s %O" common\n'
            'IncludeOptional conf-enabled/*.conf\n'
            'IncludeOptional sites-enabled/*.conf\n')
    site = ('<VirtualHost *:80>\n'
            '\tServerName example.org\n'
            '\tErrorLog ${APACHE_LOG_DIR}/error.log\n'
            '\tCustomLog "|/usr/bin/rotatelogs -l ${APACHE_LOG_DIR}/access.%Y-%m-%d 86400" combined\n'
            '</VirtualHost>\n')
    other = '<VirtualHost *:8080>\n  CustomLog ${APACHE_LOG_DIR}/other.log combined\n</VirtualHost>\n'
    result = run(main, files={f'{ROOT}/ports.conf': 'Listen 80\n', f'{ROOT}/sites-enabled/000-default.conf': site,
                              f'{ROOT}/sites-enabled/other.conf': other},
                 includes={f'{ROOT}/mods-enabled/*.load': [], f'{ROOT}/ports.conf': [f'{ROOT}/ports.conf'],
                           f'{ROOT}/conf-enabled/*.conf': [],
                           f'{ROOT}/sites-enabled/*.conf': [f'{ROOT}/sites-enabled/other.conf',
                                                            f'{ROOT}/sites-enabled/000-default.conf']})
    assert progs(result) == [('CustomLog', '<VirtualHost *:80>', 'direct',
                              ['/usr/bin/rotatelogs', '-l', '/var/log/apache2/access.%Y-%m-%d', '86400'])]
    program = result['programs'][0]
    assert program['file'] == f'{ROOT}/sites-enabled/000-default.conf' and program['line'] == 4
    assert program['working_directory'] == ROOT and 'root' in program['runs_as']
    assert program['log_condition'] is None and program['conditions'] == []
    # Matches are processed in sorted order, whatever order the collector gave.
    assert result['files_parsed'] == [MAIN, f'{ROOT}/ports.conf', f'{ROOT}/sites-enabled/000-default.conf',
                                      f'{ROOT}/sites-enabled/other.conf']
    # The vhost ErrorLog is the same string as the main server's, so it shares that (file) logger.
    assert result['shared_error_logs'] == [{'server': '<VirtualHost *:80>', 'file': program['file'], 'line': 3,
                                            'shares_with': 'main'}]
    assert result['complete'] is True and result['origin'] == 'not_assessed'


def test_rhel_layout_with_error_log_pipe_and_server_root_relative_program():
    main = ('ServerRoot "/etc/httpd"\n'
            'Include conf.modules.d/*.conf\n'
            'ErrorLog "|bin/logger-wrap --tag httpd"\n'
            'IncludeOptional conf.d/*.conf\n')
    result = run(main, root='/usr/local/apache2', config='/etc/httpd/conf/httpd.conf',
                 files={'/etc/httpd/conf.modules.d/00-base.conf': 'LoadModule log_config_module x.so\n',
                        '/etc/httpd/conf.d/ssl.conf': '<VirtualHost _default_:443>\n'
                        'ErrorLog "|$/usr/bin/logger -t ssl"\n</VirtualHost>\n'},
                 includes={'/etc/httpd/conf.modules.d/*.conf': ['/etc/httpd/conf.modules.d/00-base.conf'],
                           '/etc/httpd/conf.d/*.conf': ['/etc/httpd/conf.d/ssl.conf']})
    assert progs(result) == [
        ('ErrorLog', 'main', 'direct', ['bin/logger-wrap', '--tag', 'httpd']),
        ('ErrorLog', '<VirtualHost _default_:443>', 'shell', ['/bin/sh', '-c', '/usr/bin/logger -t ssl'])]
    assert result['programs'][0]['executable'] == '/etc/httpd/bin/logger-wrap'
    assert result['server_root'] == '/etc/httpd' and result['complete'] is True


@pytest.mark.parametrize('target, invocation, argv', [
    ('"|/bin/log a"', 'direct', ['/bin/log', 'a']),
    ('"||/bin/log a"', 'direct', ['/bin/log', 'a']),
    ('"|$/bin/log a | tee x"', 'shell', ['/bin/sh', '-c', '/bin/log a | tee x']),
    ('"||$exec /bin/log"', 'shell', ['/bin/sh', '-c', 'exec /bin/log']),
    # apr_tokenize_to_argv: quotes group only at a word start, backslashes are removed.
    ('"|/bin/log \'two words\' \\"q\\" a\\\\ b"', 'direct', ['/bin/log', 'two words', 'q', 'a b']),
    ('"|/bin/log mid\'quote"', 'direct', ['/bin/log', "mid'quote"]),
    # In shell mode the words are joined with single spaces, so the quotes are gone before sh sees them.
    ('"|$/bin/echo \'a  b\' >/tmp/x"', 'shell', ['/bin/sh', '-c', '/bin/echo a  b >/tmp/x']),
    ('|/bin/bare', 'direct', ['/bin/bare']),
])
def test_pipe_invocation_and_tokenisation(target, invocation, argv):
    result = run(f'CustomLog {target} common\n')
    assert progs(result) == [('CustomLog', 'main', invocation, argv)]


def test_tokenizer_matches_apr_edge_cases():
    assert apl.tokenize_to_argv('  a\t"b c"d \'e') == ['a', 'b c', 'd', 'e']
    assert apl.tokenize_to_argv('a\\ b c\\\\d') == ['a b', 'c\\d']
    assert apl.tokenize_to_argv('') == [] and apl.tokenize_to_argv('   ') == []


def test_every_access_log_directive_spawns_and_conditions_are_kept():
    main = ('GlobalLog "|/bin/g" common\n'
            'TransferLog "|/bin/t"\n'
            'CustomLog "|/bin/c" common env=!dontlog\n'
            'CustomLog "|/bin/c" common\n'
            '<IfModule mod_ssl.c>\n  CustomLog "|/bin/ssl" common expr=%{HTTPS}\n</IfModule>\n'
            'customlog /var/log/file common\n')
    result = run(main)
    assert [p['argv'][0] for p in result['programs']] == ['/bin/g', '/bin/t', '/bin/c', '/bin/c', '/bin/ssl']
    assert result['programs'][2]['log_condition'] == 'env=!dontlog'
    assert result['programs'][4]['conditions'] == ['<IfModule mod_ssl.c>']
    assert result['complete'] is True


def test_error_log_last_wins_and_vhost_sharing():
    main = ('ErrorLog "|/bin/first"\nErrorLog "|/bin/main"\n'
            '<VirtualHost a:80>\nErrorLog "|/bin/vhost"\n</VirtualHost>\n'
            '<VirtualHost b:80>\nErrorLog "|/bin/vhost"\n</VirtualHost>\n'
            '<VirtualHost c:80>\nErrorLog "|/bin/main"\n</VirtualHost>\n'
            '<VirtualHost d:80>\nServerName d\n</VirtualHost>\n')
    result = run(main)
    assert [(p['server'], p['argv'][0]) for p in result['programs']] == [('main', '/bin/main'),
                                                                         ('<VirtualHost a:80>', '/bin/vhost')]
    assert [(s['server'], s['shares_with']) for s in result['shared_error_logs']] == [
        ('<VirtualHost b:80>', '<VirtualHost a:80>'), ('<VirtualHost c:80>', 'main')]
    assert result['complete'] is True


def test_conditional_error_log_override_is_blocking():
    result = run('ErrorLog "|/bin/a"\n<IfModule x>\nErrorLog "|/bin/b"\n</IfModule>\n')
    assert 'error_log_conditional' in codes(result) and result['complete'] is False


def test_ifdefine_uses_d_flags_define_and_undefine():
    main = ('<IfDefine SSL>\nCustomLog "|/bin/ssl" c\n</IfDefine>\n'
            '<IfDefine !FOREGROUND>\nCustomLog "|/bin/bg" c\n<IfModule x>\n</IfModule>\n</IfDefine>\n'
            'Define LOGGER /opt/log\nCustomLog "|${LOGGER} -x" c\n'
            'UnDefine SSL\n<IfDefine SSL>\nCustomLog "|/bin/ssl2" c\n</IfDefine>\n')
    result = run(main, defines=['SSL', 'FOREGROUND'])
    assert [p['argv'] for p in result['programs']] == [['/bin/ssl'], ['/opt/log', '-x']]
    assert result['complete'] is True


def test_define_overrides_environment_and_conditional_define_is_uncertain():
    result = run('Define APACHE_LOG_DIR /srv/logs\nCustomLog "|/bin/r ${APACHE_LOG_DIR}/a" c\n')
    assert result['programs'][0]['argv'] == ['/bin/r', '/srv/logs/a']
    result = run('<IfModule x>\nDefine P /bin/p\n</IfModule>\nCustomLog "|${P}" c\n'
                 '<IfDefine P>\nCustomLog "|/bin/q" c\n</IfDefine>\n')
    assert 'variable_conditional' in codes(result) and result['complete'] is False
    assert result['programs'][1]['conditions'] == ['<IfDefine P>']


def test_unresolved_variable_in_log_or_include_is_blocking_but_colon_names_are_not():
    result = run('CustomLog "|/bin/r ${NOPE}" c\n')
    assert 'variable_unresolved' in codes(result) and result['complete'] is False
    result = run('CustomLog "|/bin/r ${a:b}" c\nRewriteRule x ${NOPE}\n')
    assert result['programs'][0]['argv'] == ['/bin/r', '${a:b}'] and result['complete'] is True


def test_line_continuation_and_comment_rules():
    main = ('CustomLog "|/bin/r \\\n   -x" \\\r\n common\n'
            '   # CustomLog "|/bin/commented" c\n'
            '# continued comment \\\nCustomLog "|/bin/swallowed" c\n'
            'CustomLog "|/bin/hash #notcomment" c\n')
    result = run(main)
    assert [p['argv'] for p in result['programs']] == [['/bin/r', '-x'], ['/bin/hash', '#notcomment']]
    assert result['programs'][0]['line'] == 1 and result['programs'][1]['line'] == 7


def test_server_root_changes_affect_later_includes_and_final_working_directory():
    main = 'Include a.conf\nServerRoot /srv/h\nInclude b.conf\nCustomLog "|bin/x" c\n'
    result = run(main, files={f'{ROOT}/a.conf': '', '/srv/h/b.conf': ''},
                 includes={f'{ROOT}/a.conf': [f'{ROOT}/a.conf'], '/srv/h/b.conf': ['/srv/h/b.conf']})
    assert result['files_parsed'] == [MAIN, f'{ROOT}/a.conf', '/srv/h/b.conf']
    assert result['programs'][0]['executable'] == '/srv/h/bin/x'
    assert result['programs'][0]['working_directory'] == '/srv/h' and result['complete'] is True


@pytest.mark.parametrize('main, files, includes, code', [
    ('Include x/*.conf\n', {}, {}, 'include_not_observed'),
    ('Include x/*.conf\n', {}, {f'{ROOT}/x/*.conf': []}, 'include_failed'),
    ('Include x.conf\n', {}, {f'{ROOT}/x.conf': []}, 'include_failed'),
    ('Include x.conf\n', {}, {f'{ROOT}/x.conf': [f'{ROOT}/x.conf']}, 'file_not_observed'),
    ('Include apache2.conf\n', {}, {MAIN: [MAIN]}, 'include_too_deep'),
    ('<VirtualHost *>\nCustomLog "|/b" c\n', {}, {}, 'container_unbalanced'),
    ('</IfModule>\n', {}, {}, 'container_unbalanced'),
    ('<IfModule x\n</IfModule>\n', {}, {}, 'container_malformed'),
    ('<VirtualHost a>\n<VirtualHost b>\n</VirtualHost>\n</VirtualHost>\n', {}, {}, 'nested_virtual_host'),
    ('<Directory />\nCustomLog "|/b" c\n</Directory>\n', {}, {}, 'directive_not_allowed'),
    ('<If "true">\nErrorLog "|/b"\n</If>\n', {}, {}, 'directive_not_allowed'),
    ('<VirtualHost a>\nGlobalLog "|/b" c\n</VirtualHost>\n', {}, {}, 'directive_not_allowed'),
    ('CustomLog "|/b"\n', {}, {}, 'arguments_malformed'),
    ('CustomLog "|/b" c bogus=1\n', {}, {}, 'arguments_malformed'),
    ('ErrorLog "|/b" extra\n', {}, {}, 'arguments_malformed'),
    ('CustomLog "|" c\n', {}, {}, 'empty_program'),
    ('CustomLog "|$  " c\n', {}, {}, 'empty_program'),
    ('<IfModule x>\nServerRoot /x\n</IfModule>\n', {}, {}, 'server_root_conditional'),
    ('<Macro M $a>\nCustomLog "|$a" c\n</Macro>\nUse M /bin/x\n', {}, {}, 'macro_unmodelled'),
    ('CustomLog "|/b\0" c\n', {}, {}, 'nul_byte'),
])
def test_fail_closed_gaps(main, files, includes, code):
    result = run(main, files=files, includes=includes)
    assert code in codes(result) and result['complete'] is False


def test_optional_include_without_match_and_include_inside_directory_are_fine():
    main = 'IncludeOptional none/*.conf\n<Directory /var/www>\nInclude d.conf\n</Directory>\n'
    result = run(main, files={f'{ROOT}/d.conf': 'Options None\n'},
                 includes={f'{ROOT}/none/*.conf': [], f'{ROOT}/d.conf': [f'{ROOT}/d.conf']})
    assert result['complete'] is True and result['programs'] == []


def test_false_ifdefine_section_is_soaked_unparsed():
    main = '<IfDefine NOPE>\nInclude never/*.conf\n<Directory />\nCustomLog "|/b" c\n</Directory>\n</IfDefine>\n'
    result = run(main)
    assert result['complete'] is True and result['programs'] == [] and result['gaps'] == []


def test_other_program_mechanisms_are_listed_not_resolved():
    main = ('RewriteMap lb "prg:/usr/local/bin/map"\nRewriteMap t txt:/etc/map.txt\n'
            'ExtFilterDefine f cmd="/bin/sed s/a/b/"\nSSLPassPhraseDialog exec:/usr/libexec/pass\n'
            'SSLPassPhraseDialog builtin\nSSLRandomSeed startup exec:/bin/seed\n')
    result = run(main)
    assert [o['directive'] for o in result['other_programs']] == ['RewriteMap', 'ExtFilterDefine',
                                                                   'SSLPassPhraseDialog', 'SSLRandomSeed']
    assert result['programs'] == [] and result['complete'] is True


@pytest.mark.parametrize('payload', [
    None, {}, {'server_root': 'rel', 'config_file': MAIN, 'files': {}},
    {'server_root': ROOT, 'config_file': MAIN, 'files': {}, 'defines': ['']},
    {'server_root': ROOT, 'config_file': MAIN, 'files': {}, 'environment': {'A': 1}},
])
def test_malformed_payloads(payload):
    result = apl.evaluate(payload)
    assert codes(result) == {'input_malformed'} and result['complete'] is False


def test_limits_and_non_string_text():
    assert 'text_too_large' in codes(run('#' * (apl.MAX_TEXT + 1)))
    assert 'input_malformed' in codes(run(5))
    result = run('CustomLog "|/bin/x" c\n')
    assert result['note'] == apl.NOT_A_VERDICT and result['reference'] == {'httpd': '2.4.62', 'apr': '1.7.5'}


def test_vhost_error_log_matching_a_conditional_main_log_is_still_reported():
    main = ('<IfModule x>\nErrorLog "|/bin/e"\n</IfModule>\n'
            '<VirtualHost a>\nErrorLog "|/bin/e"\n</VirtualHost>\n')
    result = run(main)
    assert [(p['server'], p.get('may_share_with')) for p in result['programs']] == [
        ('main', None), ('<VirtualHost a>', 'main')]
    assert result['programs'][0]['conditions'] == ['<IfModule x>'] and result['shared_error_logs'] == []


def test_only_ascii_white_space_separates_config_words():
    result = run('CustomLog |/bin/x\u00a0common\n')
    assert 'arguments_malformed' in codes(result)
    assert apl.getword_conf('a\u2003b c') == ('a\u2003b', 'c')
