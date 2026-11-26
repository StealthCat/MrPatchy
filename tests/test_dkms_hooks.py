import unittest

from app import dkms_hooks as d

CONF = '/var/lib/dkms/hello/1.0/source/dkms.conf'
SRC = '/var/lib/dkms/hello/1.0/source'
BUILD = '/var/lib/dkms/hello/1.0/build'

# The dkms.conf used in the native run of Ubuntu 24.04 dkms 3.0.11 (see the docs checkpoint),
# without its marker lines, which are tested separately.
NATIVE = '''PACKAGE_NAME=hello
PACKAGE_VERSION=1.0
BUILT_MODULE_NAME[0]=hello
DEST_MODULE_LOCATION[0]=/updates
STRIP[0]=no
MAKE[0]="touch hello.ko"
CLEAN="make clean"
POST_ADD="hook.sh add a1  a2"
PRE_BUILD="hook.sh prebuild"
POST_BUILD="/hook.sh postbuild"
PRE_INSTALL="hook.sh preinstall"
POST_INSTALL="noexec.sh postinstall"
POST_REMOVE="hook.sh remove"
'''


def file(text):
    return {'state': 'file', 'text': text}


def directory(**entries):
    return {'state': 'directory', 'entries': entries}


def paths(conf=NATIVE, etc=None, framework='', dropins=None, **extra):
    etc = etc or {}
    result = {
        d.FRAMEWORK_FILE: file(framework),
        d.FRAMEWORK_DIR: directory(**(dropins or {})),
        d.ETC_DKMS: directory(**{name: {} for name in etc}),
        CONF: file(conf),
    }
    for name, text in etc.items():
        result[f'{d.ETC_DKMS}/{name}'] = file(text)
    result.update(extra)
    return result


MODULE = [{'module': 'hello', 'version': '1.0', 'conf': CONF}]
EXEC = {f'{SRC}/hook.sh': True, f'{BUILD}/hook.sh': True, f'{BUILD}//hook.sh': True, f'{SRC}/noexec.sh': False}


def hooks(result, index=0):
    return {h['hook']: h for h in result['modules'][index]['hooks']}


class NativeRunTests(unittest.TestCase):
    """Expected values match what dkms 3.0.11 did as root in the native run."""

    def setUp(self):
        self.result = d.assess(paths(etc={'hello.conf': "POST_REMOVE='hook.sh remove-override'\n",
                                          'hello-1.0.conf': ''}), MODULE, executables=EXEC)
        self.hooks = hooks(self.result)

    def test_complete_and_never_authorizes(self):
        self.assertTrue(self.result['complete'])
        self.assertFalse(self.result['authorizes_response'])
        self.assertEqual(self.result['origin'], 'not_assessed')

    def test_source_hooks_run_from_source_with_collapsed_whitespace(self):
        # native: hook pwd=.../source argv=.../source/hook.sh add a1 a2
        self.assertEqual(self.hooks['POST_ADD']['state'], 'runs')
        self.assertEqual(self.hooks['POST_ADD']['directory'], SRC)
        self.assertEqual(self.hooks['POST_ADD']['argv'], [f'{SRC}/hook.sh', 'add', 'a1', 'a2'])
        self.assertEqual(self.hooks['PRE_INSTALL']['argv'], [f'{SRC}/hook.sh', 'preinstall'])

    def test_build_hooks_run_a_copy_and_absolute_values_stay_under_build(self):
        self.assertEqual(self.hooks['PRE_BUILD']['argv'], [f'{BUILD}/hook.sh', 'prebuild'])
        self.assertEqual(self.hooks['PRE_BUILD']['copied_from'], f'{SRC}/hook.sh')
        # native: argv=/var/lib/dkms/hello/1.0/build//hook.sh postbuild
        self.assertEqual(self.hooks['POST_BUILD']['program'], f'{BUILD}//hook.sh')

    def test_non_executable_hook_is_skipped(self):
        # native: "Warning: The post_install script is not executable."
        self.assertEqual(self.hooks['POST_INSTALL']['state'], 'skipped_not_executable')

    def test_module_override_is_sourced_after_dkms_conf_and_wins(self):
        # native: override-module, override-module-version, then hook.sh remove-override
        files = [f['path'] for f in self.result['modules'][0]['sourced_files']]
        self.assertEqual(files, [CONF, '/etc/dkms/hello.conf', '/etc/dkms/hello-1.0.conf'])
        self.assertEqual(self.hooks['POST_REMOVE']['argv'], [f'{SRC}/hook.sh', 'remove-override'])
        self.assertEqual(self.hooks['POST_REMOVE']['source'], {'path': '/etc/dkms/hello.conf', 'line': 1})

    def test_make_and_clean_are_root_eval(self):
        make = self.result['modules'][0]['make']
        self.assertEqual(make['make_candidates'][0]['command'], 'touch hello.ko')
        self.assertFalse(make['default_make_possible'])
        self.assertEqual(make['clean'], 'make clean')

    def test_every_sourced_file_is_root(self):
        for f in self.result['modules'][0]['sourced_files'] + self.result['framework']['sourced_files']:
            self.assertEqual(f['sourced_as'], 'root')


class FrameworkTests(unittest.TestCase):
    def test_only_conf_dropins_in_byte_order(self):
        # native: AA.conf then zz.conf; "noext" was not sourced
        result = d.assess(paths(dropins={'zz.conf': file(''), 'AA.conf': file(''), 'noext': file('x')}),
                          MODULE, executables=EXEC)
        self.assertEqual([f['path'] for f in result['framework']['sourced_files']],
                         [d.FRAMEWORK_FILE, f'{d.FRAMEWORK_DIR}/AA.conf', f'{d.FRAMEWORK_DIR}/zz.conf'])
        self.assertIn('order_locale_dependent', {g['code'] for g in result['gaps']})

    def test_dkms_tree_override_moves_hook_paths(self):
        result = d.assess(paths(framework='dkms_tree="/srv/dkms"\n'), MODULE,
                          executables={'/srv/dkms/hello/1.0/source/hook.sh': True})
        self.assertEqual(hooks(result)['POST_ADD']['program'], '/srv/dkms/hello/1.0/source/hook.sh')
        self.assertEqual(hooks(result)['POST_ADD']['state'], 'runs')

    def test_framework_code_makes_hook_paths_unknown_but_keeps_argv(self):
        result = d.assess(paths(framework='dkms_tree=$(cat /x)\n'), MODULE, executables=EXEC)
        self.assertIsNone(result['framework']['dkms_tree'])
        hook = hooks(result)['POST_ADD']
        self.assertEqual((hook['state'], hook['reason'], hook['value']), ('unknown', 'dkms_tree_unknown',
                                                                         'hook.sh add a1 a2'))
        self.assertFalse(result['framework']['sourced_files'][0]['only_literal_assignments'])

    def test_sign_file_reported(self):
        result = d.assess(paths(framework="sign_file='/opt/sign'\n"), MODULE, executables=EXEC)
        self.assertEqual(result['framework']['sign_file'], '/opt/sign')


class FailClosedTests(unittest.TestCase):
    def state(self, conf, executables=EXEC, **kw):
        return hooks(d.assess(paths(conf=conf, **kw), MODULE, executables=executables))['POST_ADD']

    def test_single_quoted_substitution_is_reinterpreted(self):
        # native: POST_ADD='hook.sh $(echo ...)lit' ran the substitution as root
        hook = self.state("POST_ADD='hook.sh $(id)lit'\n")
        self.assertEqual((hook['state'], hook['reason']), ('unknown', 'reinterpreted_value'))
        self.assertTrue(d.echo_back('hook.sh $(id)')['executes_when_sourced'])

    def test_glob_is_unknown(self):
        # native: "hook.s? g*" was glob-expanded and then not run
        self.assertEqual(self.state('POST_ADD="hook.s? g*"\n')['reason'], 'glob_in_value')

    def test_any_command_line_makes_values_unknown(self):
        for line in ('echo hi', 'POST_ADD=a; POST_ADD=b', 'f() { :; }', 'POST_ADD="a \\', 'POST_ADD=~/x',
                     'DKMS_DIRECTIVE_X=1', 'POST_ADD="${x}"'):
            with self.subTest(line=line):
                hook = self.state(f'POST_ADD=hook.sh\n{line}\n')
                self.assertEqual((hook['state'], hook['reason']), ('unknown', 'conf_not_understood'))

    def test_comments_and_trailing_comments_are_understood(self):
        hook = self.state('# c\n  POST_ADD="hook.sh"x # trailing\n')
        self.assertEqual(hook['argv'], [f'{SRC}/hook.shx'])

    def test_unobserved_executable_bit_is_unknown(self):
        hook = self.state('POST_ADD=hook.sh\n', executables={})
        self.assertEqual((hook['state'], hook['reason']), ('unknown', 'executable_bit_not_observed'))

    def test_empty_value_is_not_configured(self):
        self.assertEqual(self.state('POST_ADD=\n')['state'], 'not_configured')

    def test_missing_etc_listing_and_unreadable_conf_block(self):
        p = paths()
        del p[d.ETC_DKMS]
        result = d.assess(p, MODULE, executables=EXEC)
        self.assertEqual(hooks(result)['POST_ADD']['state'], 'unknown')
        self.assertFalse(d.assess(paths(**{CONF: {'state': 'unreadable'}}), MODULE)['complete'])

    def test_kernel_override_needs_kernel_context(self):
        etc = {'hello-1.0-6.8.0-1-generic.conf': 'POST_ADD="hook.sh k"\n'}
        self.assertEqual(self.state(NATIVE, etc=etc)['state'], 'unknown')
        result = d.assess(paths(etc=etc), MODULE, kernels=[{'kernel': '6.8.0-1-generic', 'arch': 'x86_64'}],
                          executables=EXEC)
        self.assertEqual(hooks(result)['POST_ADD']['argv'], [f'{SRC}/hook.sh', 'k'])

    def test_array_elements_accumulate_across_the_chain(self):
        result = d.assess(paths(conf='MAKE[0]="make a"\n', etc={'hello.conf': 'MAKE[1]="make b"\n'
                                                                'MAKE_MATCH[1]="^6"\n'}), MODULE)
        make = result['modules'][0]['make']
        self.assertEqual([(c['index'], c['command'], c['match_regex']) for c in make['make_candidates']],
                         [(0, 'make a', None), (1, 'make b', '^6')])


if __name__ == '__main__':
    unittest.main()
