"""Pure dnsmasq script contract (roadmap F slice, #1365).

dnsmasq runs programs because of its configuration:

* ``dhcp-script`` (``-6``) runs on every DHCP lease event, and also on ARP
  changes with ``script-arp`` and TFTP transfers with ``enable-tftp``.
* ``dhcp-luascript`` runs on the same events.
* ``conf-script`` is run through ``popen()`` (``/bin/sh -c``) while the
  configuration is read, before privileges are dropped, and its output is read
  as more configuration.

This contract takes the daemon's captured argv, captured configuration texts
and captured directory listings, and says which of these programs dnsmasq would
run and as which user. It follows the main file, ``conf-file`` and ``conf-dir``.

Semantics follow dnsmasq 2.92 (``src/option.c`` and ``src/dnsmasq.c``, as
shipped in Debian and Ubuntu ``dnsmasq_2.92``):

* The command line is read first, in order. The first ``-C``/``--conf-file``
  becomes the main file and is read after the command line. Later ones, and
  every ``-7``/``--conf-dir``, are read at once. Without ``-C`` the main file is
  ``/etc/dnsmasq.conf``, and it may be missing.
* A configuration line keeps ``#`` comments only after whitespace. Double
  quotes protect text, with ``\\" \\\\ \\t \\n \\e \\b \\r`` escapes. Spaces
  around ``=`` are ignored, and the option name must match exactly.
* ``conf-dir=DIR[,SUFFIX...]`` skips names that end in ``~``, start with
  ``.``, or start and end with ``#``. ``*SUFFIX`` arguments are required
  suffixes and the others are ignored suffixes. Only regular files (after
  following symlinks) are read, in ``strcmp`` order of their paths.
* A file whose device and inode were already read is skipped.
* ``dhcp-script`` and ``dhcp-scriptuser`` take one value. Repeating one on the
  command line, or repeating one across files, makes dnsmasq refuse to start,
  but a file value overrides the command line. ``dhcp-luascript`` keeps the last
  value, and an empty value clears either script.
* Scripts run in a helper process. It runs as root unless ``dhcp-scriptuser``
  is set and a ``dhcp-range`` exists. In ``no-daemon`` (``-d``) mode it keeps
  the daemon's own user, which is root for the packaged service.

The contract performs no I/O, never runs a command and never authorizes a
response action. Unobserved files, directories or identities, ``conf-script``
output (which it cannot see), stdin configuration, abbreviated long options,
over-long lines, malformed input and over-limit input are blocking gaps. A
configuration dnsmasq would refuse is reported as ``refused``, with its reason.
Option values that have nothing to do with scripts are not checked. The account
named by ``dhcp-scriptuser`` is not resolved. No record is labelled safe, and
``origin`` is always ``not_assessed``.
"""
from __future__ import annotations

from typing import Any

CONTRACT_VERSION = 1
REFERENCES = ('dnsmasq 2.92 src/option.c, src/dnsmasq.c, src/helper.c (dnsmasq_2.92.orig.tar.gz)',
              'debian/systemd-helper and debian/dnsmasq.default (dnsmasq_2.92-1)')
DEFAULT_CONF = '/etc/dnsmasq.conf'
# Debian's /etc/default/dnsmasq CONFIG_DIR, passed as -7 by systemd-helper.
DEBIAN_ARGV = ('/usr/sbin/dnsmasq', '-x', '/run/dnsmasq/dnsmasq.pid', '-u', 'dnsmasq',
               '-7', '/etc/dnsmasq.d,.dpkg-dist,.dpkg-old,.dpkg-new', '--local-service')
OPTSTRING = '951yZDNLERKzowefnbvhdkqr:m:p:c:l:s:i:t:u:g:a:x:S:C:A:T:H:Q:I:B:F:G:O:M:X:V:U:j:P:J:W:Y:2:4:6:7:8:0:3:'
MAXDNAME = 1025
MAX_FILES = 512
MAX_LINES = 20000
# Long option name -> has_arg (0 none, 1 required, 2 optional), from opts[] in option.c.
LONG_OPTIONS = {
    'version': 0, 'no-hosts': 0, 'no-poll': 0, 'help': 0, 'no-daemon': 0, 'log-queries':
    2, 'user': 2, 'group': 2, 'resolv-file': 2, 'servers-file': 1, 'mx-host': 1,
    'mx-target': 1, 'cache-size': 2, 'port': 1, 'dhcp-leasefile': 2, 'dhcp-lease': 1,
    'dhcp-host': 1, 'dhcp-range': 1, 'dhcp-option': 1, 'dhcp-boot': 1, 'domain': 1,
    'domain-suffix': 1, 'interface': 1, 'listen-address': 1, 'local-service': 2,
    'bogus-priv': 0, 'bogus-nxdomain': 1, 'ignore-address': 1, 'selfmx': 0,
    'filterwin2k': 0, 'filter-A': 0, 'filter-AAAA': 0, 'filter-rr': 1, 'pid-file': 2,
    'strict-order': 0, 'server': 1, 'rev-server': 1, 'local': 1, 'address': 1,
    'conf-file': 2, 'conf-script': 1, 'no-resolv': 0, 'expand-hosts': 0, 'localmx': 0,
    'local-ttl': 1, 'no-negcache': 0, 'no-round-robin': 0, 'no-0x20-encode': 0,
    'do-0x20-encode': 0, 'cache-rr': 1, 'addn-hosts': 1, 'hostsdir': 1, 'query-port': 1,
    'except-interface': 1, 'no-dhcp-interface': 1, 'no-dhcpv4-interface': 1,
    'no-dhcpv6-interface': 1, 'domain-needed': 0, 'dhcp-lease-max': 1,
    'bind-interfaces': 0, 'read-ethers': 0, 'alias': 1, 'dhcp-vendorclass': 1,
    'dhcp-userclass': 1, 'dhcp-ignore': 1, 'edns-packet-max': 1, 'keep-in-foreground':
    0, 'dhcp-authoritative': 0, 'srv-host': 1, 'localise-queries': 0, 'txt-record': 1,
    'caa-record': 1, 'dns-rr': 1, 'enable-dbus': 2, 'enable-ubus': 2, 'bootp-dynamic':
    2, 'dhcp-mac': 1, 'no-ping': 0, 'dhcp-script': 1, 'conf-dir': 1, 'log-facility': 1,
    'leasefile-ro': 0, 'script-on-renewal': 0, 'dns-forward-max': 1, 'clear-on-reload':
    0, 'dhcp-ignore-names': 2, 'enable-tftp': 2, 'tftp-secure': 0, 'tftp-no-fail': 0,
    'tftp-unique-root': 2, 'tftp-root': 1, 'tftp-max': 1, 'tftp-mtu': 1,
    'tftp-lowercase': 0, 'tftp-single-port': 0, 'ptr-record': 1, 'naptr-record': 1,
    'bridge-interface': 1, 'shared-network': 1, 'dhcp-option-force': 1,
    'dhcp-option-pxe': 1, 'tftp-no-blocksize': 0, 'log-dhcp': 0, 'log-async': 2,
    'dhcp-circuitid': 1, 'dhcp-remoteid': 1, 'dhcp-subscrid': 1, 'dhcp-pxe-vendor': 1,
    'interface-name': 1, 'dhcp-hostsfile': 1, 'dhcp-optsfile': 1, 'dhcp-hostsdir': 1,
    'dhcp-optsdir': 1, 'dhcp-no-override': 0, 'tftp-port-range': 1, 'stop-dns-rebind':
    0, 'rebind-domain-ok': 1, 'all-servers': 0, 'dhcp-match': 1, 'dhcp-name-match': 1,
    'dhcp-broadcast': 2, 'neg-ttl': 1, 'max-ttl': 1, 'min-cache-ttl': 1,
    'max-cache-ttl': 1, 'dhcp-alternate-port': 2, 'dhcp-scriptuser': 1, 'min-port': 1,
    'max-port': 1, 'dhcp-fqdn': 0, 'cname': 1, 'pxe-prompt': 1, 'pxe-service': 1,
    'test': 0, 'tag-if': 1, 'dhcp-proxy': 2, 'dhcp-generate-names': 2,
    'rebind-localhost-ok': 0, 'add-mac': 2, 'strip-mac': 0, 'add-subnet': 2,
    'strip-subnet': 0, 'add-cpe-id': 1, 'proxy-dnssec': 0, 'dhcp-sequential-ip': 0,
    'conntrack': 0, 'dhcp-client-update': 0, 'dhcp-luascript': 1, 'enable-ra': 0,
    'dhcp-duid': 1, 'host-record': 1, 'bind-dynamic': 0, 'auth-zone': 1, 'auth-server':
    1, 'auth-ttl': 1, 'auth-soa': 1, 'auth-sec-servers': 1, 'auth-peer': 1, 'ipset': 1,
    'nftset': 1, 'connmark-allowlist-enable': 2, 'connmark-allowlist': 1,
    'synth-domain': 1, 'dnssec': 0, 'trust-anchor': 1, 'dnssec-debug': 0,
    'dnssec-check-unsigned': 2, 'dnssec-no-timecheck': 0, 'dnssec-timestamp': 1,
    'dnssec-limits': 1, 'dhcp-relay': 1, 'dhcp-split-relay': 1, 'ra-param': 1,
    'quiet-dhcp': 0, 'quiet-dhcp6': 0, 'quiet-ra': 0, 'dns-loop-detect': 0,
    'script-arp': 0, 'dhcp-ttl': 1, 'dhcp-reply-delay': 1, 'dhcp-rapid-commit': 0,
    'dumpfile': 1, 'dumpmask': 1, 'dhcp-ignore-clid': 0, 'dynamic-host': 1, 'log-debug':
    0, 'umbrella': 2, 'quiet-tftp': 0, 'port-limit': 1, 'fast-dns-retry': 2,
    'use-stale-cache': 2, 'no-ident': 0, 'max-tcp-connections': 1, 'leasequery': 2,
}
# Short options that matter here -> their long names. Every other OPTSTRING
# letter is parsed for argument consumption only.
SHORT_NAMES = {'6': 'dhcp-script', '7': 'conf-dir', 'C': 'conf-file', 'd': 'no-daemon', 'F': 'dhcp-range'}
SINGLE_VALUE = ('dhcp-script', 'dhcp-scriptuser')
# Options that make dnsmasq start the script helper (dnsmasq.c create_helper()).
HELPER_ACTIVATORS = ('dhcp-range', 'dhcp-relay', 'enable-tftp', 'script-arp')
# Characters hide_meta() hides inside quotes (option.c meta[]); '=' is not one.
META = frozenset('\x00123456 \b\t\n78\r90abcdefABCDE\x1bF:,.')
C_SPACE = frozenset(' \t\n\v\f\r')
ESCAPES = {'"': '"', 't': '\t', 'n': '\n', 'e': '\x1b', 'b': '\b', 'r': '\r', '\\': '\\'}


class Refused(Exception):
    """dnsmasq would exit with a configuration error."""

    located = False


class _Blocked(Exception):
    """The input does not let the contract follow dnsmasq any further."""


def _short_table() -> dict[str, bool]:
    table: dict[str, bool] = {}
    i = 0
    while i < len(OPTSTRING):
        takes = i + 1 < len(OPTSTRING) and OPTSTRING[i + 1] == ':'
        table[OPTSTRING[i]] = takes
        i += 2 if takes else 1
    return table


SHORT_OPTIONS = _short_table()


def parse_line(line: str) -> list[tuple[str, bool]] | None:
    """Apply read_file()'s quote, escape and comment rules.

    Returns (char, hidden) pairs with leading and trailing spaces stripped, or
    None for a blank or comment line. Raises Refused for an unterminated quote.
    """
    chars = list(line)
    hidden = [False] * len(chars)
    white = True
    p = 0
    while p < len(chars):
        if chars[p] == '"':
            del chars[p], hidden[p]
            while p < len(chars) and chars[p] != '"':
                if chars[p] == '\\' and p + 1 < len(chars) and chars[p + 1] in ESCAPES:
                    chars[p + 1] = ESCAPES[chars[p + 1]]
                    del chars[p], hidden[p]
                hidden[p] = chars[p] in META
                p += 1
            if p >= len(chars):
                raise Refused('missing "')
            del chars[p], hidden[p]
            if p >= len(chars):
                # read_file() would step past the terminator here; only a final
                # line without a newline can end in a closing quote.
                raise _Blocked('line_ends_in_quote')
        if chars[p] in C_SPACE:
            chars[p] = ' '
            white = True
        else:
            if white and chars[p] == '#':
                del chars[p:], hidden[p:]
                break
            white = False
        p += 1
    pairs = list(zip(chars, hidden))
    while pairs and pairs[0] == (' ', False):
        pairs.pop(0)
    while pairs and pairs[-1] == (' ', False):
        pairs.pop()
    return pairs or None


def _text(pairs: list[tuple[str, bool]]) -> str:
    return ''.join(c for c, _ in pairs)


def split_line(pairs: list[tuple[str, bool]]) -> tuple[list[tuple[str, bool]], list[tuple[str, bool]] | None]:
    """Split an option line at its first '=', as read_file() does."""
    for i, (c, _) in enumerate(pairs):
        if c == '=':
            arg = pairs[i + 1:]
            while arg and arg[0] == (' ', False):
                arg.pop(0)
            name = pairs[:i]
            while name and name[-1][0] in ' =' and not name[-1][1]:
                name.pop()
            return name, arg
    return pairs, None


def split_commas(pairs: list[tuple[str, bool]]) -> list[str]:
    """split(): cut at unhidden commas and trim unhidden spaces around them."""
    parts: list[list[tuple[str, bool]]] = [[]]
    for c, h in pairs:
        if c == ',' and not h:
            parts.append([])
        else:
            parts[-1].append((c, h))
    out = []
    for i, part in enumerate(parts):
        if i > 0:
            while part and part[0] == (' ', False):
                part.pop(0)
        if i < len(parts) - 1:
            while part and part[-1] == (' ', False):
                part.pop()
        out.append(_text(part))
    return out


def conf_dir_files(directory: str, suffixes: list[str], entries: Any) -> tuple[list[str], list[dict[str, Any]]]:
    """Which files ``conf-dir`` reads, in order, and why the others are not read."""
    match = [s[1:] for s in suffixes if s.startswith('*') and len(s) > 1]
    ignore = [s for s in suffixes if s and not s.startswith('*')]
    chosen: list[str] = []
    skipped: list[dict[str, Any]] = []
    if not isinstance(entries, (list, tuple)):
        raise _Blocked('directory_unobserved')
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get('name'), str) or '/' in entry['name']:
            raise _Blocked('malformed_directory_entry')
        name = entry['name']
        kind = entry.get('type')
        path = directory + '/' + name
        if not name or name.endswith('~') or (name[0] == '#' and name[-1] == '#') or name[0] == '.':
            skipped.append({'path': path, 'reason': 'backup_or_dotfile'})
            continue
        if match and not any(len(name) > len(s) and name.endswith(s) for s in match):
            skipped.append({'path': path, 'reason': 'missing_required_suffix'})
            continue
        if any(len(name) > len(s) and name.endswith(s) for s in ignore):
            skipped.append({'path': path, 'reason': 'ignored_suffix'})
            continue
        if kind == 'error':
            raise Refused(f'cannot access {path}')
        if kind not in ('regular', 'directory', 'other'):
            raise _Blocked('directory_entry_type_unobserved')
        if kind != 'regular':
            skipped.append({'path': path, 'reason': 'not_regular_file'})
            continue
        chosen.append(path)
    chosen.sort(key=lambda s: s.encode('utf-8', 'surrogateescape'))
    return chosen, skipped


class _State:
    def __init__(self, files: dict, dirs: dict, lua_support: Any) -> None:
        self.files = files
        self.dirs = dirs
        self.lua_support = lua_support
        self.values: dict[str, dict[str, Any] | None] = {'dhcp-script': None, 'dhcp-luascript': None,
                                                         'dhcp-scriptuser': None}
        self.rept: dict[str, str] = {}
        self.read: list[str] = []
        self.skipped: list[dict[str, Any]] = []
        self.seen: set[tuple[Any, Any]] = set()
        self.conf_scripts: list[dict[str, Any]] = []
        self.activators: set[str] = set()
        self.no_daemon = False
        self.lines = 0

    def option(self, name: str, arg: str | None, source: dict[str, Any], command_line: bool,
               raw: list[tuple[str, bool]] | None = None) -> None:
        if name in SINGLE_VALUE:
            used = self.rept.get(name)
            if command_line:
                if used == 'cl':
                    raise Refused(f'illegal repeated flag --{name}')
                self.rept[name] = 'cl'
            else:
                if used == 'file':
                    raise Refused(f'illegal repeated keyword {name}')
                self.rept[name] = 'file'
        if name in HELPER_ACTIVATORS:
            self.activators.add(name)
        if name == 'no-daemon':
            self.no_daemon = True
        value = arg or None  # opt_string_alloc() returns NULL for an empty value.
        if name in self.values:
            if name == 'dhcp-luascript' and value is not None and self.lua_support is not True:
                if self.lua_support is False:
                    raise Refused('recompile with HAVE_LUASCRIPT defined to enable Lua scripts')
                raise _Blocked('lua_support_unobserved')
            self.values[name] = None if value is None else {'value': value, **source}
        elif name == 'conf-file':
            if value is not None:
                self.one_file(value, source)
        elif name == 'conf-script':
            if value is not None:
                self.conf_scripts.append({'command': value, **source})
                raise _Blocked('conf_script_output_unobserved')
        elif name == 'conf-dir':
            parts = split_commas(raw) if raw is not None else split_commas([(c, False) for c in arg or ''])
            directory = parts[0] if parts else ''
            if not directory:
                return
            if directory not in self.dirs:
                raise _Blocked('directory_unobserved', directory)
            listing = self.dirs[directory]
            if isinstance(listing, dict) and listing.get('error'):
                raise Refused(f'cannot access directory {directory}')
            chosen, skipped = conf_dir_files(directory, parts[1:], listing)
            self.skipped.extend(skipped)
            for path in chosen:
                self.one_file(path, source, from_dir=directory)

    def one_file(self, path: str, source: dict[str, Any], *, default: bool = False,
                 from_dir: str | None = None) -> None:
        if path == '-':
            raise _Blocked('stdin_configuration', path)
        if len(self.read) >= MAX_FILES:
            raise _Blocked('file_limit', path)
        if path not in self.files:
            raise _Blocked('file_unobserved', path)
        info = self.files[path]
        if not isinstance(info, dict):
            raise _Blocked('malformed_file', path)
        error = info.get('error')
        if error is not None:
            if error == 'ENOENT' and default:
                self.skipped.append({'path': path, 'reason': 'default_file_missing'})
                return
            raise Refused(f'cannot read {path}: {error}')
        dev, ino, text = info.get('dev'), info.get('ino'), info.get('text')
        if not isinstance(dev, int) or not isinstance(ino, int):
            raise _Blocked('file_identity_unobserved', path)
        if not isinstance(text, str) or '\x00' in text:
            raise _Blocked('malformed_file', path)
        if (dev, ino) in self.seen:
            self.skipped.append({'path': path, 'reason': 'already_read'})
            return
        self.seen.add((dev, ino))
        self.read.append(path)
        # fgets() splits on '\n' only; '\r' and other separators stay in the line.
        lines = [chunk + '\n' for chunk in text.split('\n')]
        if lines[-1] == '\n':
            lines.pop()
        else:
            lines[-1] = lines[-1][:-1]
        for lineno, line in enumerate(lines, 1):
            self.lines += 1
            if self.lines > MAX_LINES:
                raise _Blocked('line_limit', path)
            if len(line.encode('utf-8', 'surrogateescape')) > MAXDNAME - 1:
                raise _Blocked('line_too_long', f'{path}:{lineno}')
            try:
                pairs = parse_line(line)
                if pairs is None:
                    continue
                name_pairs, arg_pairs = split_line(pairs)
                name = _text(name_pairs)
                has_arg = LONG_OPTIONS.get(name) if not any(h for _, h in name_pairs) else None
                if has_arg is None:
                    raise Refused('bad option')
                if has_arg == 0 and arg_pairs is not None:
                    raise Refused('extraneous parameter')
                if has_arg == 1 and arg_pairs is None:
                    raise Refused('missing parameter')
                arg = None if arg_pairs is None else _text(arg_pairs)
                self.option(name, arg, {'path': path, 'line': lineno}, False, arg_pairs)
            except Refused as exc:
                if exc.located:  # Already reported by the included file, as dnsmasq does.
                    raise
                located = Refused(f'{exc} at line {lineno} of {path}')
                located.located = True
                raise located from None


def parse_argv(argv: list[str]) -> list[tuple[str, str | None]]:
    """getopt_long() over dnsmasq's argv, as (long name or short letter, argument) pairs."""
    out: list[tuple[str, str | None]] = []
    i = 1
    while i < len(argv):
        token = argv[i]
        i += 1
        if token == '--':
            if any(t.strip(''.join(C_SPACE)) for t in argv[i:]):
                raise Refused('junk found in command line')
            break
        if token.startswith('--'):
            name, eq, value = token[2:].partition('=')
            if name not in LONG_OPTIONS:
                if any(n.startswith(name) for n in LONG_OPTIONS) and name:
                    raise _Blocked('abbreviated_long_option', token)
                raise Refused(f'unrecognized option {token}')
            has_arg = LONG_OPTIONS[name]
            if has_arg == 0 and eq:
                raise Refused(f'option --{name} does not take an argument')
            if has_arg == 1 and not eq:
                if i >= len(argv):
                    raise Refused(f'option --{name} requires an argument')
                value = argv[i]
                i += 1
            out.append((name, value if (eq or has_arg == 1) else None))
        elif token.startswith('-') and token != '-':
            j = 1
            while j < len(token):
                letter = token[j]
                if letter not in SHORT_OPTIONS:
                    raise Refused(f'invalid option -{letter}')
                if SHORT_OPTIONS[letter]:
                    value = token[j + 1:]
                    if not value:
                        if i >= len(argv):
                            raise Refused(f'option -{letter} requires an argument')
                        value = argv[i]
                        i += 1
                    out.append((SHORT_NAMES.get(letter, '-' + letter), value))
                    break
                out.append((SHORT_NAMES.get(letter, '-' + letter), None))
                j += 1
        elif token.strip(''.join(C_SPACE)):
            # GNU getopt permutes operands to the end, where dnsmasq rejects them.
            raise Refused('junk found in command line')
    return out


def _gap(code: str, path: str | None = None) -> dict[str, Any]:
    return {'code': code, 'path': path, 'blocking': True}


def evaluate(argv: Any, files: Any, dirs: Any = None, *, lua_support: Any = None) -> dict[str, Any]:
    """Resolve which programs dnsmasq runs, and as which user.

    ``argv`` is the daemon's full argv (``argv[0]`` included), for example from
    ``/proc/<pid>/cmdline`` or :data:`DEBIAN_ARGV`. ``files`` maps a path to
    ``{'text', 'dev', 'ino'}`` or ``{'error': 'ENOENT' | ...}``. ``dirs`` maps
    a ``conf-dir`` directory to a list of ``{'name', 'type'}`` entries, where
    ``type`` is ``regular``, ``directory``, ``other`` or ``error`` after
    following symlinks, or to ``{'error': ...}`` when it cannot be opened.
    ``lua_support`` says whether the installed binary has Lua support
    (``dnsmasq-base-lua``).
    """
    result: dict[str, Any] = {
        'contract_version': CONTRACT_VERSION, 'origin': 'not_assessed', 'complete': False,
        'refused': None, 'programs': [], 'files_read': [], 'skipped': [], 'gaps': [],
    }
    if (not isinstance(argv, (list, tuple)) or not argv
            or not all(isinstance(a, str) and '\x00' not in a for a in argv)):
        result['gaps'].append(_gap('argv_unobserved'))
        return result
    if not isinstance(files, dict) or (dirs is not None and not isinstance(dirs, dict)):
        result['gaps'].append(_gap('malformed_input'))
        return result
    state = _State(files, dirs or {}, lua_support)
    try:
        try:
            conffile = None
            for name, arg in parse_argv(list(argv)):
                source = {'path': None, 'line': None, 'command_line': True}
                if name == 'conf-file' and conffile is None:
                    # opt_string_alloc() of a missing value leaves the default file in place.
                    conffile = arg or None
                    continue
                if name == 'conf-file':
                    if not arg:
                        raise _Blocked('malformed_argv')  # one_file(NULL) is undefined behaviour.
                    state.one_file(arg, source)
                    continue
                state.option(name, arg, source, True)
            if conffile is not None:
                state.one_file(conffile, {'path': None, 'line': None, 'command_line': True})
            else:
                state.one_file(DEFAULT_CONF, {'path': None, 'line': None, 'command_line': False},
                               default=True)
        except Refused as exc:
            result['refused'] = str(exc)
    except _Blocked as exc:
        result['gaps'].append(_gap(exc.args[0], exc.args[1] if len(exc.args) > 1 else None))
    result['files_read'] = list(state.read)
    result['skipped'] = list(state.skipped)
    for script in state.conf_scripts:
        result['programs'].append({
            'kind': 'conf-script', 'command': script['command'], 'via': '/bin/sh -c',
            'when': 'while the configuration is read', 'run_as': 'root',
            'source': {k: script.get(k) for k in ('path', 'line')}, 'origin': 'not_assessed',
        })
    if result['refused'] is None and not result['gaps']:
        runs_as = 'root'
        user = state.values['dhcp-scriptuser']
        if state.no_daemon:
            runs_as = 'root'  # helper.c skips setuid() in debug mode; the packaged service starts as root.
        elif user is not None and 'dhcp-range' in state.activators:
            runs_as = user['value']
        for kind in ('dhcp-script', 'dhcp-luascript'):
            entry = state.values[kind]
            if entry is None:
                continue
            result['programs'].append({
                'kind': kind, 'command': entry['value'],
                'via': 'execl' if kind == 'dhcp-script' else 'lua',
                'when': 'DHCP lease events, ARP changes with script-arp, TFTP transfers with enable-tftp',
                'runs': bool(state.activators),
                'activated_by': sorted(state.activators),
                'run_as': runs_as,
                'source': {k: entry.get(k) for k in ('path', 'line')}, 'origin': 'not_assessed',
            })
        result['complete'] = True
    return result
