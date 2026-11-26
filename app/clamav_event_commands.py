"""Pure ClamAV event-command contract (roadmap F slice, #1607).

Takes captured ``clamd.conf`` and ``freshclam.conf`` text and reports which
administrator-configured shell commands ClamAV runs on its own events, on which
event, through which ``/bin/sh`` invocation and as which account:

* clamd ``VirusEvent``: run for every detection, as the clamd ``User``.
* freshclam ``OnUpdateExecute``, ``OnErrorExecute`` and ``OnOutdatedExecute``:
  run after a database update, on an update error, or when a newer ClamAV is
  announced, as ``DatabaseOwner``.

The contract never reads a file, resolves an account, evaluates the environment
or runs a command. Ported from ClamAV 1.5.4:

* ``common/optparser.c`` ``optparse`` with a config file: each ``fgets`` chunk
  is at most 1023 bytes, so a longer line continues as a new line. Leading
  spaces and tabs are skipped (always keeping the last byte). A chunk of at most
  two bytes or starting with ``#`` is skipped. A chunk starting with ``Example``
  rejects the file. The name ends at the first space or tab, and a name with no
  argument rejects the file. The argument loses leading spaces and tabs and
  trailing spaces, tabs and newlines. An argument starting with ``"`` ends at the
  last ``"``; a missing closing quote or an empty quoted value rejects the file.
  Names match the option name or its long command-line name, case-sensitively,
  so ``on-error-execute`` works in a file. An unknown name rejects the file and a
  deprecated one is ignored. Bool, number and size values must match their
  regular expression *before* inline comments are removed. A ``#`` anywhere in
  the value, even inside quotes, then starts a comment (``strtok``), and an
  all-``#`` value crashes the parser. For a single-valued option the first
  occurrence wins.
* ``clamd/clamd_others.c`` ``virusaction``: every ``%v`` becomes the detected
  signature name, unescaped, and every ``%f`` becomes a fixed message. clamd
  runs ``execle("/bin/sh", "sh", "-c", command)`` and waits for it, under a
  mutex shared by every scanning thread. The environment holds only
  ``CLAM_VIRUSEVENT_FILENAME``, ``CLAM_VIRUSEVENT_VIRUSNAME`` and the bare
  ``PATH`` value without ``PATH=``, so the shell uses its built-in search path.
  clamd switches to ``User`` (primary group only) when started as root.
* ``freshclam/execute.c`` ``execute``: outside daemon mode, a command that
  ``sscanf("EXIT_%d")`` accepts makes freshclam exit with that status instead
  of running anything. Every other command runs through ``system()``
  (``sh -c -- command``), in daemon mode from a forked child (at most five).
* ``freshclam/freshclam.c``: ``OnUpdateExecute`` runs after at least one
  database was updated, and ``OnErrorExecute`` after a failed update.
  ``executeIfNewVersion`` replaces the first ``%v`` with an empty string,
  because its version pointer has already been advanced to the end. In daemon
  mode the outdated-version command is the ``OnUpdateExecute`` text, and nothing
  runs when ``OnUpdateExecute`` is unset. ``DatabaseOwner`` defaults to
  ``clamav``, and freshclam switches to it when started as root.

Configuration not observed, an unknown start account or freshclam daemon mode,
NUL bytes, over-limit input and inputs that crash the parser are explicit
blocking gaps. A result with any of them is never ``complete``. Command-line
options override the file, because they are parsed first and the first value
wins, and they are not observed here. ``origin`` is always ``not_assessed`` and
``authorizes_response`` is always false.
"""
from __future__ import annotations

import re
from typing import Any

CONTRACT_VERSION = 1
REFERENCE = {'clamav': '1.5.4'}
MAX_TEXT = 1048576
MAX_COMMAND = 4096
CHUNK = 1023  # fgets(buffer, MAX_OPTION_LINE_LENGTH=1024, fs)
CLAMAV_USER = 'clamav'
MAX_CHILDREN = 5
FILENAME_DISABLED_MESSAGE = ("The filename format character has been disabled due to security concerns, "
                             "use the 'CLAM_VIRUSEVENT_FILENAME' environment variable instead.")
CLAMD_CONF = '/etc/clamav/clamd.conf'
FRESHCLAM_CONF = '/etc/clamav/freshclam.conf'
REGEX = {
    'b': r'^(yes|true|1|no|false|0)(( +)?#(.*))?$',
    'n': r'^[0-9]+((( +)?#(.*))?)$',
    's': r'^[0-9]+[KMG]?(( +)?#(.*))?$',
}

# Generated from ClamAV 1.5.4 common/optparser.c clam_options[]: option names and long
# command-line names owned by each tool, grouped by value check ('-' none, 'd' deprecated,
# 'b'/'n'/'s' MATCH_BOOL/NUMBER/SIZE, or the option's own regular expression).
CLAMD_OPTIONS = {
    'b': (
        'AlertBrokenExecutables', 'AlertBrokenMedia', 'AlertEncrypted', 'AlertEncryptedArchive',
        'AlertEncryptedDoc', 'AlertExceedsMax', 'AlertOLE2Macros', 'AlertPartitionIntersection',
        'AlertPhishingCloak', 'AlertPhishingSSLMismatch', 'AlgorithmicDetection',
        'AllowAllMatchScan', 'ArchiveBlockEncrypted', 'BlockMax', 'Bytecode',
        'BytecodeUnsigned', 'ConcurrentDatabaseReload', 'CrossFilesystems', 'Debug',
        'DetectPUA', 'DevACOnly', 'DevLiblog', 'DevPerformance', 'DisableCache',
        'DisableCertCheck', 'EnableReloadCommand', 'EnableShutdownCommand',
        'EnableStatsCommand', 'EnableVersionCommand', 'ExitOnOOM', 'ExtendedDetectionInfo',
        'FIPSCryptoHashLimits', 'FixStaleSocket', 'FollowDirectorySymlinks',
        'FollowFileSymlinks', 'ForceToDisk', 'Foreground', 'GenerateMetadataJson',
        'HeuristicAlerts', 'HeuristicScanPrecedence', 'JsonStoreExtraHashes',
        'JsonStoreHTMLURIs', 'JsonStorePDFURIs', 'LeaveTemporaryFiles', 'LogClean',
        'LogFileUnlock', 'LogRotate', 'LogSyslog', 'LogTime', 'LogVerbose', 'OLE2BlockMacros',
        'OfficialDatabaseOnly', 'OnAccessDenyOnError', 'OnAccessDisableDDD',
        'OnAccessExcludeRootUID', 'OnAccessExtraScanning', 'OnAccessPrevention',
        'PartitionIntersection', 'PhishingAlwaysBlockCloak', 'PhishingAlwaysBlockSSLMismatch',
        'PhishingScanURLs', 'PhishingSignatures', 'PreludeEnable', 'ScanArchive', 'ScanELF',
        'ScanHTML', 'ScanHWP3', 'ScanImage', 'ScanImageFuzzyHash', 'ScanMail', 'ScanOLE2',
        'ScanOneNote', 'ScanPDF', 'ScanPE', 'ScanPartialMessages', 'ScanSWF', 'ScanXMLDOCS',
        'StructuredCCOnly', 'StructuredDataDetection', 'StructuredSSNFormatNormal',
        'StructuredSSNFormatStripped', 'alert-broken', 'alert-broken-media', 'alert-encrypted',
        'alert-encrypted-archive', 'alert-encrypted-doc', 'alert-exceeds-max', 'alert-macros',
        'alert-partition-intersection', 'alert-phishing-cloak', 'alert-phishing-ssl',
        'algorithmic-detection', 'allmatch', 'block-encrypted', 'block-macros', 'block-max',
        'bytecode', 'bytecode-unsigned', 'cross-fs', 'daemon', 'debug', 'defaultcolors',
        'detect-pua', 'detect-structured', 'dev-ac-only', 'dev-liblog', 'dev-performance',
        'disable-cache', 'fdpass', 'fips-limits', 'force-to-disk', 'foreground', 'gen-json',
        'help', 'heuristic-alerts', 'heuristic-scan-precedence', 'infected', 'install-service',
        'json-store-extra-hashes', 'json-store-html-uris', 'json-store-pdf-uris', 'kill',
        'log-rotate', 'memory', 'multiscan', 'no-summary', 'nocerts', 'official-db-only',
        'partition-intersection', 'phishing-cloak', 'phishing-scan-urls', 'phishing-sigs',
        'phishing-ssl', 'prelude-enable', 'quiet', 'reload', 'remove', 'scan-archive',
        'scan-elf', 'scan-html', 'scan-hwp3', 'scan-image', 'scan-image-fuzzy-hash',
        'scan-mail', 'scan-ole2', 'scan-onenote', 'scan-pdf', 'scan-pe', 'scan-swf',
        'scan-xmldocs', 'service-mode', 'stdout', 'stream', 'structured-cc-mode',
        'uninstall-service', 'unload', 'verbose', 'version', 'wait',
    ),
    'd': (
        'AllowSupplementaryGroups', 'ArchiveBlockMax', 'ArchiveLimitMemoryUsage',
        'ArchiveMaxCompressionRatio', 'ArchiveMaxFiles', 'ArchiveMaxRecursion',
        'ArchiveMaxScanSize', 'DetectBrokenExecutables', 'MailFollowURLs', 'MailMaxRecursion',
        'ScanOnAccess', 'detect-broken', 'disable-summary', 'mail-follow-urls',
    ),
    '^(Auto|ForceJIT|ForceInterpreter|Test)$': (
        'BytecodeMode', 'bytecode-mode',
    ),
    '^(TrustSigned|Paranoid)$': (
        'BytecodeSecurity',
    ),
    'n': (
        'BytecodeTimeout', 'CacheSize', 'CommandReadTimeout', 'DevACDepth',
        'FailIfCvdOlderThan', 'IdleTimeout', 'MaxConnectionQueueLength',
        'MaxDirectoryRecursion', 'MaxFiles', 'MaxIconsPE', 'MaxPartitions', 'MaxQueue',
        'MaxRecHWP3', 'MaxRecursion', 'MaxScanTime', 'MaxThreads', 'OnAccessCurlTimeout',
        'OnAccessExcludeUID', 'OnAccessMaxThreads', 'OnAccessRetryAttempts', 'PCREMatchLimit',
        'PCRERecMatchLimit', 'ReadTimeout', 'SelfCheck', 'SendBufTimeout', 'StreamMaxPort',
        'StreamMinPort', 'StructuredMinCreditCardCount', 'StructuredMinSSNCount', 'TCPSocket',
        'bytecode-timeout', 'cache-size', 'dev-ac-depth', 'fail-if-cvd-older-than',
        'max-dir-recursion', 'max-files', 'max-iconspe', 'max-partitions', 'max-rechwp3',
        'max-recursion', 'max-scantime', 'pcre-match-limit', 'pcre-recmatch-limit',
        'structured-cc-count', 'structured-ssn-count',
    ),
    '-': (
        'CVDCertsDirectory', 'DatabaseDirectory', 'ExcludePUA', 'ExcludePath', 'IncludePUA',
        'LocalSocket', 'LocalSocketGroup', 'LocalSocketMode', 'LogFacility', 'LogFile',
        'OnAccessExcludePath', 'OnAccessExcludeUname', 'OnAccessIncludePath',
        'OnAccessMountPath', 'PidFile', 'PreludeAnalyzerName', 'TCPAddr', 'TemporaryDirectory',
        'User', 'VirusEvent', 'config-file', 'copy', 'cvdcertsdir', 'datadir', 'exclude-pua',
        'file-list', 'include-pua', 'log', 'move', 'pid', 'ping', 'prelude-analyzer-name',
        'tempdir',
    ),
    's': (
        'LogFileMaxSize', 'MaxEmbeddedPE', 'MaxFileSize', 'MaxHTMLNoTags', 'MaxHTMLNormalize',
        'MaxScanSize', 'MaxScriptNormalize', 'MaxZipTypeRcg', 'OnAccessMaxFileSize',
        'PCREMaxFileSize', 'StreamMaxLength', 'max-embeddedpe', 'max-filesize',
        'max-htmlnormalize', 'max-htmlnotags', 'max-scansize', 'max-scriptnormalize',
        'max-ziptypercg', 'pcre-max-filesize',
    ),
}
FRESHCLAM_OPTIONS = {
    'd': (
        'AllowSupplementaryGroups', 'SafeBrowsing', 'http-proxy', 'log-verbose', 'proxy-user',
    ),
    'b': (
        'Bytecode', 'CompressLocalDatabase', 'Debug', 'FIPSCryptoHashLimits', 'Foreground',
        'LogRotate', 'LogSyslog', 'LogTime', 'LogVerbose', 'ScriptedUpdates', 'TestDatabases',
        'daemon', 'debug', 'fips-limits', 'foreground', 'help', 'install-service',
        'list-mirrors', 'log-rotate', 'no-dns', 'no-warnings', 'quiet', 'service-mode',
        'show-progress', 'stdout', 'uninstall-service', 'verbose', 'version',
    ),
    '-': (
        'CVDCertsDirectory', 'DNSDatabaseInfo', 'DatabaseCustomURL', 'DatabaseDirectory',
        'DatabaseMirror', 'DatabaseOwner', 'ExcludeDatabase', 'ExtraDatabase',
        'HTTPProxyPassword', 'HTTPProxyServer', 'HTTPProxyUsername', 'HTTPUserAgent',
        'LocalIPAddress', 'LogFacility', 'NotifyClamd', 'OnErrorExecute', 'OnOutdatedExecute',
        'OnUpdateExecute', 'PidFile', 'PrivateMirror', 'UpdateLogFile', 'config-file',
        'cvdcertsdir', 'daemon-notify', 'datadir', 'local-address', 'log', 'on-error-execute',
        'on-outdated-execute', 'on-update-execute', 'pid', 'update-db', 'user',
    ),
    'n': (
        'Checks', 'ConnectTimeout', 'HTTPProxyPort', 'MaxAttempts', 'ReceiveTimeout', 'checks',
    ),
    's': (
        'LogFileMaxSize',
    ),
}

ALIASES = {
    'clamd': {'VirusEvent': ('VirusEvent',), 'User': ('User',)},
    'freshclam': {'OnUpdateExecute': ('OnUpdateExecute', 'on-update-execute'),
                  'OnErrorExecute': ('OnErrorExecute', 'on-error-execute'),
                  'OnOutdatedExecute': ('OnOutdatedExecute', 'on-outdated-execute'),
                  'DatabaseOwner': ('DatabaseOwner', 'user'),
                  'daemon': ('daemon',)},
}


def _table(groups: dict[str, tuple[str, ...]]) -> dict[str, str]:
    return {name: kind for kind, names in groups.items() for name in names}


OPTIONS = {'clamd': _table(CLAMD_OPTIONS), 'freshclam': _table(FRESHCLAM_OPTIONS)}


def _chunks(data: bytes) -> list[bytes]:
    """What successive fgets() calls return: up to 1023 bytes, through LF."""
    out, pos = [], 0
    while pos < len(data):
        end = data.find(b'\n', pos, pos + CHUNK)
        stop = end + 1 if end != -1 else min(pos + CHUNK, len(data))
        out.append(data[pos:stop])
        pos = stop
    return out


def _lstrip_keep_last(raw: bytes) -> bytes:
    i = 0
    while i < len(raw) - 1 and raw[i] in b' \t':
        i += 1
    return raw[i:]


def _decode(raw: bytes) -> str:
    return raw.decode('utf-8', 'backslashreplace')


def parse(text: str | bytes, tool: str) -> dict[str, Any]:
    """Port of optparse() over one configuration file for ``tool`` (clamd or freshclam)."""
    if tool not in OPTIONS:
        raise ValueError('tool must be clamd or freshclam')
    data = text.encode('utf-8', 'surrogateescape') if isinstance(text, str) else bytes(text)
    known = OPTIONS[tool]
    values: dict[str, dict[str, Any]] = {}
    ignored: list[dict[str, Any]] = []
    result: dict[str, Any] = {'accepted': True, 'error': None, 'crash': False, 'values': values,
                              'ignored_deprecated': ignored}

    def reject(line: int, reason: str, crash: bool = False) -> dict[str, Any]:
        result.update(accepted=False, error={'line': line, 'reason': reason}, crash=crash)
        return result

    for line, raw in enumerate(_chunks(data), 1):
        buff = _lstrip_keep_last(raw)
        if len(buff) <= 2 or buff[:1] == b'#':
            continue
        if buff.startswith(b'Example'):
            return reject(line, 'example_config')
        cut = re.search(rb'[ \t]', buff)
        if not cut:
            return reject(line, 'missing_argument')
        name, rest = _decode(buff[:cut.start()]), _lstrip_keep_last(buff[cut.start() + 1:])
        arg = rest.rstrip(b' \t\n')
        if not arg:
            return reject(line, 'missing_argument')
        if arg[:1] == b'"':
            close = arg.rfind(b'"', 1)
            if close == -1:
                return reject(line, 'missing_closing_quote')
            arg = arg[1:close]
            if not arg:
                return reject(line, 'empty_argument')
        kind = known.get(name)
        if kind is None:
            return reject(line, 'unknown_option')
        if kind == 'd':
            ignored.append({'name': name, 'line': line})
            continue
        pattern = REGEX.get(kind, None if kind == '-' else kind)
        if pattern and not re.search(pattern, _decode(arg), re.IGNORECASE):
            return reject(line, 'incorrect_argument_format')
        if b'#' in arg:
            token = arg.lstrip(b'#').split(b'#', 1)[0]
            if not token:  # strtok() returns NULL and strlen(NULL) faults
                return reject(line, 'parser_crash', crash=True)
            arg = token.rstrip(b' \t')
        if name not in values:  # single-valued options keep the first occurrence
            values[name] = {'value': _decode(arg), 'line': line}
    return result


def _first(parsed: dict[str, Any], tool: str, option: str) -> dict[str, Any] | None:
    hits = [parsed['values'][n] for n in ALIASES[tool][option] if n in parsed['values']]
    return min(hits, key=lambda h: h['line']) if hits else None


def _exit_status(command: str) -> int | None:
    """sscanf(text, "EXIT_%d"): literal prefix, then optional whitespace and a signed integer."""
    match = re.match(r'EXIT_[ \t\n\v\f\r]*([+-]?[0-9]+)', command)
    if not match:
        return None
    value = int(match.group(1))
    return value if -2**31 <= value < 2**31 else None


def _clamd_account(parsed: dict[str, Any], started_as_root: bool | None) -> dict[str, Any]:
    user = _first(parsed, 'clamd', 'User')
    if started_as_root is None:
        return {'name': None, 'source': 'start_account_unknown'}
    if user and started_as_root:
        return {'name': user['value'], 'source': 'User', 'line': user['line'], 'groups': 'primary_only'}
    return {'name': 'root' if started_as_root else None, 'source': 'start_account'}


def _freshclam_account(parsed: dict[str, Any], started_as_root: bool | None) -> dict[str, Any]:
    owner = _first(parsed, 'freshclam', 'DatabaseOwner')
    if started_as_root is None:
        return {'name': None, 'source': 'start_account_unknown'}
    if not started_as_root:
        return {'name': None, 'source': 'start_account'}
    if owner:
        return {'name': owner['value'], 'source': 'DatabaseOwner', 'line': owner['line']}
    return {'name': CLAMAV_USER, 'source': 'DatabaseOwner_default'}


def _clamd(parsed: dict[str, Any], path: str, started_as_root: bool | None) -> list[dict[str, Any]]:
    event = _first(parsed, 'clamd', 'VirusEvent')
    if not event:
        return []
    template = event['value']
    return [{
        'tool': 'clamd', 'directive': 'VirusEvent', 'file': path, 'line': event['line'],
        'trigger': 'virus_found', 'runs': parsed['accepted'],
        'configured': template[:MAX_COMMAND], 'truncated': len(template) > MAX_COMMAND,
        'argv': ['sh', '-c', template.replace('%f', FILENAME_DISABLED_MESSAGE)[:MAX_COMMAND]],
        'executable': '/bin/sh', 'invocation': 'execle', 'waits': True, 'serialized': True,
        'substitutions': {'%v': 'detected_signature_name_unescaped' if '%v' in template else None,
                          '%f': 'fixed_message' if '%f' in template else None},
        'environment': ['CLAM_VIRUSEVENT_FILENAME', 'CLAM_VIRUSEVENT_VIRUSNAME'],
        'search_path': 'shell_default', 'exit_status_instead': None,
        'account': _clamd_account(parsed, started_as_root),
    }]


def _freshclam(parsed: dict[str, Any], path: str, daemon: bool | None,
               started_as_root: bool | None) -> list[dict[str, Any]]:
    rows = []
    account = _freshclam_account(parsed, started_as_root)
    update, error, outdated = (_first(parsed, 'freshclam', o) for o in
                               ('OnUpdateExecute', 'OnErrorExecute', 'OnOutdatedExecute'))
    runs = [('OnUpdateExecute', update, 'database_updated', update)]
    runs.append(('OnErrorExecute', error, 'update_failed', error))
    if outdated:
        # Daemon mode passes the OnUpdateExecute text as the outdated-version command.
        source = update if daemon else outdated if daemon is False else None
        runs.append(('OnOutdatedExecute', outdated, 'newer_clamav_announced', source))
    for directive, configured, trigger, source in runs:
        if not configured:
            continue
        text = source['value'] if source else None
        row = {'tool': 'freshclam', 'directive': directive, 'file': path, 'line': configured['line'],
               'trigger': trigger, 'runs': parsed['accepted'] and text is not None,
               'configured': configured['value'][:MAX_COMMAND], 'truncated': len(configured['value']) > MAX_COMMAND,
               'command_source': None if source is None else ('OnUpdateExecute' if source is update and directive != 'OnUpdateExecute' else directive),
               'executable': '/bin/sh', 'invocation': 'system', 'waits': daemon is False,
               'substitutions': {}, 'environment': 'inherited', 'search_path': 'inherited',
               'account': account, 'exit_status_instead': None, 'argv': None}
        if daemon is None and directive == 'OnOutdatedExecute':
            row['command_source'] = 'depends_on_daemon_mode'
        if text is not None:
            if directive == 'OnOutdatedExecute' and '%v' in text:
                text = text.replace('%v', '', 1)
                row['substitutions'] = {'%v': 'first_removed'}
            status = _exit_status(text) if daemon is False else None
            if status is not None:
                row.update(exit_status_instead=status, runs=False)
            else:
                row['argv'] = ['sh', '-c', '--', text[:MAX_COMMAND]]
        rows.append(row)
    return rows


def resolve(*, clamd_conf: str | bytes | None = None, freshclam_conf: str | bytes | None = None,
            clamd_path: str = CLAMD_CONF, freshclam_path: str = FRESHCLAM_CONF,
            started_as_root: bool | None = True, freshclam_daemon: bool | None = None) -> dict[str, Any]:
    """Report ClamAV event commands from captured configuration text.

    ``started_as_root`` describes the account the daemons are started from (root under the
    packaged clamav-daemon and clamav-freshclam units). ``freshclam_daemon`` is whether
    freshclam runs with ``-d`` (the packaged unit does); ``None`` means unknown.
    """
    gaps: list[dict[str, Any]] = []
    commands: list[dict[str, Any]] = []
    configs: dict[str, Any] = {}
    if started_as_root is None:
        gaps.append({'kind': 'start_account_unknown'})
    for tool, text, path in (('clamd', clamd_conf, clamd_path), ('freshclam', freshclam_conf, freshclam_path)):
        if text is None:
            gaps.append({'kind': 'not_observed', 'file': path})
            configs[tool] = {'file': path, 'observed': False}
            continue
        data = text.encode('utf-8', 'surrogateescape') if isinstance(text, str) else bytes(text)
        if len(data) > MAX_TEXT:
            gaps.append({'kind': 'over_limit', 'file': path})
            configs[tool] = {'file': path, 'observed': True, 'evaluated': False}
            continue
        if b'\0' in data:
            gaps.append({'kind': 'nul_byte', 'file': path})
            configs[tool] = {'file': path, 'observed': True, 'evaluated': False}
            continue
        parsed = parse(data, tool)
        if parsed['crash']:
            gaps.append({'kind': 'parser_crash', 'file': path, 'line': parsed['error']['line']})
        if tool == 'freshclam' and 'daemon' in parsed['values']:
            gaps.append({'kind': 'daemon_option_in_file', 'file': path, 'line': parsed['values']['daemon']['line']})
        configs[tool] = {'file': path, 'observed': True, 'evaluated': True, 'accepted': parsed['accepted'],
                         'error': parsed['error'], 'ignored_deprecated': parsed['ignored_deprecated']}
        if tool == 'clamd':
            commands += _clamd(parsed, path, started_as_root)
        else:
            rows = _freshclam(parsed, path, freshclam_daemon, started_as_root)
            if freshclam_daemon is None and rows:
                gaps.append({'kind': 'daemon_mode_unknown', 'file': path})
            commands += rows
    return {
        'contract_version': CONTRACT_VERSION, 'reference': REFERENCE,
        'commands': commands, 'configs': configs, 'gaps': gaps, 'complete': not gaps,
        'limitations': ['command_line_options_not_observed', 'start_time_validation_beyond_parser_not_modelled',
                        'account_not_resolved'],
        'origin': 'not_assessed', 'authorizes_response': False,
    }
