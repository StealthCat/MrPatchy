"""Pure logrotate contract (roadmap F slice, #980).

Takes captured, read-only observations of ``/etc/logrotate.conf`` and of the
files and directories it includes, and returns what logrotate would run:

- ``scripts``: ``prerotate``, ``postrotate``, ``firstaction``, ``lastaction``
  and ``preremove`` blocks. logrotate passes each to ``sh -c``, normally as root
  from a daily timer or cron job. Each carries its text, the log patterns of
  its section, the effective ``sharedscripts`` state, file and line. A script
  outside a section is listed with scope ``global``: logrotate uses it as the
  default of later sections.
- ``directives``: ``compresscmd`` and ``uncompresscmd`` (another program is
  run), ``su`` (rotation runs as another user or group) and ``shred`` (the
  ``shred`` program is run), in global or section scope.

File order and syntax follow logrotate 3.21.0 and were compared with that
binary:

- ``include`` names a file or a directory. Directory entries are read in byte
  order, hidden names included. A name matching a taboo pattern, an empty
  file, a non-regular entry and a dangling link are not read.
- A word starting with a letter is a directive and must be followed by a
  blank or ``=``; one ``=`` may separate a directive from its value
  (``include=/path``). A top-level line starting with ``/`` or a quote starts
  a log section: patterns up to ``{``, then directives up to ``}``. logrotate
  rejects any other line start.
- A name matching a taboo pattern is ignored, but ``*`` never covers a leading
  period, so hidden names such as ``.cache~`` are read.
- A script starts directly after its keyword, on the same line, and ends before
  the first later line whose first word is ``endscript``. A word is a run of
  letters, so ``endscript;`` and ``endscript}`` end the script too. Parsing
  continues after that word on the same line.
- ``#`` starts a comment only where a directive could start.

It performs no I/O, runs nothing and never authorizes a response action.
Fail-closed rules:

- Everything logrotate could read is parsed, and a problem makes the result
  ``undetermined`` instead of hiding later content. An unknown directive, a
  script outside a section (still listed) or without ``endscript``, an
  ``include`` inside a
  section (its target is still parsed), a keyword not followed by a blank or
  ``=``, an ``endscript`` followed by anything but a blank or a line end, a
  top-level line that starts with neither a keyword nor a file name, a
  brace inside a directive value, a carriage return, vertical tab or form feed
  (logrotate does not skip them as blanks), an unterminated section or quote, a script
  body with a line that starts with a script keyword, a NUL byte, an uncollected,
  unreadable or oversized file, an include that is relative, uses ``~``, loops
  or nests too deeply, and over-cap input are gaps.
- After a ``tabooext`` or ``taboopat`` directive no name is treated as taboo,
  and a gap is recorded: the changed list is not evaluated, so files logrotate
  might skip are still parsed.
- After a script without ``endscript`` the rest of the file is parsed as
  directives, because logrotate skips only that section and reads on.
- The listed scripts are an upper bound. logrotate skips a section on a bad
  value or a duplicate log file, stops reading a file on a bad top-level
  value, and runs a script only when a matching log is rotated. Values of other
  directives, which logs exist and logrotate's state file are not evaluated,
  and that is always disclosed. The result is never a safety verdict.
"""
from __future__ import annotations

import fnmatch
import re
from typing import Any

CONTRACT_VERSION = 1
MAIN_FILE = '/etc/logrotate.conf'
MAX_FILES = 512
MAX_FILE_BYTES = 256 * 1024
MAX_TOTAL_BYTES = 4 * 1024 * 1024
MAX_INCLUDE_DEPTH = 8
MAX_NAME = 255
MAX_PATH = 4096
MAX_ENTRIES = 1024
MAX_SCRIPT_CHARS = 64 * 1024
MAX_PATTERNS = 64
MAX_GAPS = 256
NOT_A_VERDICT = ('This lists the scripts and programs logrotate configuration can run. '
                 'It is not a safety verdict and authorizes no response action.')

SCRIPT_KEYS = ('prerotate', 'postrotate', 'firstaction', 'lastaction', 'preremove')
REPORTED_VALUE_KEYS = ('compresscmd', 'uncompresscmd', 'su')
# Directives after which logrotate keeps parsing the same line.
FLAG_KEYS = frozenset((
    'compress', 'nocompress', 'copy', 'nocopy', 'copytruncate', 'nocopytruncate', 'nocreate', 'nocreateolddir',
    'daily', 'monthly', 'yearly', 'hourly', 'dateext', 'nodateext', 'dateyesterday', 'datehourago',
    'delaycompress', 'nodelaycompress', 'ifempty', 'notifempty', 'missingok', 'nomissingok', 'mailfirst',
    'maillast', 'nomail', 'noolddir', 'sharedscripts', 'nosharedscripts', 'shred', 'noshred', 'renamecopy',
    'norenamecopy', 'allowhardlink', 'noallowhardlink', 'ignoreduplicates'))
# Directives whose value is the rest of the line.
VALUE_KEYS = frozenset((
    *REPORTED_VALUE_KEYS, 'compressext', 'compressoptions', 'create', 'createolddir', 'dateformat', 'extension',
    'addextension', 'include', 'mail', 'maxage', 'minage', 'maxsize', 'minsize', 'size', 'olddir', 'rotate',
    'start', 'tabooext', 'taboopat', 'shredcycles', 'weekly'))
# logrotate 3.21.0's built-in taboo list, as glob patterns over the entry name.
DEFAULT_TABOO = ('*.bak', '*.cfsaved', '*.disabled', '*.dpkg-bak', '*.dpkg-del', '*.dpkg-dist', '*.dpkg-new',
                 '*.dpkg-old', '*.dpkg-tmp', '*.rhn-cfg-tmp-*', '*.rpmnew', '*.rpmorig', '*.rpmsave', '*.swp',
                 '*.ucf-dist', '*.ucf-new', '*.ucf-old', '*,v', '*~')

_SPACE = ' \t\n\v\f\r'
_KEY = re.compile(r'[A-Za-z]+')
_NESTED_SCRIPT = re.compile(r'\n[ \t\v\f\r]*(?:' + '|'.join(SCRIPT_KEYS) + r')(?![A-Za-z])')
_OTHER_SPACE = re.compile(r'[\r\v\f]')
# logrotate takes the letters at the start of a line as its first word, so any non-letter ends it.
_ENDSCRIPT = re.compile(r'^[ \t\v\f\r]*endscript(?![A-Za-z])', re.MULTILINE)


def _gap(code: str, detail: str, **extra: Any) -> dict[str, Any]:
    return {'code': code, 'detail': detail, **extra}


def taboo(name: str) -> str | None:
    """Return the built-in taboo pattern that makes logrotate ignore ``name``, if any.

    logrotate matches with ``FNM_PERIOD``: a leading period is never covered by
    ``*``, so a hidden name such as ``.cache~`` or ``.x.bak`` is read.
    """
    if name.startswith('.'):
        return None
    return next((pattern for pattern in DEFAULT_TABOO if fnmatch.fnmatchcase(name, pattern)), None)


def split_patterns(text: str) -> list[str] | None:
    """Split a section header into log patterns; ``None`` when a quote is not closed."""
    out: list[str] = []
    pos = 0
    while pos < len(text):
        if text[pos] in _SPACE:
            pos += 1
            continue
        if text[pos] in '"\'':
            end = text.find(text[pos], pos + 1)
            if end < 0:
                return None
            out.append(text[pos + 1:end])
            pos = end + 1
            continue
        end = pos
        while end < len(text) and text[end] not in _SPACE:
            end += 1
        out.append(text[pos:end])
        pos = end
    return out


def resolve(main: Any, includes: Any = None) -> dict[str, Any]:
    """Resolve logrotate scripts and command directives from captured observations.

    ``main`` describes ``/etc/logrotate.conf`` as ``{'present': bool,
    'content': text|None}``; ``None`` means it was not collected. ``includes``
    maps each absolute ``include`` target to ``{'type': 'file', 'content':
    text|None}``, ``{'type': 'missing'}`` or ``{'type': 'dir', 'entries':
    [...]}``, where each entry has ``name``, ``type`` (``file`` for a regular
    file or a link to one, ``missing`` for a dangling link, otherwise anything
    else) and ``content``. A target absent from the mapping was not collected.
    """
    gaps: list[dict[str, Any]] = [
        _gap('invocation_unobserved',
             'Configuration files, options and the state file of a particular logrotate run are not observed.'),
        _gap('rotation_not_evaluated',
             'Which logs exist and are due, other directive values and duplicate log entries are not evaluated; '
             'a listed script may not run.'),
    ]
    state = {'undetermined': False, 'total': 0, 'files': 0, 'entries': 0, 'over_cap': False, 'taboo': True,
             'shared': False}
    files: list[dict[str, Any]] = []
    scripts: list[dict[str, Any]] = []
    directives: list[dict[str, Any]] = []

    def add_gap(code: str, detail: str, **extra: Any) -> None:
        state['undetermined'] = True
        if len(gaps) < MAX_GAPS:
            gaps.append(_gap(code, detail, **extra))
        elif gaps[-1]['code'] != 'gap_limit':
            gaps.append(_gap('gap_limit', 'Further coverage gaps were omitted.'))

    def record(target: list[dict[str, Any]], item: dict[str, Any]) -> None:
        if state['entries'] >= MAX_ENTRIES:
            state['over_cap'] = True
            return
        state['entries'] += 1
        target.append(item)

    def parse(path: str, text: str, stack: tuple[str, ...]) -> str:
        """Parse one file; returns its state."""
        outcome = 'parsed'
        pos = 0
        section: dict[str, Any] | None = None

        def problem(code: str, detail: str, at: int, **extra: Any) -> None:
            nonlocal outcome
            outcome = 'gaps'
            add_gap(code, detail, path=path, line=text.count('\n', 0, at) + 1, **extra)

        def rest_of_line() -> str:
            nonlocal pos
            end = text.find('\n', pos)
            end = len(text) if end < 0 else end
            value = text[pos:end].strip(_SPACE)
            pos = end
            return value

        def value_of_line(at: int) -> str:
            """The value of a directive; logrotate accepts one ``=`` before it."""
            nonlocal pos
            while pos < len(text) and text[pos] in ' \t':
                pos += 1
            if pos < len(text) and text[pos] == '=':
                pos += 1
            value = rest_of_line()
            if '{' in value or '}' in value:
                problem('brace_in_value', 'A brace on a directive line belongs to its value; logrotate does not '
                        'open or close a section there and may reject the value.', at)
            return value

        if '\x00' in text:
            problem('nul_byte', 'The file contains a NUL byte; logrotate stops reading there.', text.index('\x00'))
        other_space = _OTHER_SPACE.search(text)
        if other_space is not None:
            problem('control_whitespace', 'The file contains a carriage return, vertical tab or form feed; '
                    'logrotate does not skip them as blanks and may reject those lines.', other_space.start())
        while pos < len(text):
            char = text[pos]
            if char in _SPACE:
                pos += 1
                continue
            if char == '#':
                rest_of_line()
                continue
            start = pos
            if char == '}':
                pos += 1
                if section is None:
                    problem('unexpected_brace', 'A closing brace appears outside a log section.', start)
                section = None
                continue
            if char == '{':
                pos += 1
                problem('unexpected_brace', 'An opening brace appears without log patterns or inside a section.',
                        start)
                continue
            match = _KEY.match(text, pos)
            if match is not None and match.end() < len(text) and text[match.end()] not in _SPACE + '=':
                # logrotate 3.21.0 rejects the keyword and drops the section or the rest of the file.
                # The line is skipped and later content is still parsed, so nothing is hidden.
                rest_of_line()
                problem('keyword_not_separated', 'A word that starts with a letter is not followed by a blank '
                        'or "="; logrotate rejects it and skips the section or the rest of the file.', start)
                continue
            if match is None:
                if section is not None:
                    rest_of_line()
                    problem('unknown_directive', 'logrotate ignores or rejects this line.', start)
                    continue
                if char not in '/"\'':
                    # Only "/", a quote or a letter can start a top-level line; logrotate skips the line.
                    rest_of_line()
                    problem('unexpected_line_start', 'A top-level line starts with neither a keyword nor a log '
                            'file name; logrotate rejects and skips it.', start)
                    continue
                brace = text.find('{', pos)
                if brace < 0:
                    pos = len(text)
                    problem('unterminated_section', 'Log patterns are not followed by an opening brace.', start)
                    continue
                patterns = split_patterns(text[pos:brace])
                pos = brace + 1
                if patterns is None:
                    patterns = []
                    problem('unbalanced_quote', 'A quoted log pattern is not closed.', start)
                if len(patterns) > MAX_PATTERNS:
                    patterns = patterns[:MAX_PATTERNS]
                    problem('pattern_limit', f'Only the first {MAX_PATTERNS} log patterns are listed.', start)
                section = {'patterns': patterns, 'shared': state['shared'], 'scripts': [], 'kinds': set()}
                continue
            key = match.group()
            pos = match.end()
            if key in SCRIPT_KEYS:
                end = _ENDSCRIPT.search(text, text.find('\n', pos) + 1 if '\n' in text[pos:] else len(text))
                if end is None:
                    # logrotate skips the section and reads on, so the rest is parsed as directives.
                    problem('script_without_endscript', 'logrotate rejects a script that has no endscript line.',
                            start, kind=key)
                    continue
                body = text[pos:end.start()]
                pos = end.end()
                if pos < len(text) and text[pos] not in _SPACE:
                    # logrotate 3.21.0 still ends the script here; what follows on the line is parsed.
                    problem('endscript_not_separated', 'endscript is followed by a character that is neither a '
                            'blank nor a line end; logrotate ends the script there.', pos, kind=key)
                item = {'kind': key, 'script': body[:MAX_SCRIPT_CHARS], 'truncated': len(body) > MAX_SCRIPT_CHARS,
                        'empty': not body.strip(_SPACE), 'scope': 'global' if section is None else 'section',
                        'patterns': None if section is None else section['patterns'],
                        'sharedscripts': state['shared'] if section is None else section['shared'],
                        'path': path, 'line': text.count('\n', 0, start) + 1}
                if _NESTED_SCRIPT.search(body):
                    problem('script_contains_script_keyword', 'A script body contains a line starting with a '
                            'script keyword; an endscript is probably missing and the text may not run as listed.',
                            start, kind=key)
                if section is None:
                    # logrotate 3.21.0 keeps it as the default script of later sections.
                    problem('script_outside_section', 'A script outside a log section becomes the default of '
                            'later sections; which sections keep it is not evaluated.', start, kind=key)
                else:
                    if key in section['kinds']:
                        problem('duplicate_script', 'A section defines this script more than once.', start,
                                kind=key)
                    section['kinds'].add(key)
                    section['scripts'].append(item)
                record(scripts, item)
                continue
            if key == 'endscript':
                problem('unexpected_endscript', 'endscript appears without a script.', start)
                continue
            if key in FLAG_KEYS:
                if key in ('sharedscripts', 'nosharedscripts'):
                    value = key == 'sharedscripts'
                    if section is None:
                        state['shared'] = value
                    else:
                        section['shared'] = value
                        for item in section['scripts']:
                            item['sharedscripts'] = value
                elif key == 'shred':
                    record(directives, {'directive': key, 'value': None,
                                        'scope': 'global' if section is None else 'section',
                                        'patterns': None if section is None else section['patterns'],
                                        'path': path, 'line': text.count('\n', 0, start) + 1})
                continue
            if key not in VALUE_KEYS:
                rest_of_line()
                problem('unknown_directive', 'logrotate ignores or rejects this line.', start)
                continue
            value = value_of_line(start)
            if key in REPORTED_VALUE_KEYS:
                record(directives, {'directive': key, 'value': value[:MAX_PATH],
                                    'scope': 'global' if section is None else 'section',
                                    'patterns': None if section is None else section['patterns'],
                                    'path': path, 'line': text.count('\n', 0, start) + 1})
            elif key in ('tabooext', 'taboopat'):
                state['taboo'] = False
                problem('taboo_changed', 'The taboo list was changed and is not evaluated; '
                        'every later directory entry is parsed.', start)
            elif key == 'include':
                if section is not None:
                    # logrotate 3.21.0 still reads the target, so it is parsed too.
                    problem('include_in_section', 'An include inside a log section is not interpreted reliably.',
                            start)
                include(value, stack, lambda code, detail, at=start, **extra: problem(code, detail, at, **extra))
        if section is not None:
            problem('unterminated_section', 'The last log section has no closing brace.', len(text.rstrip('\n')))
        return outcome

    def load(path: str, entry: Any, stack: tuple[str, ...]) -> None:
        content = entry.get('content') if isinstance(entry, dict) else None
        reason = None
        if path in stack:
            reason = 'include_loop'
        elif len(stack) >= MAX_INCLUDE_DEPTH:
            reason = 'include_too_deep'
        elif state['files'] >= MAX_FILES:
            reason = 'file_limit'
        elif not isinstance(content, str):
            reason = 'unreadable'
        elif len(content.encode('utf-8', 'surrogatepass')) > MAX_FILE_BYTES:
            reason = 'too_large'
        elif state['total'] + len(content) > MAX_TOTAL_BYTES:
            reason = 'total_limit'
        if reason is not None:
            files.append({'path': path, 'state': reason})
            add_gap('file_' + reason if not reason.startswith(('include_', 'file_')) else reason,
                    'logrotate reads this file, but the contract did not evaluate it.', path=path)
            return
        state['files'] += 1
        state['total'] += len(content)
        slot = {'path': path, 'state': 'parsing'}
        files.append(slot)
        slot['state'] = parse(path, content, (*stack, path))

    def include(target: str, stack: tuple[str, ...], problem: Any) -> None:
        if (not target.startswith('/') or len(target) > MAX_PATH
                or any(ord(c) < 32 or ord(c) == 127 for c in target)):
            problem('include_not_resolved', 'A relative, ~ or malformed include target is not resolved.')
            return
        target = target.rstrip('/') or '/'
        observed = includes.get(target) if isinstance(includes, dict) else None
        kind = observed.get('type') if isinstance(observed, dict) else None
        if kind == 'missing':
            files.append({'path': target, 'state': 'ignored', 'reason': 'missing'})
            return
        if kind == 'file':
            load(target, observed, stack)
            return
        entries = observed.get('entries') if kind == 'dir' else None
        if not isinstance(entries, list):
            problem('include_not_collected', 'An include target was not collected or is malformed.',
                    target=target)
            return
        candidates = []
        for entry in entries[:MAX_FILES]:
            name = entry.get('name') if isinstance(entry, dict) else None
            if (not isinstance(name, str) or not name or len(name) > MAX_NAME or '/' in name
                    or name in ('.', '..') or any(ord(c) < 32 or ord(c) == 127 for c in name)):
                problem('invalid_entry', 'A directory entry with an invalid name was not evaluated.', target=target)
                continue
            candidates.append((name.encode('utf-8', 'surrogatepass'), name, entry))
        if len(entries) > MAX_FILES:
            problem('file_limit', f'Only the first {MAX_FILES} directory entries were evaluated.', target=target)
        for _, name, entry in sorted(candidates, key=lambda item: item[0]):
            path = f'{target}/{name}'
            pattern = taboo(name) if state['taboo'] else None
            if pattern is not None:
                files.append({'path': path, 'state': 'ignored', 'reason': 'taboo', 'pattern': pattern})
            elif entry.get('type') == 'missing':
                files.append({'path': path, 'state': 'ignored', 'reason': 'dangling_link'})
            elif entry.get('type') != 'file':
                files.append({'path': path, 'state': 'ignored', 'reason': 'not_regular_file'})
            elif entry.get('content') == '':
                files.append({'path': path, 'state': 'ignored', 'reason': 'empty'})
            else:
                load(path, entry, stack)

    if main is None:
        add_gap('main_not_collected', f'{MAIN_FILE} was not collected.')
    elif not isinstance(main, dict) or not isinstance(main.get('present'), bool):
        add_gap('invalid_observation', f'The {MAIN_FILE} observation is malformed.')
    elif main['present']:
        load(MAIN_FILE, main, ())
    if state['over_cap']:
        add_gap('entry_limit', f'Only the first {MAX_ENTRIES} scripts and directives are listed.')
    for item in scripts:
        item['patterns'] = None if item['patterns'] is None else list(item['patterns'])
    return {
        'contract_version': CONTRACT_VERSION,
        # The two always-present disclosure gaps do not make the configuration reading undetermined.
        'logrotate_reading': 'undetermined' if state['undetermined'] else 'determined',
        'files': files,
        'scripts': scripts,
        'directives': directives,
        'gaps': gaps,
        'not_a_verdict': NOT_A_VERDICT,
    }
