"""Pure mdadm.conf alert-program contract (roadmap F slice, #1213).

Takes observations of the mdadm configuration paths and says which
``PROGRAM`` command ``mdadm --monitor --scan`` executes as root on RAID
events, which configuration file it came from, and where coverage is missing.
It never runs anything and never reads the program itself.

Semantics come from mdadm 4.3 source (``config.c``, ``lib.c`` and
``Monitor.c`` at tag ``mdadm-4.3``) and the Ubuntu 24.04 package
``mdadm_4.3-1ubuntu2.1`` (unit files, embedded default paths and its
changelog, which drops Debian's ``conffile-location.patch``), not from
recollection:

* ``load_conffile`` opens ``/etc/mdadm.conf``. Only when that open fails does
  it open ``/etc/mdadm/mdadm.conf`` and switch the drop-in directory from
  ``/etc/mdadm.conf.d`` to ``/etc/mdadm/mdadm.conf.d``. A planted
  ``/etc/mdadm.conf`` therefore hides Debian's ``/etc/mdadm/mdadm.conf``
  entirely. The drop-in directory is read after the main file, even when
  neither main file exists.
* A configuration path that is a directory is read like the drop-in
  directory: names not starting with ``.``, at least six bytes long and
  ending in ``.conf``, in ``strcmp`` byte order. Entries that cannot be opened
  are skipped silently.
* ``conf_word``/``conf_line`` split words on spaces and tabs, honor single
  and double quotes (removed, may be mixed inside one word), drop ``#``
  comments that start a word, and continue a logical line while the next
  physical line starts with a space or tab. Comment-only and blank lines do
  not end a logical line.
* ``match_keyword`` accepts any case-insensitive prefix of at least three
  characters of a keyword, first match in mdadm's keyword order.
* ``programline`` keeps the first ``PROGRAM`` word ever seen, across all
  lines and files; later words and lines are ignored. ``MAILADDR`` likewise
  keeps the first word.
* ``Monitor`` with ``--scan`` and no ``--syslog`` exits unless a program or
  mail address is configured. Otherwise, on every event it forks and
  ``execl``s the program (no shell, no ``PATH`` search) as root with
  ``EVENT MD_DEVICE [COMPONENT_DEVICE]``.
* ``mdmonitor.service`` runs ``/sbin/mdadm --monitor --scan`` as root, and
  the daily ``mdmonitor-oneshot.timer`` runs ``--monitor --oneshot --scan``
  when ``AUTOSCAN=true`` in ``/etc/default/mdadm``.

It performs no I/O and never authorizes a response action. Unobserved or
unreadable paths, malformed input and over-limit input are blocking gaps.
"""
from __future__ import annotations

from typing import Any

CONTRACT_VERSION = 1
REFERENCE = {
    'package': 'mdadm',
    'version': '4.3-1ubuntu2.1 (Ubuntu 24.04)',
    'source': 'config.c, lib.c and Monitor.c at tag mdadm-4.3',
}
RUNS_AS = 'root'
CONF_FILE = '/etc/mdadm.conf'
CONF_DIR = '/etc/mdadm.conf.d'
ALT_CONF_FILE = '/etc/mdadm/mdadm.conf'
ALT_CONF_DIR = '/etc/mdadm/mdadm.conf.d'
PATHS = (CONF_FILE, CONF_DIR, ALT_CONF_FILE, ALT_CONF_DIR)
STATES = ('file', 'directory', 'absent', 'unreadable', 'other')
KEYWORDS = ('devices', 'array', 'mailaddr', 'mailfrom', 'program', 'create', 'homehost', 'homecluster',
            'auto', 'policy', 'part-policy', 'sysfs', 'monitordelay')
EVENTS = ('Fail', 'FailSpare', 'SpareActive', 'DegradedArray', 'SparesMissing', 'NewArray', 'MoveSpare',
          'RebuildStarted', 'RebuildNN', 'RebuildFinished', 'DeviceDisappeared', 'TestMessage')
ARGV = ('PROGRAM', 'EVENT', 'MD_DEVICE', '[COMPONENT_DEVICE]')
SERVICES = (
    {'unit': 'mdmonitor.service', 'command': '/sbin/mdadm --monitor --scan', 'when': 'while the service runs'},
    {'unit': 'mdmonitor-oneshot.timer', 'command': '/sbin/mdadm --monitor --oneshot --scan',
     'when': 'daily, only when AUTOSCAN=true in /etc/default/mdadm'},
)
MAX_BYTES = 262144
MAX_DIR_ENTRIES = 512
MAX_GAPS = 64
BLOCKING = frozenset({
    'input_malformed', 'path_not_observed', 'path_unreadable', 'path_other_type', 'entry_unreadable',
    'too_large', 'too_many_entries', 'gaps_truncated',
})
UNOBSERVED = (
    'Whether mdadm is installed, which arrays exist and whether mdmonitor.service or the oneshot timer is '
    'enabled are not observed.',
    'A --program/--alert, --mail or --config option given on a modified service command line is not observed; '
    'it would replace the configured value.',
    'The contents, owner and permissions of the program are not read.',
    'MAILADDR alerts run the system sendmail; that mailer is not evaluated here.',
)
NOT_A_VERDICT = 'Configuration text only. This is not a safety verdict and origin is not assessed.'


def _gap(gaps: list[dict[str, Any]], code: str, detail: str, path: str | None = None) -> None:
    if len(gaps) >= MAX_GAPS:
        if gaps[-1]['code'] != 'gaps_truncated':
            gaps[-1] = {'code': 'gaps_truncated', 'detail': f'Only the first {MAX_GAPS - 1} gaps are listed.'}
        return
    gap: dict[str, Any] = {'code': code, 'detail': detail}
    if path is not None:
        gap['path'] = path
    gaps.append(gap)


class _Stream:
    """getc/ungetc over text, as conf_word uses a FILE*."""

    def __init__(self, text: str) -> None:
        self.text = text
        self.pos = 0
        self.line = 1
        self.pushed: list[str] = []
        self.word_line = 0

    def getc(self) -> str:
        if self.pushed:
            return self.pushed.pop()
        if self.pos >= len(self.text):
            return ''
        c = self.text[self.pos]
        self.pos += 1
        if c == '\n':
            self.line += 1
        return c

    def ungetc(self, c: str) -> None:
        if c:
            self.pushed.append(c)


def _conf_word(f: _Stream, allow_key: bool) -> str | None:
    """Port of lib.c conf_word, including its mdstat compatibility hacks."""
    word: list[str] = []
    found = False
    while not found:
        c = f.getc()
        if c == '#':
            while c not in ('', '\n'):
                c = f.getc()
        if c == '':
            break
        if c == '\n':
            continue
        if c not in (' ', '\t') and not allow_key:
            f.ungetc(c)
            break
        quote = ''
        while c in (' ', '\t'):
            c = f.getc()
        if c not in ('', '\n', '#'):
            while c not in ('', '\n') and (quote or c not in (' ', '\t')):
                if not found:
                    f.word_line = f.line
                found = True
                if quote and c == quote:
                    quote = ''
                elif not quote and c in ('"', "'"):
                    quote = c
                else:
                    word.append(c)
                c = f.getc()
                if c == '(' and len(word) >= 6 and ''.join(word[-6:]) == 'active':
                    c = ' '
        f.ungetc(c)
    text = ''.join(word).split('\0', 1)[0]
    if text == 'auto-read-only)':
        text = '(auto-read-only)'
    return text if found else None


def _conf_lines(text: str) -> list[tuple[int, list[str]]]:
    """Port of lib.c conf_line: logical lines as (first physical line, words)."""
    f = _Stream(text)
    lines: list[tuple[int, list[str]]] = []
    while True:
        first = _conf_word(f, True)
        if first is None:
            return lines
        start = f.word_line
        words = [first]
        while (w := _conf_word(f, False)) is not None:
            words.append(w)
        lines.append((start, words))


def match_keyword(word: str) -> str | None:
    """config.c match_keyword: ASCII case-insensitive prefix of at least three characters."""
    if len(word) < 3:
        return None
    lowered = word.translate(_ASCII_LOWER)
    for keyword in KEYWORDS:
        if keyword.startswith(lowered):
            return keyword
    return None


_ASCII_LOWER = str.maketrans('ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz')


def _directory_files(path: str, entries: Any, gaps: list[dict[str, Any]]) -> list[tuple[str, Any]]:
    if not isinstance(entries, dict):
        _gap(gaps, 'input_malformed', 'A directory observation needs an entries mapping.', path)
        return []
    if len(entries) > MAX_DIR_ENTRIES:
        _gap(gaps, 'too_many_entries', f'More than {MAX_DIR_ENTRIES} entries; none were evaluated.', path)
        return []
    chosen = []
    for name in entries:
        if not isinstance(name, str) or not name or '/' in name:
            _gap(gaps, 'input_malformed', 'Directory entry names must be non-empty strings without "/".', path)
            continue
        raw = name.encode('utf-8', 'surrogateescape')
        if name.startswith('.') or len(raw) < 6 or not raw.endswith(b'.conf'):
            continue
        chosen.append((raw, name))
    chosen.sort()
    return [(f'{path}/{name}', entries[name]) for _, name in chosen]


def _read(path: str, obs: Any, gaps: list[dict[str, Any]], *, top: bool) -> list[tuple[str, str]]:
    """Return (path, text) pairs in the order mdadm parses them."""
    if not isinstance(obs, dict) or obs.get('state') not in STATES:
        _gap(gaps, 'input_malformed', f'State must be one of {", ".join(STATES)}.', path)
        return []
    state = obs['state']
    if state == 'absent':
        return []
    if state == 'unreadable':
        _gap(gaps, 'path_unreadable' if top else 'entry_unreadable',
             'mdadm (as root) may read this path, but its content was not observed.', path)
        return []
    if state == 'other':
        _gap(gaps, 'path_other_type', 'Not a regular file or directory; mdadm reads nothing from it, '
             'but opening a FIFO or device can block or read unexpected data.', path)
        return []
    if state == 'directory':
        if not top:
            return []  # conf_file on a directory reads nothing (EISDIR).
        found: list[tuple[str, str]] = []
        for child, child_obs in _directory_files(path, obs.get('entries'), gaps):
            found.extend(_read(child, child_obs, gaps, top=False))
        return found
    text = obs.get('text')
    if not isinstance(text, str):
        _gap(gaps, 'input_malformed', 'A file observation needs its text.', path)
        return []
    if len(text.encode('utf-8', 'surrogateescape')) > MAX_BYTES:
        _gap(gaps, 'too_large', f'Larger than {MAX_BYTES} bytes; not evaluated.', path)
        return []
    return [(path, text)]


def resolve_files(paths: Any, gaps: list[dict[str, Any]]) -> tuple[list[tuple[str, str]], dict[str, str]]:
    """Mirror load_conffile with no --config option."""
    used = {'file': CONF_FILE, 'directory': CONF_DIR}
    if not isinstance(paths, dict):
        _gap(gaps, 'input_malformed', 'Path observations must be a mapping of path to observation.')
        return [], used
    if CONF_FILE not in paths:
        _gap(gaps, 'path_not_observed', 'mdadm opens this path first; it was not observed.', CONF_FILE)
        return [], used
    main = paths[CONF_FILE]
    if isinstance(main, dict) and main.get('state') == 'absent':
        if ALT_CONF_FILE not in paths:
            _gap(gaps, 'path_not_observed', 'mdadm opens this path when /etc/mdadm.conf is absent; it was '
                 'not observed.', ALT_CONF_FILE)
            return [], used
        alt = paths[ALT_CONF_FILE]
        if not (isinstance(alt, dict) and alt.get('state') == 'absent'):
            used = {'file': ALT_CONF_FILE, 'directory': ALT_CONF_DIR}
    files = _read(used['file'], paths.get(used['file']), gaps, top=True)
    if used['directory'] not in paths:
        _gap(gaps, 'path_not_observed', 'mdadm reads this drop-in directory; it was not observed.',
             used['directory'])
        return files, used
    files.extend(_read(used['directory'], paths[used['directory']], gaps, top=True))
    return files, used


def assess(paths: Any = None) -> dict[str, Any]:
    """Resolve the alert program ``mdadm --monitor --scan`` runs as root.

    ``paths`` maps each of :data:`PATHS` to ``{'state': ..., 'text': ...}`` for a
    file or ``{'state': 'directory', 'entries': {name: observation}}``.
    """
    gaps: list[dict[str, Any]] = []
    files, used = resolve_files(paths, gaps)
    program: dict[str, Any] | None = None
    mailaddr: dict[str, Any] | None = None
    ignored: list[dict[str, Any]] = []
    unknown: list[dict[str, Any]] = []
    for path, text in files:
        for line, words in _conf_lines(text):
            keyword = match_keyword(words[0])
            if keyword is None:
                if len(unknown) < MAX_GAPS:
                    unknown.append({'path': path, 'line': line, 'word': words[0][:128]})
                continue
            if keyword not in ('program', 'mailaddr'):
                continue
            for index, word in enumerate(words[1:]):
                where = {'path': path, 'line': line, 'keyword': words[0], 'value': word}
                if keyword == 'program' and program is None:
                    program = where
                elif keyword == 'mailaddr' and mailaddr is None:
                    mailaddr = where
                elif keyword == 'program' and len(ignored) < MAX_GAPS:
                    ignored.append({**where, 'reason': 'mdadm keeps only the first PROGRAM word.'})
    blocking = sorted({gap['code'] for gap in gaps if gap['code'] in BLOCKING})
    monitors = program is not None or mailaddr is not None
    command = None
    if program is not None:
        value = program['value']
        command = {
            'program': value,
            'argv': [value, *ARGV[1:]],
            'runs_as': RUNS_AS,
            'shell': False,
            'path_search': False,
            'absolute': value.startswith('/'),
            'executable_name_empty': value == '',
            'events': list(EVENTS),
            'source': {k: program[k] for k in ('path', 'line', 'keyword')},
            'note': ('execl of an empty name fails, so nothing runs.' if value == '' else
                     'A relative name resolves against the service working directory (/).'
                     if not value.startswith('/') else 'Executed directly with execl.'),
        }
    return {
        'contract_version': CONTRACT_VERSION,
        'reference': dict(REFERENCE),
        'configuration': {'file': used['file'], 'directory': used['directory'],
                          'parsed': [path for path, _ in files]},
        'monitor_runs': monitors if not blocking else None,
        'command': command if not blocking else None,
        'mailaddr': mailaddr['value'] if mailaddr and not blocking else None,
        'ignored_program_words': ignored if not blocking else [],
        'unknown_keywords': unknown if not blocking else [],
        'services': [dict(service) for service in SERVICES],
        'complete': not blocking,
        'blocking_gaps': blocking,
        'gaps': gaps,
        'unobserved': list(UNOBSERVED),
        'origin': 'not_assessed',
        'not_a_verdict': NOT_A_VERDICT,
        'authorizes_response': False,
    }
