"""Pure crypttab keyscript contract (roadmap F slice, #1225).

Debian and Ubuntu cryptsetup unlock the mappings in ``/etc/crypttab`` at boot,
either from the initramfs (``scripts/local-top/cryptroot``) or from the
``cryptdisks``/``cryptdisks-early`` init scripts (``setup_mapping``). An entry
with a ``keyscript=`` option makes cryptsetup ``exec`` that program as root,
with the third crypttab field as its only argument, and pipe its output into
``cryptsetup`` as the key. On the cryptdisks path a ``check=`` program also
runs as root on every unlocked device. This module turns captured crypttab
text, and caller-observed facts about the paths those options name, into the
programs each entry would run. It performs no I/O, never runs a program or a
shell and never authorizes a response action.

The rules follow ``debian/functions``, ``debian/cryptdisks-functions`` and
``debian/initramfs/scripts/local-top/cryptroot`` in Ubuntu ``cryptsetup``
2.7.0-1ubuntu4 and 2.8.4-1ubuntu4. Their parsing and keyscript code is the
same apart from options that cannot change a keyscript or check outcome
(``tcrypt-system`` and ``x-initrd.attach`` are flags in 2.8.4 and ignored
unknown options in 2.7.0):

- ``crypttab_foreach_entry`` reads lines with ``IFS=" \\t" read -r name source
  key options``. Leading and trailing spaces and tabs are dropped, runs of them
  separate the first three fields and the fourth keeps the rest of the line.
  A final line without a newline is never processed, because ``read`` fails
  at end of file. A name starting with ``#`` or an empty name is skipped, and
  so is an entry without a source or key field.
- Each field is decoded with ``printf '%b'`` and the options are split from
  the undecoded field with ``IFS=,`` in an unquoted ``for`` loop, so the words
  also undergo pathname expansion. Both are modelled fail-closed: a backslash
  or a glob character leaves the entry unresolved.
- ``crypttab_validate_option`` maps aliases, requires values for ``cipher``,
  ``hash``, ``header``, ``keyscript`` and ``checkargs``, checks numeric
  options with ``grep -Ex``, resolves a relative ``keyscript`` under
  ``/lib/cryptsetup/scripts`` and a relative ``check`` under
  ``/lib/cryptsetup/checks`` and requires each to pass ``[ -x ] && [ -f ]``.
  ``header`` must exist, because both boot paths call
  ``crypttab_parse_options --missing-path=fail``. A ``check`` flag without a
  value uses ``$CRYPTDISKS_CHECK`` (``blkid`` in ``/etc/default/cryptdisks``)
  and is dropped when that is empty. Unknown options are ignored. A later
  option replaces an earlier one, and the first invalid value makes the
  function return 1, so the whole entry is not unlocked.
- ``run_keyscript`` exports ``CRYPTTAB_NAME``, ``CRYPTTAB_SOURCE``,
  ``CRYPTTAB_OPTIONS``, their undecoded ``_`` forms, ``CRYPTTAB_TRIED`` and,
  for a keyscript, ``CRYPTTAB_KEY``/``_CRYPTTAB_KEY``, then runs
  ``exec "$keyscript" "$CRYPTTAB_KEY"``. Without a keyscript, a key field of
  ``none`` runs ``/lib/cryptsetup/askpass`` with a prompt instead. A keyscript
  equal to ``/lib/cryptsetup/askpass`` with any other key reaches
  ``exec ""``, which fails.
- ``setup_mapping`` runs ``"$check" <mapped device> [checkargs]`` after each
  successful unlock and skips ``noauto`` entries unless started manually and
  ``noearly`` entries in the early init script. The initramfs path never runs
  ``check``.

Fail-closed rules: unobserved crypttab text or path facts, invalid UTF-8, NUL
bytes and over-limit input mark the result incomplete; affected entries are
``unresolved`` and never reported as running nothing. ``origin`` is always
``not_assessed``, ``authorizes_response`` is always False and no result is a
safety verdict.
"""
from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from typing import Any

CONTRACT_VERSION = 1
SOURCE_VERSIONS = ('2.7.0-1ubuntu4', '2.8.4-1ubuntu4')
TABFILE = '/etc/crypttab'
KEYSCRIPT_DIR = '/lib/cryptsetup/scripts'
CHECK_DIR = '/lib/cryptsetup/checks'
ASKPASS = '/lib/cryptsetup/askpass'
DEFAULT_CRYPTDISKS_CHECK = 'blkid'
CONTEXTS = ('cryptdisks', 'initramfs')
MAX_TEXT = 65536
MAX_LINES = 1024
MAX_GAPS = 64

STATUSES = ('accepted', 'rejected', 'skipped', 'unresolved')
BLOCKING = frozenset({
    'text_not_observed', 'over_limit', 'invalid_utf8', 'binary', 'lines_over_limit', 'escape_not_modeled',
    'glob_not_modeled', 'path_not_observed', 'relative_header', 'check_default_not_observed', 'gaps_truncated',
})
NOT_OBSERVED = (
    ('Which boot path handles each entry: the initramfs unlocks only the entries its hook copied (root, resume '
     'and initramfs-flagged devices), and on systemd hosts systemd-cryptsetup-generator, which does not support '
     'keyscript=, may handle the rest instead of the cryptdisks init scripts.'),
    'Whether the source device exists at boot, or the mapping is already active, so whether unlocking is attempted.',
    'The contents of the keyscript or check programs, and of the initramfs copy of each program.',
    'How many unlock attempts run; the keyscript runs once per attempt, up to tries= (default 3, 0 is unlimited).',
)
FLAGS = frozenset({
    'verify', 'loud', 'quiet', 'initramfs', 'noearly', 'noauto', 'readonly', 'discard', 'plain', 'luks', 'swap',
    'tcrypt', 'veracrypt', 'tcrypthidden', 'tcryptsystem', 'bitlk', 'fvault2', 'same-cpu-crypt',
    'submit-from-crypt-cpus', 'no-read-workqueue', 'no-write-workqueue',
})
ALIASES = {'read-only': 'readonly', 'key-slot': 'keyslot', 'tcrypt-hidden': 'tcrypthidden',
           'tcrypt-veracrypt': 'veracrypt', 'tcrypt-system': 'tcryptsystem'}
_POSITIVE = re.compile(r'0*[1-9][0-9]*')
_NON_NEGATIVE = re.compile(r'[0-9]+')
_GLOB = frozenset('*?[')
_IFS = ' \t'


def _gap(gaps: list[dict[str, Any]], code: str, line: int | None = None, detail: str = '') -> None:
    if len(gaps) < MAX_GAPS:
        gaps.append({'code': code, 'line': line, 'detail': detail[:240], 'blocking': code in BLOCKING})
    elif gaps[-1]['code'] != 'gaps_truncated':
        gaps.append({'code': 'gaps_truncated', 'line': None, 'detail': 'Further gaps were not recorded.',
                     'blocking': True})


def split_line(line: str) -> tuple[str, str, str, str]:
    """Split one line as ``IFS=" \\t" read -r name source key options`` does."""
    rest = line.strip(_IFS)
    fields: list[str] = []
    for _ in range(3):
        match = re.match(r'[^ \t]*', rest)
        word = match.group(0) if match else ''
        fields.append(word)
        rest = rest[len(word):].lstrip(_IFS)
    return fields[0], fields[1], fields[2], rest


def _executable_file(path: str, paths: Mapping[str, Any]) -> bool | None:
    """``[ -x path ] && [ -f path ]`` as root, from caller-observed facts (symlinks followed)."""
    fact = paths.get(path)
    if not isinstance(fact, Mapping) or fact.get('type') not in ('file', 'directory', 'other', 'missing'):
        return None
    return fact['type'] == 'file' and fact.get('executable') is True


def _exists(path: str, paths: Mapping[str, Any]) -> bool | None:
    fact = paths.get(path)
    if not isinstance(fact, Mapping) or fact.get('type') not in ('file', 'directory', 'other', 'missing'):
        return None
    return fact['type'] != 'missing'


def parse_options(raw: str, *, paths: Mapping[str, Any] | None = None,
                  cryptdisks_check: str | None = DEFAULT_CRYPTDISKS_CHECK) -> dict[str, Any]:
    """Apply ``crypttab_parse_options --missing-path=fail`` to an undecoded options field.

    ``status`` is ``valid``, ``invalid`` (the function returns 1) or ``unresolved`` (a path fact or the
    ``$CRYPTDISKS_CHECK`` value it depends on was not supplied).
    """
    paths = paths or {}
    result: dict[str, Any] = {'status': 'valid', 'options': {}, 'ignored': [], 'invalid': None,
                              'unresolved': [], 'keyscript_relative': False}
    invalid: list[str] = []
    # IFS=, field splitting keeps empty fields between commas but not after a trailing one.
    words = raw.split(',') if raw else []
    if words and words[-1] == '':
        words.pop()
    for word in words:
        name, has_value, value_text = word.partition('=')
        value: str | None = value_text if has_value else None
        option = ALIASES.get(name, name)
        kind = option
        verdict: bool | None = True
        if kind in ('cipher', 'hash'):
            verdict = bool(value)
        elif kind == 'header':
            if not value:
                verdict = False
            elif not value.startswith('/'):
                verdict = None
                result['unresolved'].append({'option': word, 'reason': 'relative_header'})
            else:
                verdict = _exists(value, paths)
                if verdict is None:
                    result['unresolved'].append({'option': word, 'reason': 'path_not_observed', 'path': value})
        elif kind in ('size', 'keyfile-size', 'sector-size'):
            verdict = bool(_POSITIVE.fullmatch(value or ''))
        elif kind in ('offset', 'skip', 'tries', 'keyslot', 'keyfile-offset'):
            verdict = bool(_NON_NEGATIVE.fullmatch(value or ''))
        elif kind == 'tmp':
            verdict = value != ''
            value = 'ext4' if value is None else value
        elif kind in ('check', 'keyscript'):
            if kind == 'check' and value is None:
                if cryptdisks_check is None:
                    result['unresolved'].append({'option': word, 'reason': 'check_default_not_observed'})
                    verdict = None
                elif cryptdisks_check == '':
                    result['ignored'].append({'option': word, 'reason': 'check_default_empty'})
                    continue
                else:
                    value = cryptdisks_check
            if verdict is not None:
                if not value:
                    verdict = False
                else:
                    relative = not value.startswith('/')
                    if relative:
                        value = f'{CHECK_DIR if kind == "check" else KEYSCRIPT_DIR}/{value}'
                    if kind == 'keyscript':
                        result['keyscript_relative'] = relative
                    verdict = _executable_file(value, paths)
                    if verdict is None:
                        result['unresolved'].append({'option': word, 'reason': 'path_not_observed', 'path': value})
        elif kind == 'checkargs':
            verdict = value is not None
        elif kind in FLAGS:
            verdict = True
        else:
            result['ignored'].append({'option': word, 'reason': 'x_initrd_attach' if kind == 'x-initrd.attach'
                                      else 'unknown_option'})
            continue
        if verdict is False:
            invalid.append(word)
            continue
        result['options'][option.replace('-', '_')] = True if value is None else value
    if invalid:
        result.update(status='invalid', invalid=invalid[0][:240], unresolved=[])
    elif result['unresolved']:
        result['status'] = 'unresolved'
    return result


def _programs(name: str, source: str, key: str, options: Mapping[str, Any], context: str) -> dict[str, Any]:
    keyscript = options.get('keyscript')
    env = ['CRYPTTAB_NAME', 'CRYPTTAB_SOURCE', 'CRYPTTAB_OPTIONS', '_CRYPTTAB_NAME', '_CRYPTTAB_SOURCE',
           '_CRYPTTAB_OPTIONS', 'CRYPTTAB_TRIED']
    if keyscript is not None and keyscript != ASKPASS:
        unlock = {'method': 'keyscript', 'program': keyscript, 'argv': [keyscript, key], 'user': 'root',
                  'exec': True, 'environment': env + ['CRYPTTAB_KEY', '_CRYPTTAB_KEY', 'CRYPTTAB_OPTION_*'],
                  'relative_resolved': False}
    elif key == 'none':
        unlock = {'method': 'askpass', 'program': ASKPASS, 'argv': [ASKPASS, f'Please unlock disk {name}: '],
                  'user': 'root', 'exec': True, 'environment': env + ['CRYPTTAB_OPTION_*'],
                  'relative_resolved': False}
    elif keyscript is not None:
        unlock = {'method': 'exec_fails', 'program': None, 'argv': ['', key], 'user': 'root', 'exec': True,
                  'environment': env + ['CRYPTTAB_OPTION_*'], 'relative_resolved': False}
    else:
        unlock = {'method': 'keyfile', 'program': None, 'argv': None, 'user': 'root', 'exec': False,
                  'environment': [], 'relative_resolved': False}
    check = options.get('check')
    check_run = None
    if check is not None and context == 'cryptdisks':
        argv = [check, '<unlocked device>']
        if 'checkargs' in options:
            argv.append(options['checkargs'])
        check_run = {'program': check, 'argv': argv, 'user': 'root', 'when': 'after_each_successful_unlock'}
    if context == 'cryptdisks':
        boot = 'manual_only' if 'noauto' in options else ('not_early' if 'noearly' in options else 'boot')
    else:
        boot = 'initramfs'
    return {'unlock': unlock, 'check': check_run, 'boot': boot}


def evaluate(text: str | bytes | None, *, context: str = 'cryptdisks', paths: Mapping[str, Any] | None = None,
             cryptdisks_check: str | None = DEFAULT_CRYPTDISKS_CHECK) -> dict[str, Any]:
    """Resolve which programs each crypttab entry runs as root while unlocking.

    ``text`` is the captured crypttab (``None`` when it was not observed). ``context`` is ``'cryptdisks'``
    (the init scripts) or ``'initramfs'`` (``local-top/cryptroot``). ``paths`` maps an absolute path to
    ``{'type': 'file' | 'directory' | 'other' | 'missing', 'executable': bool}`` as observed by root with
    symlinks followed; in the initramfs context the facts must describe the initramfs image.
    ``cryptdisks_check`` is ``$CRYPTDISKS_CHECK`` (``None`` when it was not observed).
    """
    gaps: list[dict[str, Any]] = []
    result: dict[str, Any] = {
        'contract_version': CONTRACT_VERSION, 'format': 'crypttab_keyscripts',
        'source_versions': list(SOURCE_VERSIONS), 'context': context, 'complete': False, 'sha256': None,
        'entries': [], 'programs': [], 'origin': 'not_assessed', 'authorizes_response': False, 'gaps': gaps,
        'not_observed': list(NOT_OBSERVED),
    }
    if context not in CONTEXTS:
        raise ValueError(f'context must be one of {CONTEXTS}')
    if text is None:
        _gap(gaps, 'text_not_observed', None, f'{TABFILE} was not captured.')
        return _finish(result, gaps)
    data = text.encode('utf-8', 'surrogatepass') if isinstance(text, str) else text
    if not isinstance(data, bytes) or len(data) > MAX_TEXT:
        _gap(gaps, 'over_limit', None, f'More than {MAX_TEXT} bytes.')
        return _finish(result, gaps)
    if b'\x00' in data:
        _gap(gaps, 'binary', None, 'The file contains NUL bytes.')
        return _finish(result, gaps)
    try:
        decoded = data.decode('utf-8')
    except UnicodeDecodeError:
        _gap(gaps, 'invalid_utf8', None, 'The file is not valid UTF-8.')
        return _finish(result, gaps)
    result['sha256'] = hashlib.sha256(data).hexdigest()
    lines = decoded.split('\n')
    unterminated = lines.pop()
    if len(lines) > MAX_LINES:
        _gap(gaps, 'lines_over_limit', None, f'More than {MAX_LINES} lines.')
        return _finish(result, gaps)
    for number, line in enumerate(lines, 1):
        entry = _entry(number, line, context, paths or {}, cryptdisks_check, gaps)
        if entry is not None:
            result['entries'].append(entry)
            if entry['status'] == 'accepted':
                for kind in ('unlock', 'check'):
                    run = entry[kind]
                    if run and run.get('program'):
                        result['programs'].append({'name': entry['name'], 'line': number, 'kind': kind,
                                                   'method': run.get('method', 'check'),
                                                   'program': run['program'], 'argv': run['argv'],
                                                   'user': 'root', 'boot': entry['boot'],
                                                   'origin': 'not_assessed'})
    name = split_line(unterminated)[0]
    if name and not name.startswith('#'):
        result['entries'].append({'line': len(lines) + 1, 'name': name, 'status': 'skipped',
                                  'reason': 'unterminated_last_line', 'origin': 'not_assessed'})
    return _finish(result, gaps)


def _entry(number: int, line: str, context: str, paths: Mapping[str, Any], cryptdisks_check: str | None,
           gaps: list[dict[str, Any]]) -> dict[str, Any] | None:
    name, source, key, options = split_line(line)
    if not name or name.startswith('#'):
        return None
    base: dict[str, Any] = {'line': number, 'name': name, 'source': source, 'key': key, 'options_raw': options,
                            'status': 'unresolved', 'reason': None, 'options': None, 'ignored_options': [],
                            'unlock': None, 'check': None, 'boot': None, 'origin': 'not_assessed'}
    if not source or not key:
        return {**base, 'status': 'skipped', 'reason': 'missing_fields'}
    if '\\' in line:
        _gap(gaps, 'escape_not_modeled', number, "The line contains a backslash, which printf '%b' decodes.")
        return {**base, 'reason': 'escape_not_modeled'}
    if any(ch in options for ch in _GLOB):
        _gap(gaps, 'glob_not_modeled', number, 'The options field contains a glob character, so the unquoted '
             'expansion may match files in the working directory.')
        return {**base, 'reason': 'glob_not_modeled'}
    parsed = parse_options(options, paths=paths, cryptdisks_check=cryptdisks_check)
    base['ignored_options'] = parsed['ignored']
    if parsed['status'] == 'invalid':
        return {**base, 'status': 'rejected', 'reason': 'invalid_option', 'invalid_option': parsed['invalid']}
    if parsed['status'] == 'unresolved':
        for item in parsed['unresolved']:
            _gap(gaps, item['reason'], number, f'{item["option"][:120]}: {item.get("path", "")[:100]}')
        return {**base, 'reason': parsed['unresolved'][0]['reason'], 'options': parsed['options']}
    runs = _programs(name, source, key, parsed['options'], context)
    runs['unlock']['relative_resolved'] = runs['unlock']['method'] == 'keyscript' and parsed['keyscript_relative']
    return {**base, 'status': 'accepted', 'options': parsed['options'], **runs}


def _finish(result: dict[str, Any], gaps: list[dict[str, Any]]) -> dict[str, Any]:
    result['complete'] = not any(g['blocking'] for g in gaps)
    return result

