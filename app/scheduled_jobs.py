"""Pure anacrontab and at-queue job parsing contract (roadmap F slice, #711).

Turns captured, read-only text of an anacrontab file or one at spool job into
typed, bounded job records. It performs no I/O, never runs ``anacron``/``atq``
or a job, never sources a script and never authorizes a response action.

Fail-closed rules:

- Over-limit text, invalid UTF-8 and lines the documented format does not allow
  become explicit gaps. An over-limit file yields no jobs at all rather than a
  silently truncated list.
- Environment values are withheld. Only variable names, plus a fixed set of
  anacron scheduling settings whose values are needed to understand when jobs
  run, are returned. Values may contain credentials.
- No record is labelled a package default or "safe". ``origin`` is always
  ``not_assessed``; provenance needs separate authenticated package evidence.

anacrontab follows ``anacrontab(5)``: ``VAR=value`` assignments and job lines
``period delay job-identifier command`` where period is a positive day count or
``@daily``/``@weekly``/``@monthly``/``@yearly``/``@annually``.

at spool job names follow the ``atd`` layout ``<queue><job:5 hex><minute:8 hex>``.
The minute field counts minutes since the Unix epoch. Queue ``=`` marks a job
that is currently running, and uppercase queues are run as ``batch`` jobs.
The job body is the script ``at`` wrote: ``#!/bin/sh``, ``# atrun uid= gid=``,
``# mail`` header, ``umask``, exported environment, ``cd <dir> || {...}`` and
then the user command, optionally wrapped in a ``${SHELL:-/bin/sh} << 'DELIM'``
heredoc.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any

CONTRACT_VERSION = 1
MAX_TEXT = 65536
MAX_LINES = 2048
MAX_JOBS = 256
MAX_ENV = 256
MAX_COMMAND = 4096
MAX_GAPS = 64

PERIOD_NAMES = {'daily': 1, 'weekly': 7, 'monthly': 30, 'yearly': 365, 'annually': 365}
# Settings whose values change when anacron runs jobs; never credentials.
DISCLOSED_SETTINGS = ('START_HOURS_RANGE', 'RANDOM_DELAY')

_ASSIGN = re.compile(r'\s*([A-Za-z_][A-Za-z0-9_]*)\s*=(.*)')
_IDENT = re.compile(r'[^\s/]{1,255}')
_HOURS = re.compile(r'([0-9]{1,2})-([0-9]{1,2})')
_AT_NAME = re.compile(r'([a-zA-Z=])([0-9a-f]{5})([0-9a-f]{8})')
_AT_HEADER = re.compile(r'# atrun uid=(\d{1,10}) gid=(\d{1,10})')
_AT_EXPORT = re.compile(r'([A-Za-z_][A-Za-z0-9_]*)=.*; export \1')
_AT_CD = re.compile(r'cd (.+) \|\| \{')
_AT_HEREDOC = re.compile(r"\$\{SHELL:-/bin/sh\} << '([A-Za-z0-9_]{1,64})'")


def _gap(gaps: list[dict[str, Any]], code: str, line: int | None = None, detail: str = '') -> None:
    if len(gaps) < MAX_GAPS:
        gaps.append({'code': code, 'line': line, 'detail': detail[:200]})
    elif gaps[-1]['code'] != 'gaps_truncated':
        gaps.append({'code': 'gaps_truncated', 'line': None, 'detail': 'Further gaps were not recorded.'})


def _decode(text: str | bytes, gaps: list[dict[str, Any]]) -> str | None:
    if isinstance(text, bytes):
        if len(text) > MAX_TEXT:
            _gap(gaps, 'over_limit', None, f'More than {MAX_TEXT} bytes.')
            return None
        try:
            text = text.decode('utf-8')
        except UnicodeDecodeError:
            _gap(gaps, 'invalid_utf8', None, 'Text is not valid UTF-8.')
            return None
    if not isinstance(text, str):
        _gap(gaps, 'unreadable', None, 'No text was captured.')
        return None
    if len(text.encode('utf-8')) > MAX_TEXT:
        _gap(gaps, 'over_limit', None, f'More than {MAX_TEXT} bytes.')
        return None
    if '\x00' in text:
        _gap(gaps, 'binary', None, 'Text contains NUL bytes.')
        return None
    return text


def _command(raw: str) -> dict[str, Any]:
    data = raw.encode('utf-8')
    return {'command': raw[:MAX_COMMAND], 'command_truncated': len(raw) > MAX_COMMAND,
            'command_sha256': hashlib.sha256(data).hexdigest()}


def _run_parts(command: str) -> list[str]:
    """Absolute directories a ``run-parts`` invocation names, never guessed."""
    tokens = command.split()
    dirs: list[str] = []
    for index, token in enumerate(tokens):
        if token.rsplit('/', 1)[-1] != 'run-parts':
            continue
        for arg in tokens[index + 1:]:
            if arg in (';', '&&', '||', '|') or arg.endswith(';'):
                break
            if arg.startswith('-'):
                continue
            if arg.startswith('/'):
                dirs.append(arg.rstrip('/') or '/')
            break
    return dirs


def _settings(name: str, value: str) -> tuple[Any, str | None]:
    """Validate a disclosed anacron setting; return (parsed, gap code)."""
    value = value.strip()
    if name == 'RANDOM_DELAY':
        return (int(value), None) if value.isascii() and value.isdigit() and len(value) <= 6 else (None, 'invalid_setting')
    match = _HOURS.fullmatch(value)
    if not match:
        return None, 'invalid_setting'
    start, end = int(match.group(1)), int(match.group(2))
    if not (0 <= start <= 24 and 0 <= end <= 24):
        return None, 'invalid_setting'
    return {'start': start, 'end': end}, None


def parse_anacrontab(text: str | bytes) -> dict[str, Any]:
    """Parse one anacrontab file into job records and coverage gaps."""
    gaps: list[dict[str, Any]] = []
    result: dict[str, Any] = {'contract_version': CONTRACT_VERSION, 'format': 'anacrontab', 'state': 'parsed',
                              'jobs': [], 'environment_names': [], 'settings': {}, 'gaps': gaps}
    decoded = _decode(text, gaps)
    if decoded is None:
        result['state'] = 'unavailable'
        return result
    lines = decoded.split('\n')
    if len(lines) > MAX_LINES:
        _gap(gaps, 'over_limit', None, f'More than {MAX_LINES} lines.')
        result['state'] = 'unavailable'
        return result
    seen: dict[str, int] = {}
    env: list[str] = []
    for number, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            continue
        assign = _ASSIGN.fullmatch(line)
        if assign:
            name = assign.group(1)
            if len(env) >= MAX_ENV:
                _gap(gaps, 'over_limit', number, f'More than {MAX_ENV} environment assignments.')
                result.update(state='unavailable', jobs=[], environment_names=[], settings={})
                return result
            if name not in env:
                env.append(name)
            if name in DISCLOSED_SETTINGS:
                parsed, code = _settings(name, assign.group(2))
                if code:
                    _gap(gaps, code, number, f'{name} is not a valid anacron value.')
                    result['settings'].pop(name, None)
                else:
                    result['settings'][name] = parsed
            continue
        fields = stripped.split(None, 3)
        if len(fields) < 4:
            _gap(gaps, 'malformed_line', number, 'Expected period, delay, job identifier and command.')
            continue
        period_text, delay_text, ident, command = fields
        if period_text.startswith('@'):
            days = PERIOD_NAMES.get(period_text[1:])
            period = {'kind': 'named', 'name': period_text[1:], 'days': days}
        elif period_text.isascii() and period_text.isdigit() and len(period_text) <= 5 and int(period_text) > 0:
            days = int(period_text)
            period = {'kind': 'days', 'name': None, 'days': days}
        else:
            days = None
        if days is None:
            _gap(gaps, 'invalid_period', number, 'Period must be a positive day count or a documented @name.')
            continue
        if not (delay_text.isascii() and delay_text.isdigit() and len(delay_text) <= 6):
            _gap(gaps, 'invalid_delay', number, 'Delay must be a non-negative number of minutes.')
            continue
        if not _IDENT.fullmatch(ident):
            _gap(gaps, 'invalid_identifier', number, 'Job identifier must not contain slashes or whitespace.')
            continue
        if len(result['jobs']) >= MAX_JOBS:
            _gap(gaps, 'over_limit', number, f'More than {MAX_JOBS} jobs.')
            result.update(state='unavailable', jobs=[], environment_names=[], settings={})
            return result
        job = {'line': number, 'identifier': ident, 'period': period, 'delay_minutes': int(delay_text),
               'run_parts_dirs': _run_parts(command), 'duplicate_of_line': seen.get(ident),
               'origin': 'not_assessed'}
        job.update(_command(command))
        if ident in seen:
            _gap(gaps, 'duplicate_identifier', number, f'Job identifier also used on line {seen[ident]}; '
                 'anacron shares one timestamp file between them.')
        else:
            seen[ident] = number
        result['jobs'].append(job)
    result['environment_names'] = env
    if gaps:
        result['state'] = 'partial'
    return result


def decode_at_name(name: str) -> dict[str, Any] | None:
    """Decode an at spool file name, or None when it is not a job file."""
    match = _AT_NAME.fullmatch(name or '')
    if not match:
        return None
    queue = match.group(1)
    return {'queue': queue, 'job_number': int(match.group(2), 16),
            'scheduled_at': int(match.group(3), 16) * 60,
            'running': queue == '=', 'batch': queue.isupper()}


def parse_at_job(name: str, text: str | bytes, owner_uid: int | None = None) -> dict[str, Any]:
    """Parse one at spool job script into a typed record and coverage gaps."""
    gaps: list[dict[str, Any]] = []
    result: dict[str, Any] = {'contract_version': CONTRACT_VERSION, 'format': 'at_job', 'state': 'parsed',
                              'name': str(name)[:255], 'queue': None, 'job_number': None, 'scheduled_at': None,
                              'running': None, 'batch': None, 'uid': None, 'gid': None, 'owner_uid': owner_uid,
                              'owner_mismatch': None, 'environment_names': [], 'working_directory': None,
                              'command': None, 'command_truncated': False, 'command_sha256': None,
                              'origin': 'not_assessed', 'gaps': gaps}
    decoded_name = decode_at_name(name)
    if decoded_name is None:
        _gap(gaps, 'unrecognized_name', None, 'File name is not an at job (<queue><job><minute>).')
        result['state'] = 'unavailable'
        return result
    result.update(decoded_name)
    decoded = _decode(text, gaps)
    if decoded is None:
        result['state'] = 'unavailable'
        return result
    lines = decoded.split('\n')
    if len(lines) > MAX_LINES:
        _gap(gaps, 'over_limit', None, f'More than {MAX_LINES} lines.')
        result['state'] = 'unavailable'
        return result
    header = _AT_HEADER.fullmatch(lines[1]) if len(lines) > 1 and lines[0].startswith('#!') else None
    if header is None:
        _gap(gaps, 'unrecognized_layout', 1, 'Missing the "#!" and "# atrun uid= gid=" header.')
        result['state'] = 'unavailable'
        return result
    result['uid'], result['gid'] = int(header.group(1)), int(header.group(2))
    if owner_uid is not None:
        result['owner_mismatch'] = owner_uid != result['uid']
        if result['owner_mismatch']:
            _gap(gaps, 'owner_mismatch', 2, 'Spool file owner differs from the declared atrun uid.')
    index = 2
    env: list[str] = []
    cd_line = None
    while index < len(lines):
        line = lines[index]
        if line.startswith('#') or line.startswith('umask ') or not line.strip():
            index += 1
            continue
        export = _AT_EXPORT.fullmatch(line)
        if export:
            if len(env) >= MAX_ENV:
                _gap(gaps, 'over_limit', index + 1, f'More than {MAX_ENV} exported variables.')
                result.update(state='unavailable', environment_names=[])
                return result
            if export.group(1) not in env:
                env.append(export.group(1))
            index += 1
            continue
        cd = _AT_CD.fullmatch(line)
        if cd:
            cd_line = index
            result['working_directory'] = cd.group(1)[:4096]
        break
    result['environment_names'] = env
    if cd_line is None:
        _gap(gaps, 'unrecognized_layout', index + 1, 'Missing the "cd <dir> || {" preamble.')
        result['state'] = 'unavailable'
        return result
    close = next((i for i in range(cd_line + 1, min(cd_line + 6, len(lines))) if lines[i] == '}'), None)
    if close is None:
        _gap(gaps, 'unrecognized_layout', cd_line + 1, 'The cd failure block is not closed.')
        result['state'] = 'unavailable'
        return result
    body = lines[close + 1:]
    heredoc = _AT_HEREDOC.fullmatch(body[0]) if body else None
    if heredoc:
        delimiter = heredoc.group(1)
        end = next((i for i in range(1, len(body)) if body[i] == delimiter), None)
        if end is None:
            _gap(gaps, 'unrecognized_layout', close + 2, 'The command heredoc is not terminated.')
            result['state'] = 'unavailable'
            return result
        trailing = [line for line in body[end + 1:] if line.strip()]
        if trailing:
            _gap(gaps, 'unrecognized_layout', close + end + 3, 'Unexpected text after the command heredoc.')
            result['state'] = 'unavailable'
            return result
        body = body[1:end]
    command = '\n'.join(body).strip('\n')
    if not command.strip():
        _gap(gaps, 'empty_command', close + 2, 'The job contains no command.')
        result['state'] = 'partial'
        return result
    result.update(_command(command))
    if gaps:
        result['state'] = 'partial'
    return result
