"""Pure ifplugd init-script start contract (roadmap F slice, #1377, increment 2).

At boot, Debian's ``/etc/init.d/ifplugd start`` runs as root. It sources
``/etc/default/ifplugd`` (``[ -f $CFG ] && . $CFG``), so that file is itself
root shell code. The script then resolves ``INTERFACES`` and, for each
interface ``IF`` that exists under ``/sys/class/net`` and has no running
daemon, runs::

    IF1=$(echo $IF | sed "s/-/_/")
    A=$(eval echo \\$\\{ARGS_${IF1}\\})
    [ -z "$A" ] && A="$ARGS"
    $IFPLUGD -i $IF $A

``INTERFACES`` of exactly ``auto`` or ``all`` is replaced by
``all_interfaces``. That function walks ``/sys/class/net/*`` in ``dash`` glob
order (byte order, no dot names). It keeps an entry that has a ``device``
entry and, when ``type`` is a regular file, a line that is exactly ``1``, and
whose name matches ``eth*`` or ``wlan*``.

This module takes captured, read-only observations and says which daemon
starts happen, with which ``-i`` interface and which ``$A`` string. Those
strings are the ``ARGS`` input of :mod:`app.ifplugd_actions`. The rules are
pinned to ``ifplugd_0.28-19.7_amd64.deb`` (sha256
``bce99ac50912b7376180cc1237bf0a86723da8bb1d64ce7e6c8cebaac3791136``),
``/etc/init.d/ifplugd``, run by ``dash``.

Shell is never evaluated. The config file is understood only as blank lines,
comments and simple ``NAME=value`` assignments whose value uses plain
characters, single quotes, or double quotes without ``$``, backquote or
backslash. Anything else is a blocking gap, because sourcing it runs it as
root. A config that sets ``IFPLUGD`` changes which root program starts, and
``IFS`` or ``PATH`` change how the script runs. Both are gaps. The same goes for
an interface word or ``ARGS_*`` value that ``dash`` would glob, ``echo`` would
reinterpret, or ``eval`` would parse as more than one parameter name. A plain
``ARGS`` fallback is a gap when it holds a glob character or a backslash,
because ``$A`` is expanded unquoted on the daemon command line.

Not modelled: positional ``start`` interfaces (boot passes none),
``/lib/lsb/init-functions`` and its hooks, an inherited environment, and
whether a daemon is already running (``ifplugd -c`` skips the interface). The
``/sys/class/net`` observation is taken at collection time, not at boot, and a
listed entry is taken to exist.

It performs no I/O, never runs a command and never authorizes a response action.
"""
from __future__ import annotations

import re
from typing import Any

CONTRACT_VERSION = 1
MAX_CONFIG_BYTES = 65536
MAX_LINES = 4096
MAX_ENTRIES = 1024
MAX_GAPS = 256

CONFIG_PATH = '/etc/default/ifplugd'
DAEMON = '/usr/sbin/ifplugd'
CONFIG_STATES = ('regular', 'absent', 'other', 'unknown')
TYPE_STATES = ('regular', 'absent', 'other', 'unknown')

_NAME = re.compile(r'[A-Za-z_][A-Za-z0-9_]*')
_ASSIGN = re.compile(r'([A-Za-z_][A-Za-z0-9_]*)=')
_PLAIN = re.compile(r'[A-Za-z0-9_./,:+=@%^-]+')
_SINGLE = re.compile(r"'([^']*)'")
_DOUBLE = re.compile(r'"([^"$`\\]*)"')
_COMMENT = re.compile(r'[ \t]+(#.*)?')
_IFS = re.compile(r'[ \t\n]+')
_GLOB = re.compile(r'[*?\[]')
_IFNAME = re.compile(r'[^\x00/]{1,255}')
_LOOKUP = re.compile(r'[A-Za-z0-9_]*')
_ENV_CHANGERS = frozenset({'IFS', 'PATH', 'ENV', 'CDPATH'})


class Invalid(ValueError):
    """Raised for observations that do not have the documented shape."""


def _gap(gaps: list[dict[str, Any]], code: str, **detail: Any) -> None:
    if len(gaps) < MAX_GAPS:
        gaps.append({'code': code, **detail})
    elif gaps[-1].get('code') != 'gap_cap_reached':
        gaps.append({'code': 'gap_cap_reached'})


def _value(text: str) -> tuple[str | None, str]:
    """Parse an assignment value; return (value or None, remaining text)."""
    out: list[str] = []
    position = 0
    while position < len(text):
        for pattern, group in ((_PLAIN, 0), (_SINGLE, 1), (_DOUBLE, 1)):
            match = pattern.match(text, position)
            if match:
                out.append(match.group(group))
                position = match.end()
                break
        else:
            break
    return ''.join(out), text[position:]


def parse_config(text: str) -> tuple[dict[str, str], list[dict[str, Any]]]:
    """Return the variables a simple config assigns, and gaps for the rest."""
    variables: dict[str, str] = {}
    gaps: list[dict[str, Any]] = []
    lines = text.split('\n')
    if len(lines) > MAX_LINES:
        _gap(gaps, 'config_over_cap', lines=len(lines))
        return variables, gaps
    for number, line in enumerate(lines, 1):
        body = line.lstrip(' \t')
        if not body or body.startswith('#'):
            continue
        match = _ASSIGN.match(body)
        if not match:
            _gap(gaps, 'config_not_simple_assignment', line=number)
            continue
        value, rest = _value(body[match.end():])
        if rest and not _COMMENT.fullmatch(rest):
            _gap(gaps, 'config_not_simple_assignment', line=number)
            continue
        variables[match.group(1)] = value
    return variables, gaps


def _config(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get('state') not in CONFIG_STATES:
        raise Invalid('config must be an object with a known state')
    text = value.get('text')
    if value['state'] == 'regular':
        if not isinstance(text, str):
            raise Invalid('a regular config needs text')
        if len(text.encode('utf-8', 'surrogatepass')) > MAX_CONFIG_BYTES:
            raise Invalid('config text is over the size cap')
    return value


def _entries(value: Any) -> list[dict[str, Any]] | None:
    if value is None:
        return None
    if not isinstance(value, list) or len(value) > MAX_ENTRIES:
        raise Invalid('interfaces must be a list within the entry cap')
    seen: set[str] = set()
    out = []
    for entry in value:
        if not isinstance(entry, dict):
            raise Invalid('each interface entry must be an object')
        name = entry.get('name')
        if not isinstance(name, str) or not _IFNAME.fullmatch(name) or name in seen:
            raise Invalid('interface names must be unique path components')
        seen.add(name)
        if not isinstance(entry.get('device'), bool):
            raise Invalid('device must be a boolean')
        if entry.get('type_state') not in TYPE_STATES:
            raise Invalid('type_state must be a known state')
        if entry['type_state'] == 'regular' and not isinstance(entry.get('type_text'), str):
            raise Invalid('a regular type file needs type_text')
        out.append(entry)
    return out


def _all_interfaces(entries: list[dict[str, Any]], gaps: list[dict[str, Any]]) -> list[str]:
    names = []
    for entry in sorted(entries, key=lambda item: item['name'].encode('utf-8', 'surrogatepass')):
        name = entry['name']
        if name.startswith('.') or not entry['device']:
            continue
        if entry['type_state'] == 'unknown':
            _gap(gaps, 'interface_type_unknown', interface=name)
            continue
        if entry['type_state'] == 'regular' and '1' not in entry['type_text'].split('\n'):
            continue
        if not name.startswith(('eth', 'wlan')):
            continue
        names.append(name)
    return names


def _echo_words(value: str, gaps: list[dict[str, Any]], code: str, **detail: Any) -> str | None:
    """What ``echo $value`` prints in dash, or None with a gap."""
    words = [word for word in _IFS.split(value) if word]
    if any(_GLOB.search(word) for word in words):
        _gap(gaps, code, reason='pathname_expansion', **detail)
        return None
    if '\\' in value or (words and words[0] == '-n'):
        _gap(gaps, code, reason='echo_reinterprets', **detail)
        return None
    return ' '.join(words)


def _fallback_args(value: str, gaps: list[dict[str, Any]], **detail: Any) -> str | None:
    """``$ARGS`` as ``$A``, or None with a gap when the unquoted ``$A`` would change it.

    ``$A`` is expanded unquoted on the daemon command line, so dash globs its
    words against the working directory. A backslash in an unquoted expansion
    also takes part in that pattern matching.
    """
    words = [word for word in _IFS.split(value) if word]
    if any(_GLOB.search(word) for word in words):
        _gap(gaps, 'args_not_modelled', reason='pathname_expansion', variable='ARGS', **detail)
        return None
    if '\\' in value:
        _gap(gaps, 'args_not_modelled', reason='unquoted_backslash', variable='ARGS', **detail)
        return None
    return value


def resolve(observation: Any) -> dict[str, Any]:
    """Resolve the daemon starts of ``/etc/init.d/ifplugd start`` at boot."""
    if not isinstance(observation, dict):
        raise Invalid('observation must be an object')
    config = _config(observation.get('config'))
    entries = _entries(observation.get('interfaces'))
    gaps: list[dict[str, Any]] = []
    variables: dict[str, str] = {}
    sourced = config['state'] == 'regular'
    if config['state'] == 'unknown':
        _gap(gaps, 'config_unobserved', path=CONFIG_PATH)
    elif sourced:
        variables, config_gaps = parse_config(config['text'])
        for gap in config_gaps:
            _gap(gaps, **gap)
    for name in sorted(_ENV_CHANGERS & variables.keys()):
        _gap(gaps, 'config_changes_shell_environment', variable=name)
    daemon = variables.get('IFPLUGD', DAEMON)
    if daemon != DAEMON:
        _gap(gaps, 'daemon_overridden', daemon=daemon)

    interfaces_value = variables.get('INTERFACES', '')
    auto = interfaces_value in ('auto', 'all')
    starts: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    if auto:
        if entries is None:
            _gap(gaps, 'interfaces_unobserved')
            words: list[str] = []
        else:
            words = []
            for name in _all_interfaces(entries, gaps):
                printed = _echo_words(name, gaps, 'interface_word_not_modelled', interface=name)
                if printed is not None:
                    words.extend(printed.split(' '))
    else:
        words = [word for word in _IFS.split(interfaces_value) if word]
    by_name = {entry['name']: entry for entry in entries or []}
    for word in words:
        if _GLOB.search(word) or '/' in word or word in ('.', '..'):
            _gap(gaps, 'interface_word_not_modelled', interface=word, reason='path_or_glob')
            continue
        if entries is None:
            _gap(gaps, 'interfaces_unobserved', interface=word)
            continue
        if word not in by_name:
            skipped.append({'interface': word, 'reason': 'not_present'})
            continue
        if '\\' in word or word == '-n':
            _gap(gaps, 'interface_word_not_modelled', interface=word, reason='echo_reinterprets')
            continue
        lookup = word.replace('-', '_', 1)
        if not _LOOKUP.fullmatch(lookup):
            _gap(gaps, 'interface_name_evaluated', interface=word)
            continue
        source = 'ARGS_' + lookup
        printed = _echo_words(variables.get(source, ''), gaps, 'args_not_modelled',
                              interface=word, variable=source)
        if printed is None:
            continue
        if not printed:
            source = 'ARGS'
            printed = _fallback_args(variables.get('ARGS', ''), gaps, interface=word)
            if printed is None:
                continue
        starts.append({'interface': word, 'args': printed, 'args_source': source,
                       'daemon': daemon})
    return {
        'contract_version': CONTRACT_VERSION,
        'complete': not gaps,
        'config_sourced_as_root': sourced,
        'interfaces_mode': 'auto' if auto else 'list',
        'starts': starts,
        'skipped': skipped,
        'gaps': gaps,
        'not_modelled': ['positional_interfaces', 'lsb_init_functions', 'inherited_environment',
                         'running_daemon_check', 'boot_time_interface_presence'],
    }
