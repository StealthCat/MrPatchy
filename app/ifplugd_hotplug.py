"""Pure ifplugd udev hotplug-agent contract (roadmap F slice, #1377, increment 3).

Debian's ``/lib/udev/rules.d/60-ifplugd.rules`` is
``SUBSYSTEM=="net", RUN+="ifplugd.agent"``. udev therefore runs
``/lib/udev/ifplugd.agent`` as root on every network-interface event, with
``INTERFACE`` and ``ACTION`` in its environment. The agent:

1. exits unless ``INTERFACE`` is set and ``/usr/sbin/ifplugd`` is executable
   (the check runs *before* the config is read);
2. exits unless ``/etc/default/ifplugd`` is a regular file, then sources it as
   root shell code, so a config can replace ``DAEMON``, ``INTERFACE`` or
   ``ACTION``;
3. leaves ``INTERFACE`` alone when it is a word of ``INTERFACES`` or that list
   contains ``all`` (the init script owns it; ``auto`` does *not* match here);
4. otherwise, when ``INTERFACE`` is a word of ``HOTPLUG_INTERFACES`` or that
   list contains ``all``, runs on ``add``/``register``::

       IF1=$(echo $INTERFACE | sed "s/-/_/")
       A=$(eval echo \\$\\{ARGS_${IF1}\\})
       [ -z "$A" ] && A="$ARGS"
       exec $DAEMON -i $INTERFACE $A

   and on ``remove``/``unregister`` runs ``exec $DAEMON -k -i $INTERFACE``.

``HOTPLUG_INTERFACES=all`` has no ``eth*|wlan*`` filter, unlike the init
script's ``auto``. It starts a root daemon for every interface udev reports,
including ``lo``, bridges and container ``veth`` pairs.

This module takes captured, read-only observations and reports, for each
observed interface name, whether the agent starts or kills a daemon, and with
which ``$A`` string. Those strings are the ``ARGS`` input of
:mod:`app.ifplugd_actions`. The config is understood with the same simple
assignment model as :mod:`app.ifplugd_init`, and anything else is a blocking
gap. The rules are pinned to ``ifplugd_0.28-19.7_amd64.deb`` (sha256
``bce99ac50912b7376180cc1237bf0a86723da8bb1d64ce7e6c8cebaac3791136``),
``/lib/udev/ifplugd.agent`` and ``/lib/udev/rules.d/60-ifplugd.rules``, run by
``dash``.

Not modelled: the udev environment the config does not overwrite (a udev rule
can set ``ENV{HOTPLUG_INTERFACES}`` or ``ENV{ARGS}``), other rules that change
``RUN`` or the interface name, the ``wait_for_interface lo`` loop (which never
returns while ``lo`` is ``down``), whether a daemon already runs for the
interface, and event actions other than add/register/remove/unregister, which
do nothing. Interface names are the observed names at collection time.

It performs no I/O, never runs a command and never authorizes a response action.
"""
from __future__ import annotations

import re
from typing import Any

from app import ifplugd_init as _init

CONTRACT_VERSION = 1
MAX_INTERFACES = 1024

AGENT = '/lib/udev/ifplugd.agent'
RULE = '/lib/udev/rules.d/60-ifplugd.rules'
CONFIG_PATH = _init.CONFIG_PATH
DAEMON = _init.DAEMON
CONFIG_STATES = _init.CONFIG_STATES

Invalid = _init.Invalid

# Linux dev_valid_name(): 1..15 bytes, not "." or "..", no "/", ":" or isspace().
_KERNEL_IFNAME = re.compile(r'[^/:\x00 \t\n\v\f\r]{1,15}')
_UDEV_ENVIRONMENT = frozenset({'INTERFACE', 'ACTION'})
NOT_MODELLED = ['inherited_udev_environment', 'other_udev_rules', 'loopback_wait',
                'running_daemon_check', 'other_udev_actions', 'collection_time_interface_names']


def _interfaces(value: Any) -> list[str] | None:
    if value is None:
        return None
    if not isinstance(value, list) or len(value) > MAX_INTERFACES:
        raise Invalid('interfaces must be a list within the entry cap')
    seen: set[str] = set()
    for name in value:
        if (not isinstance(name, str) or not _KERNEL_IFNAME.fullmatch(name)
                or len(name.encode('utf-8', 'surrogatepass')) > 15
                or name in ('.', '..') or name in seen):
            raise Invalid('interfaces must be unique kernel interface names')
        seen.add(name)
    return sorted(value, key=lambda item: item.encode('utf-8', 'surrogatepass'))


def _words(variables: dict[str, str], name: str, gaps: list[dict[str, Any]]) -> list[str]:
    words = [word for word in _init._IFS.split(variables.get(name, '')) if word]
    for word in words:
        if _init._GLOB.search(word):
            _init._gap(gaps, 'interface_word_not_modelled', variable=name, interface=word,
                       reason='pathname_expansion')
    return words


def _member(name: str, words: list[str]) -> bool:
    return name in words or 'all' in words


def resolve(observation: Any) -> dict[str, Any]:
    """Resolve what ``ifplugd.agent`` runs as root for each observed interface."""
    if not isinstance(observation, dict):
        raise Invalid('observation must be an object')
    config = _init._config(observation.get('config'))
    executable = observation.get('daemon_executable')
    if executable not in (True, False, None):
        raise Invalid('daemon_executable must be a boolean or null')
    names = _interfaces(observation.get('interfaces'))
    gaps: list[dict[str, Any]] = []
    result: dict[str, Any] = {
        'contract_version': CONTRACT_VERSION,
        'rule': RULE,
        'agent': AGENT,
        'config_sourced_as_root': False,
        'exits_before_config': None,
        'hotplug': [],
        'skipped': [],
        'gaps': gaps,
        'not_modelled': list(NOT_MODELLED),
    }

    def done() -> dict[str, Any]:
        result['complete'] = not gaps
        return result

    if executable is False:
        result['exits_before_config'] = 'daemon_not_executable'
        return done()
    if executable is None:
        _init._gap(gaps, 'daemon_executable_unobserved', path=DAEMON)
    if config['state'] == 'unknown':
        _init._gap(gaps, 'config_unobserved', path=CONFIG_PATH)
        return done()
    if config['state'] != 'regular':
        result['exits_before_config'] = 'config_not_regular_file'
        return done()

    result['config_sourced_as_root'] = True
    variables, config_gaps = _init.parse_config(config['text'])
    for gap in config_gaps:
        _init._gap(gaps, **gap)
    for name in sorted(_init._ENV_CHANGERS & variables.keys()):
        _init._gap(gaps, 'config_changes_shell_environment', variable=name)
    for name in sorted(_UDEV_ENVIRONMENT & variables.keys()):
        _init._gap(gaps, 'config_overrides_udev_environment', variable=name)
    daemon = variables.get('DAEMON', DAEMON)
    if daemon != DAEMON:
        _init._gap(gaps, 'daemon_overridden', daemon=daemon)
    static = _words(variables, 'INTERFACES', gaps)
    hotplug = _words(variables, 'HOTPLUG_INTERFACES', gaps)
    if names is None:
        _init._gap(gaps, 'interfaces_unobserved')
        return done()

    for name in names:
        if _member(name, static):
            result['skipped'].append({'interface': name, 'reason': 'statically_managed'})
            continue
        if not _member(name, hotplug):
            result['skipped'].append({'interface': name, 'reason': 'not_hotplug'})
            continue
        if _init._GLOB.search(name):
            _init._gap(gaps, 'interface_word_not_modelled', interface=name,
                       reason='pathname_expansion')
            continue
        if '\\' in name or name == '-n':
            _init._gap(gaps, 'interface_word_not_modelled', interface=name,
                       reason='echo_reinterprets')
            continue
        lookup = name.replace('-', '_', 1)
        if not _init._LOOKUP.fullmatch(lookup):
            _init._gap(gaps, 'interface_name_evaluated', interface=name)
            continue
        source = 'ARGS_' + lookup
        printed = _init._echo_words(variables.get(source, ''), gaps, 'args_not_modelled',
                                    interface=name, variable=source)
        if printed is None:
            continue
        if not printed:
            source, printed = 'ARGS', variables.get('ARGS', '')
        result['hotplug'].append({
            'interface': name,
            'matched': 'all' if name not in hotplug else 'name',
            'daemon': daemon,
            'add': {'args': printed, 'args_source': source},
            'remove': {'argv': ['-k', '-i', name]},
        })
    return done()
