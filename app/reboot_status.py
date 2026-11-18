"""Read-only pending-reboot state from the last reported agent inventory.

The agent reports whether installed updates are waiting for a reboot (the Debian
``/var/run/reboot-required`` flag or the boot-bound RPM marker). The value is
untrusted target data: anything malformed is ``not_reported``, never
``not_required``. This is visibility only; it authorizes no reboot or response.
"""
import re

PACKAGE = re.compile(r'[A-Za-z0-9][A-Za-z0-9+_.:-]{0,199}')
PACKAGE_LIMIT = 50
GAP = ('Reported from the last inventory refresh. Debian-family hosts list the packages '
       'that requested the reboot when the system provides them; RPM hosts report only '
       'Mr Patchy patch transactions. Running services that still use replaced libraries '
       'without a reboot flag are not detected.')


def evaluate(inventory):
    inventory = inventory if isinstance(inventory, dict) else {}
    collected = inventory.get('collected')
    observed = collected if isinstance(collected, (int, float)) and not isinstance(collected, bool) and collected > 0 else None
    value = inventory.get('reboot')
    base = {'state': 'not_reported', 'packages': [], 'packages_truncated': False, 'observed': observed, 'gap': GAP}
    if (not isinstance(value, dict) or set(value) != {'required', 'packages', 'packages_truncated'}
            or type(value['required']) is not bool or type(value['packages_truncated']) is not bool
            or not isinstance(value['packages'], list) or len(value['packages']) > PACKAGE_LIMIT
            or any(not isinstance(name, str) or not PACKAGE.fullmatch(name) for name in value['packages'])
            or len(set(value['packages'])) != len(value['packages'])
            or (not value['required'] and (value['packages'] or value['packages_truncated']))):
        return base
    return {**base, 'state': 'required' if value['required'] else 'not_required',
            'packages': list(value['packages']), 'packages_truncated': value['packages_truncated']}
