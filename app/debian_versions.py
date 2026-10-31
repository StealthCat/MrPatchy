"""Native Debian ordering with bounded, per-inventory comparison reuse."""
from functools import lru_cache
import subprocess


def newer_flags(pairs):
    # Scope the cache to this inventory; bound memory even for unique versions.
    @lru_cache(maxsize=512)
    def newer(candidate, installed):
        if candidate == installed:
            return False
        result = subprocess.run(
            ['/usr/bin/dpkg', '--compare-versions', candidate, 'gt', installed],
            timeout=10, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        if result.returncode not in (0, 1):
            raise ValueError('Native Debian version comparison failed')
        return result.returncode == 0

    return [newer(candidate, installed) for candidate, installed in pairs]
