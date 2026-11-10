"""Shared controller scan-directory syntax and excluded-filesystem boundary."""
from pathlib import PurePosixPath

from target.agent import scan_excluded


def canonical(path, *, allow_root=False):
    if not isinstance(path,str) or not 1<=len(path)<=4096:return False
    if path=='/' and not allow_root:return False
    parsed=PurePosixPath(path)
    return (path.startswith('/') and not path.startswith('//') and str(parsed)==path
        and '..' not in parsed.parts and not any(ord(c)<32 or ord(c)==127 for c in path)
        and not scan_excluded(parsed))
