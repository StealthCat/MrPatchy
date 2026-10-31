"""Distribution-aware package operations; discovery always runs centrally."""
import json
import os
from pathlib import Path
import tempfile
from . import apt
from . import debian_versions
from .db import DATA
from .process import bounded
from .repository_access import validate as validate_access
from target import rpm_support


def is_rpm(inv):return inv.get('package_manager')=='rpm'


def native(action, **payload):
    DATA.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='rpm-request-',dir=DATA) as directory:
        request=Path(directory)/'request.json';request.write_text(json.dumps({'action':action,**payload}));request.chmod(0o600)
        out,_=bounded(['/usr/bin/python3','-I',str(Path(rpm_support.__file__)),str(request)],timeout=900)
        return json.loads(out)


def installed(inv):
    if not is_rpm(inv):return apt.installed(inv['status'])
    return [{k:v for k,v in p.items() if k!='installed_versions'} for p in native('installed',inventory=inv)]


def newer_flags(inv,pairs):
    if is_rpm(inv):return native('compare',pairs=pairs) if pairs else []
    return debian_versions.newer_flags(pairs)


def refresh(host_id,inv,access=None):
    if not is_rpm(inv):return apt.refresh(host_id,inv,access)
    access=validate_access(access or {})
    root=DATA/'rpm'/host_id;root.mkdir(parents=True,exist_ok=True)
    return native('discover',inventory=inv,root=str(root.resolve()),access=access),'Central DNF metadata check completed; exact dependencies are resolved on the target before installation.'


def source_path(path,inv):return rpm_support.source_path(path) if is_rpm(inv) else apt.source_path(path)


def sources(content,path,inv,access):
    if is_rpm(inv):return rpm_support.repositories({path:content},inv.get('rpm_vars',{}))
    rewritten=apt.rewrite(content,access);apt.validate_source(rewritten,path.endswith('.sources'))
    return list(apt.source_options(rewritten,path.endswith('.sources')))
