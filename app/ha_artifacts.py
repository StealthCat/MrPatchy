"""Durable-file inventory and read-only shared-backend assessment for HA planning (#447, first slice).

Pure data and arithmetic: nothing here touches the filesystem, the database, a secret or a remote
host, and it authorizes no migration, failover or deployment action. A backend capability counts only
when it is the boolean ``True``; an absent, unknown or malformed declaration is treated as missing so
that an unverified backend is never reported ready.
"""
AUTHORITATIVE='authoritative'
CACHE='cache'
COORDINATION='coordination'

CAPABILITIES=('atomic_publish','read_after_publish','exclusive_create','owner_only_permissions',
              'symlink_safe_directories','durable_fsync','advisory_locks')

# Templates are relative to the root named in `root`; <id> placeholders are never expanded here.
CONSUMERS=(
    {'id':'instance_key','root':'data','path':'secret.key','class':AUTHORITATIVE,'sensitivity':'secret',
     'requires':('exclusive_create','atomic_publish','read_after_publish','owner_only_permissions','durable_fsync'),
     'note':'Root of sealed secrets and derived signing keys; never regenerate when shared custody is missing or mismatched.'},
    {'id':'ssh_keys','root':'data','path':'ssh/<host>.key','class':AUTHORITATIVE,'sensitivity':'secret',
     'requires':('exclusive_create','atomic_publish','read_after_publish','owner_only_permissions','durable_fsync'),
     'note':'Per-target private keys.'},
    {'id':'ssh_rotation_journal','root':'data','path':'ssh/<host>.rotation.json','class':AUTHORITATIVE,'sensitivity':'secret',
     'requires':('atomic_publish','read_after_publish','owner_only_permissions','durable_fsync'),
     'note':'Resumable key-rotation state; losing it can strand a target.'},
    {'id':'database_profiles','root':'data','path':'database-<name>.json','class':AUTHORITATIVE,'sensitivity':'secret',
     'requires':('atomic_publish','read_after_publish','owner_only_permissions','durable_fsync'),
     'note':'Database connection profiles.'},
    {'id':'evidence_archive','root':'data','path':'evidence-archive/<id>/','class':AUTHORITATIVE,'sensitivity':'evidence',
     'requires':('atomic_publish','read_after_publish','owner_only_permissions','symlink_safe_directories','durable_fsync'),
     'note':'Approved evidence copies; the controller anchors them with no symlink traversal.'},
    {'id':'vendor_packages','root':'data','path':'vendor-packages/<id>/','class':AUTHORITATIVE,'sensitivity':'artifact',
     'requires':('atomic_publish','read_after_publish','durable_fsync'),'note':'Offline/vendor replacement bundles.'},
    {'id':'yara_rules','root':'data','path':'yara-rules/<id>/','class':AUTHORITATIVE,'sensitivity':'artifact',
     'requires':('atomic_publish','read_after_publish','durable_fsync'),'note':'Uploaded YARA rule bundles.'},
    {'id':'tls_material','root':'tls','path':'','class':AUTHORITATIVE,'sensitivity':'secret',
     'requires':('atomic_publish','read_after_publish','owner_only_permissions','durable_fsync'),
     'note':'Caddyfile, certificates and keys; one Caddy administration endpoint still serves them.'},
    {'id':'apt_workdirs','root':'data','path':'apt/<host>/, apt/release-<id>/','class':CACHE,'sensitivity':'working',
     'requires':(),'note':'Per-node working copies that can be rebuilt; confirm before deleting.'},
    {'id':'rpm_workdirs','root':'data','path':'rpm/<host>/','class':CACHE,'sensitivity':'working',
     'requires':(),'note':'Per-node working copies that can be rebuilt; confirm before deleting.'},
    {'id':'operation_locks','root':'data','path':'locks/*','class':COORDINATION,'sensitivity':'none',
     'requires':('advisory_locks',),
     'note':'flock files are visible only on one host; a shared MySQL does not share them, so multi-host use needs distributed coordination.'},
    {'id':'database_maintenance_lock','root':'data','path':'database-maintenance.lock','class':COORDINATION,'sensitivity':'none',
     'requires':('advisory_locks',),'note':'Shared/exclusive flock that requires one shared data directory.'},
)


def inventory():
    """Return a copy of the consumer inventory."""
    return [{**c,'requires':list(c['requires'])} for c in CONSUMERS]


def declared(backend):
    """Capabilities explicitly declared as boolean True; everything else is missing."""
    if not isinstance(backend,dict):return set()
    return {name for name in CAPABILITIES if backend.get(name) is True}


def assess(backend):
    """Compare a declared backend with what each durable consumer needs.

    ``ready`` is true only when every authoritative consumer is satisfied; coordination consumers
    that need locks are reported separately because file locks cannot be assumed to work across hosts.
    """
    have=declared(backend)
    consumers=[]
    for c in CONSUMERS:
        missing=[r for r in c['requires'] if r not in have]
        consumers.append({'id':c['id'],'class':c['class'],'status':'satisfied' if not missing else 'blocked','missing':missing})
    blocked=[c['id'] for c in consumers if c['status']=='blocked']
    authoritative=[c['id'] for c in consumers if c['class']==AUTHORITATIVE and c['status']=='blocked']
    return {'ready':not blocked,'declared':sorted(have),'consumers':consumers,'blocked':blocked,
            'blocked_authoritative':authoritative,
            'reason':'' if not blocked else 'Backend does not declare every capability needed by: '+', '.join(blocked)+'.'}
