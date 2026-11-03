from types import SimpleNamespace

from app import worker
from app.db import Session
from target import agent
from test_review_regressions import create_host


def filesystem(**changes):
    values={'f_frsize':4096,'f_bsize':4096,'f_blocks':100,'f_bfree':25,'f_bavail':20,
            'f_files':50,'f_ffree':15,'f_favail':10}
    values.update(changes)
    return SimpleNamespace(**values)


def test_root_filesystem_health_reports_bounded_bytes_and_inodes():
    result=agent.root_filesystem_health(lambda path:filesystem(f_bavail=200,f_favail=100),123.5)
    assert result=={
        'version':1,'collected':123.5,'source':'statvfs','scope':{'kind':'filesystem','path':'/'},'gaps':[],'applicability':'supported',
        'bytes':{'state':'collected','unit':'bytes','total':409600,'available':409600,'used':307200},
        'inodes':{'state':'collected','unit':'inodes','total':50,'available':50,'used':35},
    }


def test_root_filesystem_health_keeps_unsupported_inodes_unknown():
    result=agent.root_filesystem_health(lambda path:filesystem(f_files=0,f_ffree=0,f_favail=0),10)
    assert result['bytes']['state']=='collected'
    assert result['applicability']=='partial'
    assert result['inodes']=={'state':'unknown','unit':'inodes'}
    assert result['gaps']==[{'signal':'inodes','reason':'unsupported'}]


def test_root_filesystem_health_bounds_inode_values_independently():
    result=agent.root_filesystem_health(lambda path:filesystem(f_files=2**64),10)
    assert result['bytes']['state']=='collected' and result['applicability']=='partial'
    assert result['inodes']=={'state':'unknown','unit':'inodes'}
    assert result['gaps']==[{'signal':'inodes','reason':'unavailable-or-malformed'}]


def test_root_filesystem_health_failure_is_unknown_and_redacted():
    def denied(path):raise PermissionError('/secret/device')
    result=agent.root_filesystem_health(denied,10)
    assert result['bytes']=={'state':'unknown','unit':'bytes'}
    assert result['inodes']=={'state':'unknown','unit':'inodes'}
    assert result['applicability']=='unknown'
    assert result['gaps']==[{'signal':'filesystem-capacity','reason':'permission-denied'}]
    assert '/secret' not in str(result)


def test_root_filesystem_health_rejects_malformed_or_oversized_values():
    for value in (filesystem(f_blocks=True),filesystem(f_bavail=-1),filesystem(f_blocks=2**62)):
        result=agent.root_filesystem_health(lambda path,value=value:value,10)
        assert result['bytes']['state']=='unknown' and result['inodes']['state']=='unknown'
        assert result['gaps']==[{'signal':'filesystem-capacity','reason':'unavailable-or-malformed'}]


def test_telemetry_snapshot_composes_device_health_without_mutating_inputs():
    hashes={'/managed':'abc'};metadata={'/managed':{'uid':0,'gid':0,'mode':0o600}};processes=[{'pid':2}];errors=[]
    result=agent.telemetry_snapshot(5,hashes,metadata,processes,errors,lambda:20,lambda path:filesystem())
    assert result['collected']==20 and result['device_health']['collected']==20
    assert result['device_health']['scope']=={'kind':'filesystem','path':'/'}
    assert result['managed'] is hashes and result['managed_metadata'] is metadata
    assert result['processes'] is processes and result['errors'] is errors


def test_telemetry_snapshot_survives_capacity_collection_failure():
    def denied(path):raise PermissionError(path)
    result=agent.telemetry_snapshot(5,{}, {},[],[],lambda:20,denied)
    assert result['collected']==20 and result['device_health']['applicability']=='unknown'
    assert result['device_health']['gaps']==[{'signal':'filesystem-capacity','reason':'permission-denied'}]


def test_controller_ingest_retains_device_health(admin):
    with Session() as session:
        host=create_host(session)
        snapshot=agent.telemetry_snapshot(5,host.baseline,{},[],[],lambda:20,lambda path:filesystem())
        worker.ingest(session,host,{'telemetry':snapshot})
        assert host.telemetry['device_health']==snapshot['device_health']
