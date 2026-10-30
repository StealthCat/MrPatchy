import os
import signal
import sys
import time
from pathlib import Path
import pytest
from app import process
from target import bridge


@pytest.mark.parametrize('runner',[process.bounded,bridge.bounded])
def test_timeout_kills_descendant_after_parent_exits(tmp_path,runner):
    pidfile=tmp_path/'child.pid'
    script='import os,time,pathlib; pid=os.fork(); pathlib.Path('+repr(str(pidfile))+').write_text(str(pid)) if pid else time.sleep(30)'
    pid=None
    proc_matches_namespace=int(Path('/proc/self/stat').read_text().split()[0])==os.getpid()
    try:
        with pytest.raises(TimeoutError):runner([sys.executable,'-c',script],timeout=.3)
        pid=int(pidfile.read_text())
        deadline=time.monotonic()+2
        while time.monotonic()<deadline:
            try:os.kill(pid,0)
            except ProcessLookupError:break
            # Some nested runtimes expose host procfs with namespace-local syscalls.
            # Never mistake an unrelated host PID for our child in that environment.
            if proc_matches_namespace:
                path=Path('/proc')/str(pid)/'stat'
                try:state=path.read_text().split()[2]
                except FileNotFoundError:break  # Reaped during observation; already exited.
                if state=='Z':break
            time.sleep(.01)
        else:pytest.fail('Descendant survived bounded command timeout')
    finally:
        if pid:
            try:os.kill(pid,signal.SIGKILL)
            except ProcessLookupError:pass
