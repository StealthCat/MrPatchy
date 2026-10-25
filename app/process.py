"""Bound subprocess lifetime and output without buffering unlimited pipe data."""
import os
import selectors
import signal
import subprocess
import time

def bounded(args,timeout=900,env=None,limit=16_000_000):
    process=subprocess.Popen(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env,start_new_session=True)
    output=bytearray();errors=bytearray();selector=selectors.DefaultSelector()
    selector.register(process.stdout,selectors.EVENT_READ,output)
    selector.register(process.stderr,selectors.EVENT_READ,errors)
    deadline=time.monotonic()+timeout
    try:
        while selector.get_map():
            if time.monotonic()>deadline: raise TimeoutError('Operation timed out; verify target state before retrying')
            for key,_ in selector.select(min(.2,max(0,deadline-time.monotonic()))):
                chunk=os.read(key.fileobj.fileno(),65536)
                if not chunk: selector.unregister(key.fileobj);continue
                key.data.extend(chunk)
                if len(output)+len(errors)>limit: raise RuntimeError('Operation output exceeded 16 MB limit')
        process.wait(timeout=max(.1,deadline-time.monotonic()))
        if process.returncode: raise RuntimeError((output+errors)[-16000:].decode(errors='replace'))
        return output.decode(errors='replace'),errors.decode(errors='replace')
    finally:
        if process.poll() is None:
            os.killpg(process.pid,signal.SIGKILL);process.wait()
        selector.close();process.stdout.close();process.stderr.close()
