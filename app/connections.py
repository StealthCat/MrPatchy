"""Typed SSH routes. Google IAP transports bytes, never installs SSH keys."""
import os
import select
import shutil
import socket
import subprocess
import time
from typing import Literal
from pydantic import BaseModel, Field, model_validator
from .db import Session, Setting

class Connection(BaseModel):
    address: str = Field(min_length=1, max_length=253, pattern=r'^[A-Za-z0-9:.\-]+$')
    port: int = Field(default=22, ge=1, le=65535)
    transport: Literal['direct', 'gcp_iap'] = 'direct'
    project: str = Field(default='', max_length=63, pattern=r'^[a-z0-9-]*$')
    zone: str = Field(default='', max_length=63, pattern=r'^[a-z0-9-]*$')
    instance: str = Field(default='', max_length=63, pattern=r'^[a-z0-9-]*$')

    @model_validator(mode='after')
    def check_iap(self):
        if self.transport == 'gcp_iap':
            if not all(value and value[0].isalnum() and value[-1].isalnum()
                       for value in (self.project, self.zone, self.instance)):
                raise ValueError('IAP requires a project ID, zone and instance name')
        return self

def saved(s, host):
    row = s.get(Setting, 'connection:' + host.id)
    return Connection(**{**(row.value if row else {}), 'address': host.address, 'port': host.port})

def for_host(host):
    with Session() as s:
        return saved(s, host)

class IAPSocket:
    """Bounded, shell-free gcloud stdio transport with deterministic child cleanup."""
    def __init__(self, connection, deadline):
        executable = shutil.which('gcloud')
        if not executable:
            raise RuntimeError('Google IAP requires gcloud in the Mr Patchy runtime. Install the Google Cloud CLI and configure its runtime identity; see docs/GCP.md.')
        self.deadline = deadline
        self.timeout = 15
        self.closed = False
        self.process = subprocess.Popen([
            executable, 'compute', 'start-iap-tunnel', connection.instance, str(connection.port),
            '--listen-on-stdin', '--project=' + connection.project, '--zone=' + connection.zone,
            '--quiet', '--verbosity=error'], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, bufsize=0,
            env={**os.environ, 'CLOUDSDK_CORE_DISABLE_PROMPTS': '1'})
        os.set_blocking(self.process.stdin.fileno(), False)
        os.set_blocking(self.process.stdout.fileno(), False)

    def settimeout(self, timeout):
        self.timeout = timeout

    def _wait(self, stream, writing=False):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise socket.timeout('IAP operation exceeded its total deadline')
        timeout = min(remaining, self.timeout) if self.timeout is not None else remaining
        readers, writers, _ = select.select([] if writing else [stream], [stream] if writing else [], [], timeout)
        if not readers and not writers:
            raise socket.timeout('IAP transport timed out')

    def send(self, data):
        self._wait(self.process.stdin, writing=True)
        return os.write(self.process.stdin.fileno(), data)

    def recv(self, size):
        self._wait(self.process.stdout)
        return os.read(self.process.stdout.fileno(), size)

    @property
    def _closed(self):
        return self.closed

    def close(self):
        if self.closed:
            return
        self.closed = True
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.process.kill()
        self.process.wait()
        self.process.stdin.close()
        self.process.stdout.close()
