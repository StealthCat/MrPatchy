"""Roadmap B: cross-server exact known-good hits and contextual misses (#1035).

These acceptance tests drive the real ``worker.investigate_one()`` path end to
end. Server A's fresh provider result publishes the fleet candidate, and server
B either reuses it with zero provider calls or reaches the provider when any
security-relevant context differs. Only the provider transport is a fixture.
The canonical fingerprint contract itself is unit-tested in
``tests/test_known_good.py``.
"""
import copy
import json
import threading
from concurrent.futures import ThreadPoolExecutor

import httpx
import pytest
from sqlalchemy import select

from app import ai, ai_assessments, ai_budget, ai_runs, known_good, worker
from app.db import Behavior, Host, Session, Setting
from app.security import seal

MODEL = 'gpt-6-astra'
USAGE = {'input_tokens': 1000, 'output_tokens': 200, 'total_tokens': 1200,
         'input_tokens_details': {'cached_tokens': 0, 'cache_write_tokens': 0},
         'output_tokens_details': {'reasoning_tokens': 100}}


def sha(letter):
    return letter * 64


def evidence(host, pid=10, sha256=sha('a'), privileges=sha('1'), network=sha('3')):
    """Complete, verified known-good context for one observation on ``host``."""
    return {
        'executable': '/usr/bin/fixture', 'sha256': sha256, 'identity_verified': True,
        'host_id': host, 'observed': 100,
        'investigation': {'details': {
            'version': 2, 'identity_verified': True,
            'context': {'version': 1, 'process': {'pid': pid, 'start_ticks': pid + 10},
                'coverage': {'scope': 'recorded_process_identity', 'gaps': []}},
            'known_good_context': {
                'version': 1,
                'artifact': {'version': 1, 'verified': True, 'path': '/usr/bin/fixture',
                    'sha256': sha256, 'manifest_sha256': sha('b'), 'kind': 'elf'},
                'provenance': {'version': 1, 'verified': True, 'scheme': 'vendor-signature',
                    'subject': 'fixture-package', 'release': '1.0-1',
                    'manifest_sha256': sha('c'), 'proof_sha256': sha('d')},
                'configuration': {'version': 1, 'complete': True, 'manifest_sha256': sha('e')},
                'behavior': {'version': 1, 'complete': True, 'manifest_sha256': sha('f'),
                    'privileges_sha256': privileges, 'startup_sha256': sha('2'),
                    'network_sha256': network, 'execution_sha256': sha('4'),
                    'memory_sha256': sha('5')},
                'followup': {'version': 1, 'complete': True, 'requirements_sha256': sha('6'),
                    'evidence_sha256': sha('7'), 'policy_version': 'process-followup-v1'},
                'coverage': {'version': 1, 'complete': True, 'manifest_sha256': sha('8'), 'gaps': []},
                'observation': {'host_id': host, 'pid': pid, 'start_ticks': pid + 10,
                    'collected': 100 + pid, 'ephemeral_source_ports': [49152 + pid]},
            },
        }},
    }


class Provider:
    """Record each transmitted request and answer with the configured verdict."""

    def __init__(self, risk='low', barrier=None):
        self.risk, self.barrier = risk, barrier
        self.inputs = []
        self.guard = threading.Lock()

    def __call__(self, *args, **kwargs):
        with self.guard:
            self.inputs.append(json.loads(kwargs['json']['input']))
        if self.barrier:
            self.barrier.wait(timeout=15)
        data = {'risk': self.risk, 'explanation': 'Fresh provider result',
                'recommended_checks': 'Continue deterministic monitoring', 'requested_checks': []}
        response = {'model': MODEL, 'service_tier': 'default', 'status': 'completed', 'usage': USAGE,
                    'output': [{'content': [{'type': 'output_text', 'text': json.dumps(data)}]}]}
        return httpx.Response(200, json=response, request=httpx.Request('POST', ai.URL))


def configure(capped=False):
    value = {'ai_enabled': True, 'ai_model': MODEL, 'ai_hourly_limit': 50, 'ai_updates_enabled': False}
    if capped:
        value.update(ai_control_mode='daily_cap', ai_daily_cap_usd=5.0, ai_budget_timezone='UTC')
    with Session() as s:
        s.merge(Setting(key='config', value=value))
        s.merge(Setting(key='openai_key', value={'encrypted': seal('private-key')}))
        s.commit()


def observe(host, subject, snapshot):
    with Session() as s:
        if s.get(Host, host) is None:
            s.add(Host(id=host, name=host, address='192.0.2.1', fingerprint=''))
        s.add(Behavior(id=subject, host_id=host, evidence=snapshot, verdict='pending'))
        s.commit()


def drain():
    for _ in range(10):
        with Session() as s:
            if not s.scalar(select(Behavior.id).where(Behavior.verdict == 'pending')):
                return
        worker.investigate_one()
    pytest.fail('triage did not drain')


def outcome(subject):
    with Session() as s:
        behavior = s.get(Behavior, subject)
        saved = list(s.scalars(select(ai_assessments.Assessment).where(
            ai_assessments.Assessment.subject == subject)))
        runs = list(s.scalars(select(ai_runs.AIRun).where(ai_runs.AIRun.subject == subject)))
        return {
            'verdict': behavior.verdict,
            'sources': [row.source for row in saved],
            'reused': [row.result.get('known_good_reuse', {}).get('fingerprint') for row in saved],
            'calls': [row.calls for row in runs],
            'entries': [(row.fingerprint, row.active) for row in s.scalars(select(known_good.Entry))],
            'observations': sorted(row.host_id for row in s.scalars(select(known_good.Observation))),
            'ledger': len(list(s.scalars(select(ai_budget.BudgetEntry)))),
        }


def publish_from_server_a(provider):
    """Server A's fresh low result publishes exactly one active fleet candidate."""
    observe('host-a', 'behavior-a', evidence('host-a'))
    drain()
    first = outcome('behavior-a')
    assert len(provider.inputs) == 1
    assert first['verdict'] == 'low' and first['sources'] == ['ai'] and first['calls'] == [1]
    assert len(first['entries']) == 1 and first['entries'][0][1] is True
    return first['entries'][0][0]


@pytest.mark.parametrize('capped', [False, True], ids=['rate', 'daily-cap'])
def test_exact_match_on_another_server_reuses_with_zero_provider_calls(client, monkeypatch, capped):
    configure(capped)
    provider = Provider()
    monkeypatch.setattr(ai.transport, 'post', provider)
    fingerprint = publish_from_server_a(provider)
    ledger = outcome('behavior-a')['ledger']
    assert ledger == (1 if capped else 0)

    # Only observation fields differ: host, PID, start ticks and ephemeral port.
    observe('host-b', 'behavior-b', evidence('host-b', pid=77))
    drain()
    hit = outcome('behavior-b')
    assert len(provider.inputs) == 1, 'an exact cross-server hit must not call the provider'
    assert hit['verdict'] == 'low' and hit['sources'] == ['known_good']
    assert hit['reused'] == [fingerprint] and hit['calls'] == [0]
    assert hit['entries'] == [(fingerprint, True)]
    assert hit['observations'] == ['host-a', 'host-b']
    # No spend reservation is made for a cache hit.
    assert hit['ledger'] == ledger


@pytest.mark.parametrize('changed', [
    pytest.param({'sha256': sha('9')}, id='same-path-different-hash'),
    pytest.param({'privileges': sha('0')}, id='same-hash-different-account'),
    pytest.param({'network': sha('0')}, id='same-hash-different-behavior'),
])
def test_contextual_difference_on_another_server_is_a_miss(client, monkeypatch, changed):
    configure()
    provider = Provider()
    monkeypatch.setattr(ai.transport, 'post', provider)
    fingerprint = publish_from_server_a(provider)

    observe('host-b', 'behavior-b', evidence('host-b', pid=77, **changed))
    drain()
    missed = outcome('behavior-b')
    assert len(provider.inputs) == 2, 'a contextual difference must reach the provider'
    assert provider.inputs[1] != provider.inputs[0]
    assert missed['sources'] == ['ai'] and missed['reused'] == [None] and missed['calls'] == [1]
    # The fresh safe result publishes its own distinct candidate; A's entry is untouched.
    assert (fingerprint, True) in missed['entries'] and len(missed['entries']) == 2


@pytest.mark.parametrize('risk', ['medium', 'unknown'])
def test_non_safe_result_publishes_nothing_so_the_next_server_still_calls(client, monkeypatch, risk):
    configure()
    provider = Provider(risk)
    monkeypatch.setattr(ai.transport, 'post', provider)
    observe('host-a', 'behavior-a', evidence('host-a'))
    drain()
    assert outcome('behavior-a')['entries'] == []

    observe('host-b', 'behavior-b', evidence('host-b', pid=77))
    drain()
    second = outcome('behavior-b')
    assert len(provider.inputs) == 2
    assert second['verdict'] == risk and second['sources'] == ['ai'] and second['entries'] == []


def test_revoked_candidate_is_not_reused_on_another_server(client, monkeypatch):
    configure()
    provider = Provider()
    monkeypatch.setattr(ai.transport, 'post', provider)
    fingerprint = publish_from_server_a(provider)
    with Session() as s:
        entry = s.scalar(select(known_good.Entry))
        entry.active = False
        s.commit()

    observe('host-b', 'behavior-b', evidence('host-b', pid=77))
    drain()
    missed = outcome('behavior-b')
    assert len(provider.inputs) == 2
    assert missed['sources'] == ['ai'] and missed['reused'] == [None]
    # A revoked candidate is never reactivated by a later matching assessment.
    assert missed['entries'] == [(fingerprint, False)]


def test_concurrent_first_encounters_publish_one_candidate_then_a_third_server_hits(client, monkeypatch):
    configure()
    # Both first encounters are in flight at the provider at the same time.
    provider = Provider(barrier=threading.Barrier(2))
    monkeypatch.setattr(ai.transport, 'post', provider)
    observe('host-a', 'behavior-a', evidence('host-a', pid=11))
    observe('host-b', 'behavior-b', evidence('host-b', pid=22))
    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(lambda _: worker.investigate_one(), range(2)))
    assert len(provider.inputs) == 2
    first, second = outcome('behavior-a'), outcome('behavior-b')
    assert first['sources'] == second['sources'] == ['ai']
    assert len(first['entries']) == 1 and first['entries'][0][1] is True
    assert first['observations'] == ['host-a', 'host-b']
    fingerprint = first['entries'][0][0]

    provider.barrier = None
    observe('host-c', 'behavior-c', evidence('host-c', pid=33))
    drain()
    third = outcome('behavior-c')
    assert len(provider.inputs) == 2
    assert third['sources'] == ['known_good'] and third['reused'] == [fingerprint] and third['calls'] == [0]
    assert third['observations'] == ['host-a', 'host-b', 'host-c']


def test_reused_assessment_keeps_its_own_server_observation(client, monkeypatch):
    configure()
    provider = Provider()
    monkeypatch.setattr(ai.transport, 'post', provider)
    publish_from_server_a(provider)
    snapshot = evidence('host-b', pid=77)
    observe('host-b', 'behavior-b', copy.deepcopy(snapshot))
    drain()
    with Session() as s:
        saved = s.scalar(select(ai_assessments.Assessment).where(
            ai_assessments.Assessment.subject == 'behavior-b'))
        observation = s.get(known_good.Observation, saved.id)
        assert saved.host_id == 'host-b' and observation.host_id == 'host-b'
        local = saved.snapshot['investigation']['details']['known_good_context']['observation']
        assert local['host_id'] == 'host-b' and local['pid'] == 77
