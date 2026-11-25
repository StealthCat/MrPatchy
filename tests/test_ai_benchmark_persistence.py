"""Persisted timing and assessment coverage for the disposable AI workload."""
from copy import deepcopy
import json
from types import SimpleNamespace

import pytest

from tools.benchmark_ai import (
    BenchmarkAssessmentError, BenchmarkTimingError, FIXTURE_FOLLOW_UP,
    FIXTURE_MODEL, FIXTURE_RESULT, assessment_coverage, collect_persisted_timings,
)


RESULT = 'result_persistence'
EVIDENCE = 'evidence_persistence'
EXPECTED = {RESULT: {'one', 'two'}, EVIDENCE: {'two'}}


def event(run_id, stage=RESULT, *, message=None, outcome='complete'):
    return SimpleNamespace(
        run_id=run_id,
        stage=f'timing_{stage}',
        message=message if message is not None else
        f"{stage.replace('_', ' ')}: 0.123 ms; outcome={outcome}",
    )


def test_timings_keep_samples_for_the_matching_runs():
    events = [event('two', EVIDENCE), event('one'), event('two'), event('one', 'provider')]
    assert collect_persisted_timings(events, EXPECTED) == {
        RESULT: [0.123, 0.123], EVIDENCE: [0.123], 'provider': [0.123],
    }
    assert collect_persisted_timings([event('one'), event('two')], {
        RESULT: {'one', 'two'}, EVIDENCE: set(),
    }) == {RESULT: [0.123, 0.123]}


@pytest.mark.parametrize(('events', 'reason'), [
    ([event('two', EVIDENCE), event('one')], 'result_persistence: missing 1 timing'),
    ([event('one'), event('two')], 'evidence_persistence: missing 1 timing'),
    ([event('one'), event('one')], 'result_persistence: duplicate timing'),
    ([event('one', EVIDENCE)], 'evidence_persistence: unexpected timing'),
    ([event('other')], 'result_persistence: unexpected timing'),
    ([event('one', outcome='error')], 'result_persistence: failed timing'),
    ([event('one', message='evidence persistence: 0.123 ms; outcome=complete')],
     'result_persistence: malformed timing'),
    ([event('two', EVIDENCE, message='evidence persistence: NaN ms; outcome=complete')],
     'evidence_persistence: malformed timing'),
    ([event('one', message='result persistence: -0.123 ms; outcome=complete')],
     'result_persistence: malformed timing'),
])
def test_reject_invalid_persistence_evidence(events, reason):
    with pytest.raises(BenchmarkTimingError, match=reason):
        collect_persisted_timings(events, EXPECTED)


def assessment_fixture():
    initial = {'executable': '/fixture/artifact', 'two_stage': True}
    snapshot = {**initial, 'investigation': {'collected': 100, 'details': deepcopy(FIXTURE_FOLLOW_UP)}}
    policy = {'version': 1}
    observation = SimpleNamespace(id='subject', host_id='host', evidence=snapshot)
    run = SimpleNamespace(id='run', subject='subject')
    assessment = SimpleNamespace(
        subject=observation.id, host_id=observation.host_id, run_id=run.id, source='ai',
        model=FIXTURE_MODEL, result=deepcopy(FIXTURE_RESULT), snapshot=deepcopy(snapshot),
        inputs=[{'evidence': deepcopy(evidence), 'policy': policy} for evidence in (initial, snapshot)],
    )
    ai = SimpleNamespace(investigation_policy=lambda: policy, investigation_input=deepcopy)
    return assessment, observation, run, ai


def test_assessment_coverage_rejects_missing_or_duplicate_rows():
    assessment, observation, run, ai = assessment_fixture()
    for rows, reason in (([], 'missing 1 assessment'), ([assessment] * 2, 'duplicate subject')):
        with pytest.raises(BenchmarkAssessmentError, match=reason):
            assessment_coverage(rows, [observation], [run], {'subject'}, ai, [])


@pytest.mark.parametrize(('field', 'value', 'reason'), [
    ('subject', 'other-subject', 'unexpected subject'),
    ('run_id', 'other-run', 'run, host, source or model differs'),
    ('host_id', 'other-host', 'run, host, source or model differs'),
    ('source', 'known_good', 'run, host, source or model differs'),
    ('model', 'other-model', 'run, host, source or model differs'),
    ('result', {'risk': 'low'}, 'final result or evidence snapshot differs'),
    ('snapshot', {}, 'final result or evidence snapshot differs'),
    ('inputs', [], 'retained AI input stages differ'),
])
def test_assessment_coverage_rejects_incorrect_records(field, value, reason):
    assessment, observation, run, ai = assessment_fixture()
    setattr(assessment, field, value)
    with pytest.raises(BenchmarkAssessmentError, match=reason):
        assessment_coverage([assessment], [observation], [run], {'subject'}, ai, [])


def test_assessment_coverage_rejects_missing_follow_up_even_if_both_records_agree():
    assessment, observation, run, ai = assessment_fixture()
    del assessment.snapshot['investigation']
    del observation.evidence['investigation']
    with pytest.raises(BenchmarkAssessmentError, match='expected follow-up evidence is missing'):
        assessment_coverage([assessment], [observation], [run], {'subject'}, ai, [])


def test_assessment_coverage_checks_the_actual_provider_inputs_without_requiring_dispatch_order():
    assessment, observation, run, ai = assessment_fixture()
    requests = [{'input': json.dumps(item['evidence'])} for item in reversed(assessment.inputs)]
    assert assessment_coverage([assessment], [observation], [run], {'subject'}, ai, requests) == {
        'subjects': 1, 'input_stages': 2, 'follow_up_subjects': 1,
    }
    requests[0] = requests[1]
    with pytest.raises(BenchmarkAssessmentError, match='retained evidence differs from provider requests'):
        assessment_coverage([assessment], [observation], [run], {'subject'}, ai, requests)
