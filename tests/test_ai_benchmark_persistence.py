"""Persisted timing coverage for the disposable AI workload."""
from types import SimpleNamespace

import pytest

from tools.benchmark_ai import BenchmarkTimingError, collect_persisted_timings


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
