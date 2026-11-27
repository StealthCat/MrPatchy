"""Saved custom paths inside a promoted built-in directory keep their traversal depth (#1645)."""
import time
from pathlib import Path

import pytest

from target import agent


def nested(base, levels):
    path = base
    for index in range(levels):
        path = path / f'd{index}'
    path.mkdir(parents=True)
    return path


@pytest.fixture
def promoted(tmp_path, monkeypatch):
    root = tmp_path / 'promoted.d'
    root.mkdir()
    monkeypatch.setattr(agent, 'PERSISTENCE_ROOTS', (str(root),))
    monkeypatch.setattr(agent, 'PERSISTENCE_FILES', ())
    monkeypatch.setattr(agent, 'PROMOTED_PERSISTENCE_FILES', ())
    monkeypatch.setattr(agent, 'PROMOTED_PERSISTENCE_ROOTS', (str(root),))
    return root


def run(paths):
    return agent.persistence_inventory(time.monotonic() + 30, [str(p) for p in paths])


def observed(result):
    return [r['path'] for r in result['entries']]


def test_saved_deep_directory_keeps_the_depth_it_had_as_a_custom_root(promoted):
    saved = promoted / 'saved'
    deep = nested(saved, agent.SCAN_MAX_DEPTH)
    (deep / 'fixture.conf').write_text('x\n')
    # As its own custom root (before promotion), the saved directory reached the file.
    result = run([saved])
    assert observed(result) == [str(deep / 'fixture.conf')]
    assert result['state'] == 'collected' and result['gaps'] == []


def test_saved_path_below_the_root_depth_limit_is_still_reached(promoted):
    # The saved directory itself sits deeper than the built-in walk reaches from the root.
    saved = nested(promoted, agent.SCAN_MAX_DEPTH + 3)
    (saved / 'fixture.conf').write_text('x\n')
    sibling = saved.parent / 'sibling'
    sibling.mkdir()
    (sibling / 'other.conf').write_text('y\n')
    result = run([saved])
    paths = observed(result)
    assert str(saved / 'fixture.conf') in paths
    # Siblings beyond the built-in limit are not inventoried; the limit is still disclosed for them.
    assert str(sibling / 'other.conf') not in paths
    assert any(gap.startswith(str(sibling) + ':') and 'depth limit' in gap for gap in result['gaps'])


def test_saved_deep_file_is_still_reached(promoted):
    deep = nested(promoted, agent.SCAN_MAX_DEPTH + 2)
    saved = deep / 'fixture.conf'
    saved.write_text('x\n')
    result = run([saved])
    assert str(saved) in observed(result)


def test_unsaved_deep_directories_still_stop_at_the_built_in_limit(promoted):
    deep = nested(promoted, agent.SCAN_MAX_DEPTH + 2)
    (deep / 'fixture.conf').write_text('x\n')
    result = run([])
    assert observed(result) == []
    assert result['state'] == 'incomplete' and any('depth limit' in gap for gap in result['gaps'])


def test_depth_limit_still_applies_below_a_saved_directory(promoted):
    saved = promoted / 'saved'
    deep = nested(saved, agent.SCAN_MAX_DEPTH + 2)
    (deep / 'fixture.conf').write_text('x\n')
    result = run([saved])
    assert observed(result) == []
    assert result['state'] == 'incomplete' and any('depth limit' in gap for gap in result['gaps'])


def test_promoted_entries_are_listed_once(promoted):
    saved = promoted / 'saved'
    inner = nested(saved, 3)
    (inner / 'a.conf').write_text('x\n')
    (promoted / 'top.conf').write_text('y\n')
    result = run([saved, inner / 'a.conf'])
    paths = observed(result)
    assert sorted(paths) == sorted({str(inner / 'a.conf'), str(promoted / 'top.conf')})
    assert result['state'] == 'collected'


def test_ordinary_scans_keep_their_depth_semantics(tmp_path):
    deep = nested(tmp_path, agent.SCAN_MAX_DEPTH + 2)
    (deep / 'f').write_text('x')
    gaps = []
    report = {'entries_examined': 0}
    with agent.scan_root(Path(tmp_path)) as fd:
        found = list(agent.scan_entries(fd, Path(tmp_path), report, time.monotonic() + 30, lambda p, r: gaps.append((str(p), r))))
    assert found == [] and any('depth limit' in reason for _, reason in gaps)
