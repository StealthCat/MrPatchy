import copy
import pytest
from sqlalchemy import select, func
from app import reboot_status, worker
from app.db import Session, InventoryRevision
from target import agent
from test_review_regressions import create_host


def paths(tmp_path):
    return {'flag': tmp_path / 'reboot-required', 'packages': tmp_path / 'reboot-required.pkgs',
            'marker': tmp_path / 'rpm-reboot-required', 'boot': tmp_path / 'boot_id'}


def test_agent_reports_debian_flag_with_bounded_validated_packages(tmp_path):
    p = paths(tmp_path)
    assert agent.reboot_state(**p) == {'required': False, 'packages': [], 'packages_truncated': False}
    p['flag'].write_text('*** System restart required ***\n')
    p['packages'].write_text('linux-image-6.1.0-30-amd64\nlibc6\nlibc6\n../evil\n$(reboot)\n\n')
    assert agent.reboot_state(**p) == {'required': True, 'packages': ['linux-image-6.1.0-30-amd64', 'libc6'],
                                       'packages_truncated': False}
    p['packages'].write_text(''.join('pkg%d\n' % i for i in range(agent.REBOOT_PACKAGE_LIMIT + 5)))
    report = agent.reboot_state(**p)
    assert len(report['packages']) == agent.REBOOT_PACKAGE_LIMIT and report['packages_truncated'] is True


def test_agent_counts_rpm_marker_only_for_the_current_boot(tmp_path):
    p = paths(tmp_path)
    p['boot'].write_text('11111111-2222-3333-4444-555555555555\n')
    p['marker'].write_text('00000000-2222-3333-4444-555555555555')
    assert agent.reboot_state(**p)['required'] is False
    p['marker'].write_text('11111111-2222-3333-4444-555555555555')
    assert agent.reboot_state(**p) == {'required': True, 'packages': [], 'packages_truncated': False}


def test_agent_inventory_includes_reboot_report(monkeypatch):
    monkeypatch.setattr(agent, 'reboot_state', lambda: {'required': True, 'packages': [], 'packages_truncated': False})
    monkeypatch.setattr(agent.Path, 'exists', lambda self: False)
    import target.rpm_support as rpm_support
    monkeypatch.setattr(rpm_support, 'local_inventory', lambda: {'package_manager': 'rpm'})
    assert agent.inventory() == {'package_manager': 'rpm', 'reboot': {'required': True, 'packages': [], 'packages_truncated': False}}


@pytest.mark.parametrize('value', [
    None, 'yes', {'required': 'true', 'packages': [], 'packages_truncated': False},
    {'required': True, 'packages': ['ok', 'bad name'], 'packages_truncated': False},
    {'required': True, 'packages': ['dup', 'dup'], 'packages_truncated': False},
    {'required': True, 'packages': ['p%d' % i for i in range(51)], 'packages_truncated': True},
    {'required': False, 'packages': ['libc6'], 'packages_truncated': False},
    {'required': True, 'packages': [], 'packages_truncated': False, 'extra': 1},
])
def test_controller_treats_malformed_reports_as_not_reported(value):
    inventory = {'collected': 100.0}
    if value is not None:inventory['reboot'] = value
    result = reboot_status.evaluate(inventory)
    assert result['state'] == 'not_reported' and result['packages'] == [] and result['observed'] == 100.0


def test_controller_states():
    assert reboot_status.evaluate(None)['state'] == 'not_reported'
    assert reboot_status.evaluate({'reboot': {'required': False, 'packages': [], 'packages_truncated': False}})['state'] == 'not_required'
    required = reboot_status.evaluate({'collected': 5, 'reboot': {'required': True, 'packages': ['libc6'], 'packages_truncated': True}})
    assert required['state'] == 'required' and required['packages'] == ['libc6'] and required['packages_truncated'] and required['observed'] == 5


def test_reboot_flag_alone_does_not_retain_a_new_inventory_revision(admin):
    with Session() as s:
        h = create_host(s);original = copy.deepcopy(h.inventory)
        worker.save_inventory(s, h, original);h.last_repo = 123;s.commit()
        before = s.scalar(select(func.count()).select_from(InventoryRevision))
        flagged = {**copy.deepcopy(original), 'reboot': {'required': True, 'packages': ['libc6'], 'packages_truncated': False}}
        worker.save_inventory(s, h, flagged);s.commit()
        assert s.scalar(select(func.count()).select_from(InventoryRevision)) == before
        assert h.inventory['reboot']['required'] is True and h.last_repo == 123
        identifier = h.id
    summary = admin.get('/api/hosts/' + identifier + '/summary').json()
    assert summary['reboot']['state'] == 'required' and summary['reboot']['packages'] == ['libc6']
    assert 'inventory' not in summary['host']


def test_summary_reports_not_reported_for_older_agents(admin):
    with Session() as s:
        h = create_host(s);inv = copy.deepcopy(h.inventory);inv.pop('reboot', None);h.inventory = inv;s.commit();identifier = h.id
    assert admin.get('/api/hosts/' + identifier + '/summary').json()['reboot']['state'] == 'not_reported'
