import re
from pathlib import Path


ROOT = Path(__file__).parents[1]
WORKFLOW = ROOT / '.github' / 'workflows' / 'codeql.yml'


def source():
    return WORKFLOW.read_text()


def test_codeql_scans_python_on_changes_and_weekly():
    text = source()
    assert re.search(r'^  push:\n    branches: \[main\]$', text, re.M)
    assert re.search(r'^  pull_request:\n    branches: \[main\]$', text, re.M)
    schedule = re.search(r"^    - cron: '([^']+)'$", text, re.M)
    assert schedule and schedule.group(1).split()[-1] not in ('*', '')
    assert re.search(r'^          languages: python$', text, re.M)
    assert re.search(r'^          queries: security-extended$', text, re.M)
    assert re.search(r'^          category: /language:python$', text, re.M)


def test_codeql_actions_are_sha_pinned_and_permissions_are_bounded():
    text = source()
    actions = re.findall(r'^\s*-?\s*uses: ([^\s]+)(?:\s+#\s*(\S+))?$', text, re.M)
    assert [name.split('@')[0] for name, _ in actions] == [
        'actions/checkout', 'github/codeql-action/init', 'github/codeql-action/analyze']
    for name, version in actions:
        assert re.fullmatch(r'[^@]+@[0-9a-f]{40}', name)
        assert version
    assert text.count('security-events: write') == 1
    assert not re.search(r'^\s+(?!security-events:)[\w-]+: write$', text, re.M)
    assert re.search(r'^    timeout-minutes: (?:[1-2]?\d|30)$', text, re.M)
