"""Drift guard for the managed agent file list and drop-in path (Refs #190).

The list and the observability drop-in path are written out in several modules
that must agree; a path changed in only one copy would silently leave a file
unverified or unrepairable.
"""
import ast
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DROPIN = '/etc/systemd/system/mrpatchy-agent.service.d/observability.conf'


def _literal(path, name):
    tree = ast.parse((ROOT / path).read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in node.targets):
            return ast.literal_eval(node.value)
    raise AssertionError(f'{name} not found in {path}')


class ManagedFilesConsistency(unittest.TestCase):
    def test_bridge_files_match_agent_managed_list(self):
        self.assertEqual(list(_literal('target/bridge.py', 'AGENT_FILES')),
                         list(_literal('target/agent.py', 'MANAGED')))

    def test_dropin_path_agrees_everywhere(self):
        self.assertEqual(_literal('target/bridge.py', 'AGENT_DROPIN'), DROPIN)
        self.assertEqual(_literal('app/agent_maintenance.py', 'OPTIONAL'), DROPIN)
        for path in ('target/agent.py', 'app/worker.py', 'app/ssh.py', 'app/main.py'):
            self.assertIn(DROPIN, (ROOT / path).read_text(), path)


if __name__ == '__main__':
    unittest.main()
