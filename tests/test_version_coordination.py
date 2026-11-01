"""Exercise development and integration gates against real Git history."""
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from tools import check_version


class VersionCoordinationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / "app").mkdir()
        (self.root / "README.md").write_text("# Project\n\nFeature and installation documentation.\n")
        self.source("1.17.0")
        self.history = "## 1.17.0 — 2026-10-30\n\n1. Existing change.\n"
        self.log("# Changelog\n\n" + self.history)
        self.git("init", "-q")
        self.git("add", ".")
        self.git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                 "commit", "-qm", "Initial fixture")
        self.base = self.git("rev-parse", "HEAD").strip()
        self.root_patch = patch.object(check_version, "ROOT", self.root)
        self.root_patch.start()
        self.addCleanup(self.root_patch.stop)

    def git(self, *arguments):
        return subprocess.check_output(["git", *arguments], cwd=self.root, text=True)

    def source(self, value):
        (self.root / "app/main.py").write_text(
            f"APP_VERSION={value!r}\napp=FastAPI(version=APP_VERSION)\n"
            "def health():\n    return {'version':APP_VERSION}\n")

    def log(self, text):
        (self.root / "CHANGELOG.md").write_text(text)

    def release(self, number=220, value="1.17.1"):
        self.source(value)
        self.log(f"# Changelog\n\n## {value} — 2026-10-31\n\n"
                 f"1. [PR #{number}](https://github.com/StealthCat/MrPatchy/pull/{number}): change.\n\n"
                 + self.history)

    def test_readme_is_not_version_metadata(self):
        (self.root / "README.md").unlink()
        self.assertEqual(check_version.check(), "1.17.0")

    def test_worker_readme_edits_are_reserved_for_the_coordinator(self):
        (self.root / "README.md").write_text("# Project\n\nWorker feature notes.\n")
        with self.assertRaisesRegex(ValueError, "README.md"):
            check_version.check(self.base, allow_unversioned=True)

    def test_coordinator_can_update_readme_with_release_metadata(self):
        self.release()
        (self.root / "README.md").write_text("# Project\n\nCoordinator feature documentation.\n")
        self.assertEqual(check_version.check(self.base, pr_number=220), "1.17.1")

    def test_worker_changes_do_not_need_a_release_version(self):
        with (self.root / "app/main.py").open("a") as stream:
            stream.write("\nFEATURE = True\n")
        self.assertEqual(check_version.check(self.base, allow_unversioned=True), "1.17.0")
        with self.assertRaisesRegex(ValueError, "increase"):
            check_version.check(self.base)

    def test_worker_cannot_change_the_shared_changelog_without_a_bump(self):
        self.log("# Changelog\n\n" + self.history.replace("Existing", "Rewritten"))
        with self.assertRaisesRegex(ValueError, "changelog"):
            check_version.check(self.base, allow_unversioned=True)

    def test_development_mode_needs_a_base(self):
        with self.assertRaisesRegex(ValueError, "base"):
            check_version.check(allow_unversioned=True)

    def test_decreasing_version_fails_even_in_development_mode(self):
        self.release(value="1.16.99")
        with self.assertRaisesRegex(ValueError, "increase"):
            check_version.check(self.base, allow_unversioned=True)

    def test_coordinator_release_is_bound_to_its_pr(self):
        self.release()
        self.assertEqual(check_version.check(self.base, pr_number=220), "1.17.1")
        with self.assertRaisesRegex(ValueError, "PR #221"):
            check_version.check(self.base, pr_number=221)

    def test_pr_link_in_old_history_does_not_validate_the_new_entry(self):
        self.history = self.history.replace("Existing change.", "[PR #220](https://github.com/StealthCat/MrPatchy/pull/220): existing change.")
        self.log("# Changelog\n\n" + self.history)
        self.git("add", ".")
        self.git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                 "commit", "-qm", "Existing linked history")
        self.base = self.git("rev-parse", "HEAD").strip()
        self.release(number=221)
        with self.assertRaisesRegex(ValueError, "PR #220"):
            check_version.check(self.base, pr_number=220)

    def test_past_changelog_entries_are_preserved_at_integration(self):
        self.release()
        self.log((self.root / "CHANGELOG.md").read_text().replace("Existing", "Rewritten"))
        with self.assertRaisesRegex(ValueError, "histor"):
            check_version.check(self.base, pr_number=220)

    def test_empty_new_entry_does_not_borrow_a_list_from_old_history(self):
        self.release()
        self.log("# Changelog\n\n## 1.17.1 — 2026-10-31\n\n" + self.history)
        with self.assertRaisesRegex(ValueError, "entry"):
            check_version.check(self.base)

    def test_malformed_authority_does_not_fall_back_to_an_api_literal(self):
        (self.root / "app/main.py").write_text("APP_VERSION='invalid'\napp=FastAPI(version='1.17.0')\n")
        with self.assertRaisesRegex(ValueError, "source version"):
            check_version.check()

    def test_missing_changelog_is_a_clear_validation_failure(self):
        self.log("# Changelog\n")
        with self.assertRaisesRegex(ValueError, "changelog"):
            check_version.check()

    def test_pr_gate_cannot_be_combined_with_development_mode(self):
        with self.assertRaisesRegex(ValueError, "integration"):
            check_version.check(self.base, allow_unversioned=True, pr_number=220)
