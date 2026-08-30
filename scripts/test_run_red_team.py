import copy
from pathlib import Path
import tempfile
import unittest

from scripts import run_red_team


class RedTeamRunnerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.repository_root = Path(__file__).resolve().parent.parent
        cls.suite_path = cls.repository_root / "examples/redteam/suite-v1.json"

    def test_repository_suite_is_complete_and_plannable(self):
        document = run_red_team.load_suite(self.suite_path)
        plan = run_red_team.validate_suite(document, self.repository_root)
        self.assertEqual(set(run_red_team.CATEGORIES), {scenario["category"] for scenario in document["scenarios"]})
        self.assertIn("internal/rollout", plan)
        self.assertIn("pkg/palisadehttp", plan)

    def test_unknown_scenario_field_is_rejected(self):
        document = copy.deepcopy(run_red_team.load_suite(self.suite_path))
        document["scenarios"][0]["raw_target"] = "https://example.invalid/private"
        with self.assertRaisesRegex(run_red_team.SuiteError, "fields are not closed"):
            run_red_team.validate_suite(document, self.repository_root)

    def test_path_escape_is_rejected(self):
        document = copy.deepcopy(run_red_team.load_suite(self.suite_path))
        document["scenarios"][0]["test_refs"] = ["../outside_test.go#TestEscape"]
        with self.assertRaisesRegex(run_red_team.SuiteError, "unsafe test reference"):
            run_red_team.validate_suite(document, self.repository_root)

    def test_missing_test_function_is_rejected(self):
        document = copy.deepcopy(run_red_team.load_suite(self.suite_path))
        document["scenarios"][0]["test_refs"] = ["internal/detector/baseline_test.go#TestRemovedControl"]
        with self.assertRaisesRegex(run_red_team.SuiteError, "function does not exist"):
            run_red_team.validate_suite(document, self.repository_root)

    def test_non_text_test_reference_is_rejected_cleanly(self):
        document = copy.deepcopy(run_red_team.load_suite(self.suite_path))
        document["scenarios"][0]["test_refs"] = [{"path": "raw"}]
        with self.assertRaisesRegex(run_red_team.SuiteError, "not text"):
            run_red_team.validate_suite(document, self.repository_root)

    def test_duplicate_json_key_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "suite.json"
            path.write_text('{"schema_version":"one","schema_version":"two"}', encoding="utf-8")
            with self.assertRaisesRegex(run_red_team.SuiteError, "duplicate JSON key"):
                run_red_team.load_suite(path)

    def test_symlink_suite_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            link = Path(directory) / "suite.json"
            link.symlink_to(self.suite_path)
            with self.assertRaisesRegex(run_red_team.SuiteError, "non-symlink"):
                run_red_team.load_suite(link)


if __name__ == "__main__":
    unittest.main()
