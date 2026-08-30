import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from scripts import red_team_findings
from scripts import run_red_team


class RedTeamFindingsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.repository_root = Path(__file__).resolve().parent.parent
        cls.suite = run_red_team.load_suite(cls.repository_root / "examples/redteam/suite-v1.json")

    def valid_report(self):
        commit = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=self.repository_root,
            check=True,
            stdout=subprocess.PIPE,
            text=True,
            encoding="utf-8",
        ).stdout.strip()
        return {
            "schema_version": red_team_findings.SCHEMA_VERSION,
            "suite_version": red_team_findings.SUITE_VERSION,
            "source_commit": commit,
            "suite_sha256": red_team_findings.suite_digest(
                self.repository_root / "examples/redteam/suite-v1.json"
            ),
            "synthetic_only": True,
            "raw_deployment_records_used": False,
            "protocol": dict(red_team_findings.PROTOCOL),
            "environment": {"go_version": "go1.27.0", "goos": "linux", "goarch": "arm64"},
            "summary": {"passed": 12, "failed": 0, "remediations_open": 0},
            "findings": [
                {
                    "id": scenario["id"],
                    "category": scenario["category"],
                    "asset": scenario["asset"],
                    "expected": scenario["expected"],
                    "status": "passed",
                    "remediation_status": "not_required",
                    "test_refs": scenario["test_refs"],
                }
                for scenario in self.suite["scenarios"]
            ],
            "limitations": list(red_team_findings.LIMITATIONS),
        }

    def test_valid_closed_report_is_accepted(self):
        red_team_findings.validate_report(self.valid_report(), self.repository_root)

    def test_changed_scenario_result_is_rejected(self):
        report = self.valid_report()
        report["findings"][0]["status"] = "failed"
        with self.assertRaisesRegex(red_team_findings.FindingsError, "passed scenario contract"):
            red_team_findings.validate_report(report, self.repository_root)

    def test_removed_limitation_is_rejected(self):
        report = self.valid_report()
        report["limitations"].pop()
        with self.assertRaisesRegex(red_team_findings.FindingsError, "limitations"):
            red_team_findings.validate_report(report, self.repository_root)

    def test_suite_hash_mismatch_is_rejected(self):
        report = self.valid_report()
        report["suite_sha256"] = "0" * 64
        with self.assertRaisesRegex(red_team_findings.FindingsError, "suite digest"):
            red_team_findings.validate_report(report, self.repository_root)

    def test_boolean_protocol_count_is_rejected(self):
        report = self.valid_report()
        report["protocol"]["scenario_count"] = True
        with self.assertRaisesRegex(red_team_findings.FindingsError, "protocol"):
            red_team_findings.validate_report(report, self.repository_root)

    def test_boolean_summary_zero_is_rejected(self):
        report = self.valid_report()
        report["summary"]["failed"] = False
        with self.assertRaisesRegex(red_team_findings.FindingsError, "summary"):
            red_team_findings.validate_report(report, self.repository_root)

    def test_duplicate_report_key_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            path.write_text('{"schema_version":"one","schema_version":"two"}', encoding="utf-8")
            with self.assertRaisesRegex(red_team_findings.FindingsError, "duplicate JSON key"):
                red_team_findings.load_report(path)

    def test_create_only_report_is_owner_only(self):
        report = self.valid_report()
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            parent.chmod(0o700)
            output = parent / "findings.json"
            red_team_findings.write_report_create_only(output, report)
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            self.assertEqual(json.loads(output.read_text(encoding="utf-8")), report)
            with self.assertRaisesRegex(red_team_findings.FindingsError, "must not already exist"):
                red_team_findings.write_report_create_only(output, report)

    def test_report_is_rejected_inside_git_worktree(self):
        report = self.valid_report()
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            parent.chmod(0o700)
            subprocess.run(["git", "init", "-q", str(parent)], check=True)
            with self.assertRaisesRegex(red_team_findings.FindingsError, "outside every Git worktree"):
                red_team_findings.write_report_create_only(parent / "findings.json", report)

    def test_concurrent_creator_is_not_deleted(self):
        report = self.valid_report()
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            parent.chmod(0o700)
            output = parent / "findings.json"

            def create_competing_output(_source, target, **_kwargs):
                Path(target).write_text("operator-owned\n", encoding="utf-8")
                raise FileExistsError("synthetic publication race")

            with mock.patch.object(red_team_findings.os, "link", side_effect=create_competing_output):
                with self.assertRaisesRegex(red_team_findings.FindingsError, "cannot publish"):
                    red_team_findings.write_report_create_only(output, report)
            self.assertEqual(output.read_text(encoding="utf-8"), "operator-owned\n")

    def test_build_requires_clean_checkout_before_execution(self):
        with mock.patch.object(
            red_team_findings, "require_clean_commit", side_effect=red_team_findings.FindingsError("dirty")
        ), mock.patch.object(run_red_team, "execute") as execute:
            with self.assertRaisesRegex(red_team_findings.FindingsError, "dirty"):
                red_team_findings.build_report(self.repository_root)
            execute.assert_not_called()


if __name__ == "__main__":
    unittest.main()
