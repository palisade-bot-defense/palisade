from pathlib import Path
import os
import tempfile
import unittest
from unittest import mock

from scripts import operator_shadow_drill


class OperatorShadowDrillTests(unittest.TestCase):
    def valid_decision(self):
        return {
            "decision_id": "synthetic-decision-0001",
            "action": "observe",
            "computed_action": "block",
            "mode": "shadow",
            "reason_codes": ["MULTI_SOURCE_ABUSE", "SHADOW_ACTION_OVERRIDDEN"],
        }

    def valid_summary(self):
        return {
            "schema_version": "palisade.admin-summary.v10",
            "runtime": {"mode": "shadow"},
            "capabilities": {"shadow_log": True},
            "traffic": {"decisions": 1},
            "recording": {"decisions": 1, "outcomes": 1, "dropped": 0},
        }

    def valid_analysis(self):
        return {
            "schema_version": "palisade.shadow-analysis.v5",
            "source": {"records": 3, "decisions": 2, "outcomes": 1},
            "readiness": {"automatic_enforcement": False, "operator_action": "remain_shadow"},
            "decisions": {"shadow_risky_enforcements": 0, "modes": {"shadow": 2}},
        }

    def test_closed_safety_snapshots_are_accepted(self):
        operator_shadow_drill.validate_decision(self.valid_decision())
        operator_shadow_drill.validate_admin_summary(self.valid_summary(), 1, 1)
        operator_shadow_drill.validate_analysis(self.valid_analysis())

    def test_risky_action_enforcement_is_rejected(self):
        decision = self.valid_decision()
        decision["action"] = "block"
        with self.assertRaisesRegex(operator_shadow_drill.DrillError, "shadow boundary"):
            operator_shadow_drill.validate_decision(decision)

    def test_missing_shadow_override_reason_is_rejected(self):
        decision = self.valid_decision()
        decision["reason_codes"] = ["MULTI_SOURCE_ABUSE"]
        with self.assertRaisesRegex(operator_shadow_drill.DrillError, "explain"):
            operator_shadow_drill.validate_decision(decision)

    def test_admin_rollout_authority_is_rejected(self):
        summary = self.valid_summary()
        summary["runtime"]["rollout_id"] = "unexpected-canary"
        with self.assertRaisesRegex(operator_shadow_drill.DrillError, "unprivileged shadow"):
            operator_shadow_drill.validate_admin_summary(summary, 1, 1)

    def test_dropped_record_is_rejected(self):
        summary = self.valid_summary()
        summary["recording"]["dropped"] = 1
        with self.assertRaisesRegex(operator_shadow_drill.DrillError, "recording counters"):
            operator_shadow_drill.validate_admin_summary(summary, 1, 1)

    def test_analysis_cannot_authorize_enforcement(self):
        analysis = self.valid_analysis()
        analysis["readiness"]["automatic_enforcement"] = True
        with self.assertRaisesRegex(operator_shadow_drill.DrillError, "authorize enforcement"):
            operator_shadow_drill.validate_analysis(analysis)

    def test_symlink_binary_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "palisade"
            target.write_text("synthetic\n", encoding="utf-8")
            target.chmod(0o700)
            link = Path(directory) / "linked"
            link.symlink_to(target)
            with self.assertRaisesRegex(operator_shadow_drill.DrillError, "non-symlink"):
                operator_shadow_drill._validate_binary(link)

    def test_subprocess_environment_does_not_inherit_unrelated_secrets(self):
        with mock.patch.dict(os.environ, {"AWS_SECRET_ACCESS_KEY": "synthetic-secret"}, clear=False):
            environment = operator_shadow_drill._base_environment()
        self.assertNotIn("AWS_SECRET_ACCESS_KEY", environment)
        self.assertIn("PATH", environment)


if __name__ == "__main__":
    unittest.main()
