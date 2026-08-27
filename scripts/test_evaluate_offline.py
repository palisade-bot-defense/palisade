#!/usr/bin/env python3

import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("evaluate_offline.py")
SPEC = importlib.util.spec_from_file_location("evaluate_offline", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class OfflineEvaluationTest(unittest.TestCase):
    def test_candidate_rules(self):
        window = {
            "count": 100,
            "first": 0.0,
            "last": 30.0,
            "errors": 50,
            "compare": 50,
        }
        self.assertTrue(all(MODULE.candidate_rules(window).values()))

    def test_evaluation_keeps_unknown_separate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "COMPLETE").write_text("palisade.offline-manifest.v1\n")
            events = [
                self.event("2026-01-01T00:00:00Z", "weak-subject", "weak-session"),
                self.event("2026-01-01T00:00:01Z", "unknown-subject", "unknown-session"),
                {
                    **self.event("2026-01-01T00:00:02Z", "weak-subject", ""),
                    "source": "crowdsec_alert",
                    "session_id": "",
                },
            ]
            shard = root / "events-000001.jsonl"
            with shard.open("w", encoding="utf-8") as handle:
                for event in events:
                    handle.write(json.dumps(event) + "\n")
            manifest = {
                "schema_version": "palisade.offline-manifest.v1",
                "provenance": "offline_export",
                "shards": [{"filename": shard.name}],
            }
            (root / "manifest.json").write_text(json.dumps(manifest))
            report = MODULE.evaluate(root)
            metrics = report["metrics"]["all"]
            self.assertEqual(metrics["weak_windows"], 1)
            self.assertEqual(metrics["unknown_windows"], 1)
            self.assertFalse(report["label_contract"]["ground_truth_available"])
            self.assertIn("unknown traffic is not a confirmed-human cohort", report["limitations"])

    def test_report_is_private_and_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            MODULE.write_report(path, {"schema_version": MODULE.SCHEMA})
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
            with self.assertRaises(ValueError):
                MODULE.write_report(path, {})

    def test_derived_evidence_keeps_labels_honest_and_emits_only_aggregates(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            clients = root / "client-features.jsonl"
            outcomes = root / "challenge-outcomes.jsonl"
            client_rows = [
                {
                    "ip": "192.0.2.1",
                    "user_agent": "Synthetic Browser",
                    "label": "human_confirmed",
                    "content_pages": 2,
                    "compare_pages": 0,
                    "gap_cv": 1.0,
                },
                {
                    "ip": "192.0.2.2",
                    "user_agent": "Synthetic Browser",
                    "label": "campaign_signature",
                    "content_pages": 5,
                    "compare_pages": 4,
                    "gap_cv": 4.0,
                },
                {
                    "ip": "192.0.2.3",
                    "user_agent": "Synthetic Other",
                    "label": "unlabeled",
                    "content_pages": 3,
                    "compare_pages": 0,
                    "gap_cv": 2.0,
                },
            ]
            outcome_rows = [
                {"ip": "192.0.2.1", "outcome": "solved"},
                {"ip": "192.0.2.2", "outcome": "solved"},
            ]
            clients.write_text("".join(json.dumps(row) + "\n" for row in client_rows))
            outcomes.write_text("".join(json.dumps(row) + "\n" for row in outcome_rows))
            os.chmod(clients, 0o600)
            os.chmod(outcomes, 0o600)

            report = MODULE.evaluate_derived(clients, outcomes)
            self.assertEqual(report["label_counts"]["human_confirmed"], 1)
            self.assertEqual(
                report["challenge_outcomes_by_label"]["campaign_signature"]["solved_share"],
                1.0,
            )
            self.assertFalse(report["false_positive_rate_available"])
            self.assertEqual(report["quality_checks"]["campaign_definition_mismatches"], 0)
            encoded = json.dumps(report, sort_keys=True)
            self.assertNotIn("192.0.2.", encoded)
            self.assertNotIn("Synthetic Browser", encoded)

    def test_derived_inputs_must_be_owner_only(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "derived.jsonl"
            path.write_text('{}\n')
            os.chmod(path, 0o644)
            with self.assertRaisesRegex(ValueError, "owner-only"):
                list(MODULE.private_jsonl(path))

    @staticmethod
    def event(observed_at, subject_id, session_id):
        return {
            "source": "access",
            "observed_at": observed_at,
            "subject_id": subject_id,
            "session_id": session_id,
            "status_class": "success",
            "endpoint_class": "other_public",
        }


if __name__ == "__main__":
    unittest.main()
