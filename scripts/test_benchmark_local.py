import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from scripts import benchmark_local


class BenchmarkLocalTests(unittest.TestCase):
    def test_latency_marker_is_closed_and_ordered(self):
        output = (
            "=== RUN   TestInProcessDecisionP95MeetsPilotBudget\n"
            "    performance_test.go:25: PALISADE_BENCHMARK_LATENCY "
            "p50_ns=100 p95_ns=200 p99_ns=300 budget_ns=10000000 samples=1000\n"
        )
        self.assertEqual(
            benchmark_local.parse_latency_output(output),
            {"samples": 1000, "p50_ns": 100, "p95_ns": 200, "p99_ns": 300, "p95_budget_ns": 10000000},
        )

    def test_latency_marker_rejects_budget_failure(self):
        output = (
            "PALISADE_BENCHMARK_LATENCY "
            "p50_ns=100 p95_ns=10000000 p99_ns=10000001 budget_ns=10000000 samples=1000"
        )
        with self.assertRaisesRegex(benchmark_local.BenchmarkError, "contract"):
            benchmark_local.parse_latency_output(output)

    def test_benchmark_samples_are_aggregated_without_claiming_percentiles(self):
        lines = []
        for index in range(benchmark_local.BENCHMARK_SAMPLES):
            lines.append(
                f"BenchmarkProductionDecisionPath-1 {1000 + index} {100 + index}.5 ns/op "
                f"{20 + index} B/op {2 + index}.0 allocs/op"
            )
        result = benchmark_local.parse_benchmark_output("\n".join(lines), "BenchmarkProductionDecisionPath")
        self.assertEqual(result["runs"], benchmark_local.BENCHMARK_SAMPLES)
        self.assertEqual(result["ns_per_op"], {"median": 103.5, "minimum": 100.5, "maximum": 106.5})
        self.assertNotIn("p95", result)

    def test_benchmark_sample_count_is_exact(self):
        line = "BenchmarkProductionDecisionPath-1 1000 100.0 ns/op 20 B/op 2 allocs/op"
        with self.assertRaisesRegex(benchmark_local.BenchmarkError, "produced 1 samples"):
            benchmark_local.parse_benchmark_output(line, "BenchmarkProductionDecisionPath")

    def test_plan_contains_only_closed_synthetic_targets(self):
        plan = benchmark_local.execution_plan()
        flattened = "\n".join(" ".join(command) for command in plan)
        self.assertEqual(len(plan), 5)
        self.assertIn("BenchmarkSignedAdaptiveDecisionPath", flattened)
        self.assertIn("BenchmarkProgressionController", flattened)
        self.assertNotIn("http://", flattened)
        self.assertNotIn("https://", flattened)

    def test_create_only_report_is_owner_only_and_deterministic(self):
        report = {"schema_version": benchmark_local.SCHEMA_VERSION, "synthetic_only": True}
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            parent.chmod(0o700)
            output = parent / "aggregate.json"
            benchmark_local.write_report_create_only(output, report)
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            self.assertEqual(json.loads(output.read_text(encoding="utf-8")), report)
            with self.assertRaisesRegex(benchmark_local.BenchmarkError, "must not already exist"):
                benchmark_local.write_report_create_only(output, report)

    def test_report_is_rejected_inside_another_git_worktree(self):
        report = {"schema_version": benchmark_local.SCHEMA_VERSION, "synthetic_only": True}
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            parent.chmod(0o700)
            subprocess.run(["git", "init", "-q", str(parent)], check=True)
            with self.assertRaisesRegex(benchmark_local.BenchmarkError, "outside every Git worktree"):
                benchmark_local.write_report_create_only(parent / "aggregate.json", report)

    def test_concurrent_output_creator_is_not_deleted(self):
        report = {"schema_version": benchmark_local.SCHEMA_VERSION, "synthetic_only": True}
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            parent.chmod(0o700)
            output = parent / "aggregate.json"

            def create_competing_output(_source, target, **_kwargs):
                Path(target).write_text("operator-owned\n", encoding="utf-8")
                raise FileExistsError("synthetic publication race")

            with mock.patch.object(benchmark_local.os, "link", side_effect=create_competing_output):
                with self.assertRaisesRegex(benchmark_local.BenchmarkError, "cannot publish"):
                    benchmark_local.write_report_create_only(output, report)
            self.assertEqual(output.read_text(encoding="utf-8"), "operator-owned\n")

    def test_permissive_output_parent_is_rejected(self):
        report = {"schema_version": benchmark_local.SCHEMA_VERSION, "synthetic_only": True}
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            parent.chmod(0o755)
            with self.assertRaisesRegex(benchmark_local.BenchmarkError, "owner-only"):
                benchmark_local.write_report_create_only(parent / "aggregate.json", report)

    def test_benchmark_environment_disables_module_resolution(self):
        environment = benchmark_local.benchmark_environment()
        self.assertEqual(environment["GOMAXPROCS"], "1")
        self.assertEqual(environment["GOPROXY"], "off")
        self.assertEqual(environment["GOSUMDB"], "off")
        self.assertEqual(environment["GOTOOLCHAIN"], "local")
        self.assertEqual(environment["GOFLAGS"], "-mod=readonly")


if __name__ == "__main__":
    unittest.main()
