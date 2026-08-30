#!/usr/bin/env python3
"""Run PALISADE's closed synthetic benchmark protocol and write an aggregate report."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import statistics
import subprocess
import sys
import tempfile


SCHEMA_VERSION = "palisade.synthetic-benchmark-report.v1"
SUITE_VERSION = "palisade.synthetic-benchmark-suite.v1"
BENCHMARK_SAMPLES = 7
BENCHTIME = "250ms"
LATENCY_TESTS = (
    ("production_shadow_decision", "TestInProcessDecisionP95MeetsPilotBudget"),
    ("signed_adaptive_enforcement_decision", "TestSignedAdaptiveRolloutP95MeetsPilotBudget"),
)
BENCHMARKS = (
    ("production_shadow_decision", "./internal/engine", "BenchmarkProductionDecisionPath"),
    ("signed_adaptive_enforcement_decision", "./internal/engine", "BenchmarkSignedAdaptiveDecisionPath"),
    ("progression_controller", "./internal/rollout", "BenchmarkProgressionController"),
)
LIMITATIONS = (
    "synthetic fixtures only; no deployment or customer records",
    "in-process Go execution only; excludes proxy, network, TLS and browser latency",
    "single logical CPU; not a concurrent, multi-replica or capacity measurement",
    "does not measure detection efficacy, false-positive rate or challenge outcomes",
    "microbenchmark run dispersion is not an operation-level latency percentile",
    "results vary with hardware, operating system, power state and Go toolchain",
    "race detector is excluded from timing runs and remains a separate release gate",
)
LATENCY_MARKER = re.compile(
    r"PALISADE_BENCHMARK_LATENCY\s+"
    r"p50_ns=(\d+)\s+p95_ns=(\d+)\s+p99_ns=(\d+)\s+"
    r"budget_ns=(\d+)\s+samples=(\d+)"
)
BENCHMARK_LINE = re.compile(
    r"^(Benchmark[A-Za-z0-9_]+)(?:-\d+)?\s+(\d+)\s+"
    r"([0-9]+(?:\.[0-9]+)?)\s+ns/op\s+"
    r"([0-9]+(?:\.[0-9]+)?)\s+B/op\s+"
    r"([0-9]+(?:\.[0-9]+)?)\s+allocs/op\s*$"
)


class BenchmarkError(ValueError):
    """The benchmark protocol or output violated its closed contract."""


def benchmark_environment() -> dict[str, str]:
    environment = os.environ.copy()
    environment.update(
        {
            "GOMAXPROCS": "1",
            "GONOSUMDB": "*",
            "GOPROXY": "off",
            "GOSUMDB": "off",
            "GOTOOLCHAIN": "local",
            "GOFLAGS": "-mod=readonly",
        }
    )
    return environment


def latency_command(test_name: str) -> list[str]:
    return ["go", "test", "./internal/engine", "-run", f"^{test_name}$", "-count=1", "-v"]


def benchmark_command(package: str, benchmark_name: str) -> list[str]:
    return [
        "go",
        "test",
        package,
        "-run",
        "^$",
        "-bench",
        f"^{benchmark_name}$",
        "-benchmem",
        "-count",
        str(BENCHMARK_SAMPLES),
        "-benchtime",
        BENCHTIME,
        "-cpu",
        "1",
    ]


def execution_plan() -> list[list[str]]:
    commands = [latency_command(test_name) for _, test_name in LATENCY_TESTS]
    commands.extend(benchmark_command(package, benchmark_name) for _, package, benchmark_name in BENCHMARKS)
    return commands


def _run(command: list[str], repository_root: Path, environment: dict[str, str]) -> str:
    completed = subprocess.run(
        command,
        cwd=repository_root,
        env=environment,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
    )
    return completed.stdout


def parse_latency_output(output: str) -> dict[str, int]:
    matches = LATENCY_MARKER.findall(output)
    if len(matches) != 1:
        raise BenchmarkError("latency test must emit exactly one benchmark marker")
    p50, p95, p99, budget, samples = (int(value) for value in matches[0])
    if not (0 <= p50 <= p95 <= p99) or p95 >= budget or samples != 1000:
        raise BenchmarkError("latency marker violates percentile, sample or budget contract")
    return {
        "samples": samples,
        "p50_ns": p50,
        "p95_ns": p95,
        "p99_ns": p99,
        "p95_budget_ns": budget,
    }


def parse_benchmark_output(output: str, expected_name: str) -> dict[str, object]:
    samples: list[dict[str, float | int]] = []
    for line in output.splitlines():
        match = BENCHMARK_LINE.fullmatch(line.strip())
        if match is None:
            continue
        name, iterations, nanoseconds, bytes_per_op, allocations = match.groups()
        if name != expected_name:
            raise BenchmarkError(f"unexpected benchmark result: {name}")
        samples.append(
            {
                "iterations": int(iterations),
                "ns_per_op": float(nanoseconds),
                "bytes_per_op": float(bytes_per_op),
                "allocations_per_op": float(allocations),
            }
        )
    if len(samples) != BENCHMARK_SAMPLES:
        raise BenchmarkError(f"{expected_name} produced {len(samples)} samples, want {BENCHMARK_SAMPLES}")
    if any(sample["iterations"] <= 0 or sample["ns_per_op"] <= 0 for sample in samples):
        raise BenchmarkError("benchmark samples must have positive iterations and time")

    def summarize(field: str) -> dict[str, float]:
        values = [float(sample[field]) for sample in samples]
        return {
            "median": statistics.median(values),
            "minimum": min(values),
            "maximum": max(values),
        }

    return {
        "runs": BENCHMARK_SAMPLES,
        "iterations_total": sum(int(sample["iterations"]) for sample in samples),
        "ns_per_op": summarize("ns_per_op"),
        "bytes_per_op": summarize("bytes_per_op"),
        "allocations_per_op": summarize("allocations_per_op"),
        "samples": samples,
    }


def require_clean_commit(repository_root: Path) -> str:
    status = subprocess.run(
        ["git", "status", "--porcelain=v1", "--untracked-files=all"],
        cwd=repository_root,
        check=True,
        stdout=subprocess.PIPE,
        text=True,
        encoding="utf-8",
    ).stdout
    if status:
        raise BenchmarkError("benchmark reports require a clean Git checkout")
    commit = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repository_root,
        check=True,
        stdout=subprocess.PIPE,
        text=True,
        encoding="utf-8",
    ).stdout.strip()
    if re.fullmatch(r"[0-9a-f]{40}", commit) is None:
        raise BenchmarkError("source commit is not a full Git object ID")
    return commit


def go_environment(repository_root: Path, environment: dict[str, str]) -> dict[str, object]:
    values = _run(["go", "env", "GOVERSION", "GOOS", "GOARCH", "CGO_ENABLED"], repository_root, environment).splitlines()
    if len(values) != 4 or re.fullmatch(r"go1\.27(?:\.\d+)?", values[0]) is None:
        raise BenchmarkError("Go 1.27.x and a complete local environment are required")
    return {
        "go_version": values[0],
        "goos": values[1],
        "goarch": values[2],
        "cgo_enabled": values[3] == "1",
        "gomaxprocs": 1,
    }


def build_report(repository_root: Path) -> dict[str, object]:
    source_commit = require_clean_commit(repository_root)
    environment = benchmark_environment()
    machine = go_environment(repository_root, environment)
    latency_profiles = []
    for profile, test_name in LATENCY_TESTS:
        result = parse_latency_output(_run(latency_command(test_name), repository_root, environment))
        latency_profiles.append({"profile": profile, **result})
    microbenchmarks = []
    for profile, package, benchmark_name in BENCHMARKS:
        result = parse_benchmark_output(
            _run(benchmark_command(package, benchmark_name), repository_root, environment), benchmark_name
        )
        microbenchmarks.append(
            {"profile": profile, "package": package, "benchmark": benchmark_name, **result}
        )
    return {
        "schema_version": SCHEMA_VERSION,
        "suite_version": SUITE_VERSION,
        "source_commit": source_commit,
        "synthetic_only": True,
        "raw_deployment_records_used": False,
        "protocol": {
            "logical_cpus": 1,
            "latency_samples_per_profile": 1000,
            "microbenchmark_samples": BENCHMARK_SAMPLES,
            "microbenchmark_benchtime": BENCHTIME,
            "module_downloads_disabled": True,
            "race_detector_enabled": False,
        },
        "environment": machine,
        "latency_profiles": latency_profiles,
        "microbenchmarks": microbenchmarks,
        "limitations": list(LIMITATIONS),
    }


def _inside_git_worktree(path: Path) -> bool:
    completed = subprocess.run(
        ["git", "-C", str(path), "rev-parse", "--is-inside-work-tree"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        encoding="utf-8",
    )
    return completed.returncode == 0 and completed.stdout.strip() == "true"


def write_report_create_only(output: Path, report: dict[str, object]) -> None:
    if output.exists() or output.is_symlink():
        raise BenchmarkError("output must not already exist")
    if not output.name or output.name in {".", ".."}:
        raise BenchmarkError("output filename is invalid")
    try:
        parent = output.parent.resolve(strict=True)
        stat = parent.stat()
    except OSError as error:
        raise BenchmarkError(f"output parent is unavailable: {error}") from error
    if not parent.is_dir() or stat.st_uid != os.getuid() or stat.st_mode & 0o077:
        raise BenchmarkError("output parent must be an owner-only directory")
    if _inside_git_worktree(parent):
        raise BenchmarkError("output must be outside every Git worktree")

    payload = (json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + "\n").encode("utf-8")
    temporary_descriptor = -1
    temporary_name = ""
    published_path: Path | None = None
    try:
        temporary_descriptor, temporary_name = tempfile.mkstemp(prefix=".palisade-benchmark-", dir=parent)
        os.fchmod(temporary_descriptor, 0o600)
        with os.fdopen(temporary_descriptor, "wb", closefd=True) as handle:
            temporary_descriptor = -1
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        target_path = parent / output.name
        os.link(temporary_name, target_path, follow_symlinks=False)
        published_path = target_path
        os.unlink(temporary_name)
        temporary_name = ""
        directory_descriptor = os.open(parent, os.O_RDONLY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    except (OSError, TypeError, ValueError) as error:
        if published_path is not None:
            try:
                os.unlink(published_path)
            except FileNotFoundError:
                pass
        raise BenchmarkError(f"cannot publish aggregate report: {error}") from error
    finally:
        if temporary_descriptor >= 0:
            os.close(temporary_descriptor)
        if temporary_name:
            try:
                os.unlink(temporary_name)
            except FileNotFoundError:
                pass


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", action="store_true", help="print the fixed protocol without running Go")
    parser.add_argument("--output", type=Path, help="create the aggregate JSON report outside every Git worktree")
    arguments = parser.parse_args(argv)
    if arguments.plan == (arguments.output is not None):
        parser.error("choose exactly one of --plan or --output")
    repository_root = Path(__file__).resolve().parent.parent
    if arguments.plan:
        for command in execution_plan():
            print("benchmark:", " ".join(command))
        print(f"benchmark: planned {len(LATENCY_TESTS)} latency profiles and {len(BENCHMARKS)} microbenchmarks")
        return 0
    try:
        report = build_report(repository_root)
        write_report_create_only(arguments.output, report)
    except (BenchmarkError, FileNotFoundError, subprocess.CalledProcessError) as error:
        print(f"benchmark: failed: {error}", file=sys.stderr)
        return 1
    print(
        f"benchmark: wrote {len(report['latency_profiles'])} latency profiles and "
        f"{len(report['microbenchmarks'])} microbenchmarks; synthetic aggregates only"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
