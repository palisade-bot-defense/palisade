#!/usr/bin/env python3
"""Run PALISADE's closed synthetic benchmark protocol and write an aggregate report."""

from __future__ import annotations

import argparse
import json
import math
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
TOP_LEVEL_FIELDS = {
    "schema_version",
    "suite_version",
    "source_commit",
    "synthetic_only",
    "raw_deployment_records_used",
    "protocol",
    "environment",
    "latency_profiles",
    "microbenchmarks",
    "limitations",
}
PROTOCOL = {
    "logical_cpus": 1,
    "latency_samples_per_profile": 1000,
    "microbenchmark_samples": BENCHMARK_SAMPLES,
    "microbenchmark_benchtime": BENCHTIME,
    "module_downloads_disabled": True,
    "race_detector_enabled": False,
}
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


def _closed_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise BenchmarkError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_report(path: Path) -> dict[str, object]:
    if path.is_symlink() or not path.is_file():
        raise BenchmarkError("benchmark report must be a regular non-symlink file")
    if path.stat().st_size > 128 * 1024:
        raise BenchmarkError("benchmark report exceeds the 128 KiB contract budget")
    try:
        document = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_closed_object)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise BenchmarkError(f"cannot read benchmark report: {error}") from error
    if not isinstance(document, dict):
        raise BenchmarkError("benchmark report root must be an object")
    return document


def _is_integer(value: object, minimum: int = 0) -> bool:
    return type(value) is int and value >= minimum


def _is_number(value: object, minimum: float = 0.0, exclusive: bool = False) -> bool:
    if type(value) not in (int, float) or not math.isfinite(float(value)):
        return False
    return float(value) > minimum if exclusive else float(value) >= minimum


def _validate_summary(summary: object, values: list[float], field: str) -> None:
    if not isinstance(summary, dict) or set(summary) != {"median", "minimum", "maximum"}:
        raise BenchmarkError(f"{field} summary fields are not closed")
    if any(not _is_number(summary[key]) for key in summary):
        raise BenchmarkError(f"{field} summary contains a non-finite or negative value")
    expected = {
        "median": statistics.median(values),
        "minimum": min(values),
        "maximum": max(values),
    }
    if summary != expected:
        raise BenchmarkError(f"{field} summary does not match the seven published samples")


def validate_report(document: dict[str, object], repository_root: Path | None = None) -> None:
    if set(document) != TOP_LEVEL_FIELDS:
        raise BenchmarkError("benchmark report top-level fields are not closed")
    if document["schema_version"] != SCHEMA_VERSION or document["suite_version"] != SUITE_VERSION:
        raise BenchmarkError("benchmark report version is unsupported")
    if document["synthetic_only"] is not True or document["raw_deployment_records_used"] is not False:
        raise BenchmarkError("benchmark report must remain synthetic and exclude deployment records")
    source_commit = document["source_commit"]
    if not isinstance(source_commit, str) or re.fullmatch(r"[0-9a-f]{40}", source_commit) is None:
        raise BenchmarkError("benchmark source commit is invalid")
    protocol = document["protocol"]
    if (
        not isinstance(protocol, dict)
        or protocol != PROTOCOL
        or any(type(protocol[key]) is not type(value) for key, value in PROTOCOL.items())
    ):
        raise BenchmarkError("benchmark protocol fields or values changed")
    if document["limitations"] != list(LIMITATIONS):
        raise BenchmarkError("benchmark limitations are missing, reordered or changed")

    environment = document["environment"]
    if not isinstance(environment, dict) or set(environment) != {
        "go_version", "goos", "goarch", "cgo_enabled", "gomaxprocs"
    }:
        raise BenchmarkError("benchmark environment fields are not closed")
    if (
        not isinstance(environment["go_version"], str)
        or re.fullmatch(r"go1\.27(?:\.\d+)?", environment["go_version"]) is None
        or not isinstance(environment["goos"], str)
        or re.fullmatch(r"[a-z0-9]+", environment["goos"]) is None
        or not isinstance(environment["goarch"], str)
        or re.fullmatch(r"[a-z0-9]+", environment["goarch"]) is None
        or type(environment["cgo_enabled"]) is not bool
        or not _is_integer(environment["gomaxprocs"], 1)
        or environment["gomaxprocs"] != 1
    ):
        raise BenchmarkError("benchmark environment values are invalid")

    latency_profiles = document["latency_profiles"]
    if not isinstance(latency_profiles, list) or len(latency_profiles) != len(LATENCY_TESTS):
        raise BenchmarkError("benchmark latency profile count changed")
    latency_fields = {"profile", "samples", "p50_ns", "p95_ns", "p99_ns", "p95_budget_ns"}
    for latency, (profile, _) in zip(latency_profiles, LATENCY_TESTS):
        if not isinstance(latency, dict) or set(latency) != latency_fields or latency["profile"] != profile:
            raise BenchmarkError("benchmark latency profile fields or order changed")
        if (
            not _is_integer(latency["samples"], 1)
            or latency["samples"] != 1000
            or not _is_integer(latency["p95_budget_ns"], 1)
            or latency["p95_budget_ns"] != 10_000_000
            or any(not _is_integer(latency[key]) for key in ("p50_ns", "p95_ns", "p99_ns"))
            or not latency["p50_ns"] <= latency["p95_ns"] <= latency["p99_ns"]
            or latency["p95_ns"] >= latency["p95_budget_ns"]
        ):
            raise BenchmarkError("benchmark latency percentiles, sample count or budget are invalid")

    microbenchmarks = document["microbenchmarks"]
    if not isinstance(microbenchmarks, list) or len(microbenchmarks) != len(BENCHMARKS):
        raise BenchmarkError("microbenchmark profile count changed")
    benchmark_fields = {
        "profile", "package", "benchmark", "runs", "iterations_total",
        "ns_per_op", "bytes_per_op", "allocations_per_op", "samples",
    }
    sample_fields = {"iterations", "ns_per_op", "bytes_per_op", "allocations_per_op"}
    for benchmark, (profile, package, name) in zip(microbenchmarks, BENCHMARKS):
        if (
            not isinstance(benchmark, dict)
            or set(benchmark) != benchmark_fields
            or (benchmark["profile"], benchmark["package"], benchmark["benchmark"]) != (profile, package, name)
            or not _is_integer(benchmark["runs"], 1)
            or benchmark["runs"] != BENCHMARK_SAMPLES
        ):
            raise BenchmarkError("microbenchmark fields, identity or order changed")
        samples = benchmark["samples"]
        if not isinstance(samples, list) or len(samples) != BENCHMARK_SAMPLES:
            raise BenchmarkError("microbenchmark must retain exactly seven samples")
        for sample in samples:
            if (
                not isinstance(sample, dict)
                or set(sample) != sample_fields
                or not _is_integer(sample["iterations"], 1)
                or not _is_number(sample["ns_per_op"], 0, exclusive=True)
                or not _is_number(sample["bytes_per_op"])
                or not _is_number(sample["allocations_per_op"])
            ):
                raise BenchmarkError("microbenchmark sample is malformed or non-finite")
        if (
            not _is_integer(benchmark["iterations_total"], 1)
            or benchmark["iterations_total"] != sum(sample["iterations"] for sample in samples)
        ):
            raise BenchmarkError("microbenchmark iteration total does not match its samples")
        _validate_summary(benchmark["ns_per_op"], [float(sample["ns_per_op"]) for sample in samples], "ns_per_op")
        _validate_summary(benchmark["bytes_per_op"], [float(sample["bytes_per_op"]) for sample in samples], "bytes_per_op")
        _validate_summary(
            benchmark["allocations_per_op"],
            [float(sample["allocations_per_op"]) for sample in samples],
            "allocations_per_op",
        )

    if repository_root is not None:
        exists = subprocess.run(
            ["git", "cat-file", "-e", f"{source_commit}^{{commit}}"],
            cwd=repository_root,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        ancestor = subprocess.run(
            ["git", "merge-base", "--is-ancestor", source_commit, "HEAD"],
            cwd=repository_root,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if exists.returncode != 0 or ancestor.returncode != 0:
            raise BenchmarkError("benchmark source commit is unavailable or not an ancestor of HEAD")


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
    report = {
        "schema_version": SCHEMA_VERSION,
        "suite_version": SUITE_VERSION,
        "source_commit": source_commit,
        "synthetic_only": True,
        "raw_deployment_records_used": False,
        "protocol": dict(PROTOCOL),
        "environment": machine,
        "latency_profiles": latency_profiles,
        "microbenchmarks": microbenchmarks,
        "limitations": list(LIMITATIONS),
    }
    validate_report(report, repository_root)
    return report


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
    parser.add_argument("--verify", type=Path, help="validate an existing aggregate benchmark report")
    arguments = parser.parse_args(argv)
    if sum((arguments.plan, arguments.output is not None, arguments.verify is not None)) != 1:
        parser.error("choose exactly one of --plan, --output or --verify")
    repository_root = Path(__file__).resolve().parent.parent
    if arguments.plan:
        for command in execution_plan():
            print("benchmark:", " ".join(command))
        print(f"benchmark: planned {len(LATENCY_TESTS)} latency profiles and {len(BENCHMARKS)} microbenchmarks")
        return 0
    try:
        if arguments.verify is not None:
            report = load_report(arguments.verify)
            validate_report(report, repository_root)
        else:
            report = build_report(repository_root)
            write_report_create_only(arguments.output, report)
    except (BenchmarkError, FileNotFoundError, subprocess.CalledProcessError) as error:
        print(f"benchmark: failed: {error}", file=sys.stderr)
        return 1
    if arguments.verify is not None:
        print(
            f"benchmark: verified {len(report['latency_profiles'])} latency profiles and "
            f"{len(report['microbenchmarks'])} microbenchmarks; synthetic aggregates only"
        )
        return 0
    print(
        f"benchmark: wrote {len(report['latency_profiles'])} latency profiles and "
        f"{len(report['microbenchmarks'])} microbenchmarks; synthetic aggregates only"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
