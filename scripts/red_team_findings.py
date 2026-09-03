#!/usr/bin/env python3
"""Create or verify PALISADE's public synthetic red-team findings record."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

if __package__:
    from scripts import run_red_team
else:
    import run_red_team


SCHEMA_VERSION = "palisade.synthetic-red-team-findings.v2"
SUITE_VERSION = "palisade.red-team-suite.v2"
PROTOCOL = {
    "category_count": 6,
    "go_test_count": 1,
    "module_downloads_disabled": True,
    "publication_requires_all_passed": True,
    "scenario_count": 12,
}
LIMITATIONS = (
    "synthetic regression controls only; not an independent penetration test or security audit",
    "uses no deployment, customer or production traffic records",
    "does not measure unknown attack classes, detection efficacy or false-positive rates",
    "does not scan a public or live target",
    "passing named controls does not establish the absence of vulnerabilities",
    "operating-system network isolation is an operator boundary and is not attested by this JSON record",
)
TOP_LEVEL_FIELDS = {
    "schema_version",
    "suite_version",
    "source_commit",
    "suite_sha256",
    "synthetic_only",
    "raw_deployment_records_used",
    "protocol",
    "environment",
    "summary",
    "findings",
    "limitations",
}
FINDING_FIELDS = {
    "id",
    "category",
    "asset",
    "expected",
    "status",
    "remediation_status",
    "test_refs",
}
SHA256 = re.compile(r"^[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")


class FindingsError(ValueError):
    """The public findings record violates its closed synthetic contract."""


def _closed_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise FindingsError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_report(path: Path) -> dict[str, object]:
    if path.is_symlink() or not path.is_file():
        raise FindingsError("findings report must be a regular non-symlink file")
    if path.stat().st_size > 256 * 1024:
        raise FindingsError("findings report exceeds the 256 KiB contract budget")
    try:
        document = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_closed_object)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise FindingsError(f"cannot read findings report: {error}") from error
    if not isinstance(document, dict):
        raise FindingsError("findings report root must be an object")
    return document


def suite_digest(path: Path) -> str:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 128 * 1024:
        raise FindingsError("suite must remain a regular bounded non-symlink file")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _git_commit_is_reachable(repository_root: Path, commit: str) -> bool:
    exists = subprocess.run(
        ["git", "cat-file", "-e", f"{commit}^{{commit}}"],
        cwd=repository_root,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    ancestor = subprocess.run(
        ["git", "merge-base", "--is-ancestor", commit, "HEAD"],
        cwd=repository_root,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return exists.returncode == 0 and ancestor.returncode == 0


def validate_report(document: dict[str, object], repository_root: Path) -> None:
    if set(document) != TOP_LEVEL_FIELDS:
        raise FindingsError("findings report top-level fields are not closed")
    if document["schema_version"] != SCHEMA_VERSION or document["suite_version"] != SUITE_VERSION:
        raise FindingsError("findings report version is unsupported")
    if document["synthetic_only"] is not True or document["raw_deployment_records_used"] is not False:
        raise FindingsError("findings report must remain synthetic and exclude deployment records")
    source_commit = document["source_commit"]
    if not isinstance(source_commit, str) or COMMIT.fullmatch(source_commit) is None:
        raise FindingsError("findings source commit is invalid")
    digest = document["suite_sha256"]
    suite_path = repository_root / "examples/redteam/suite-v2.json"
    if not isinstance(digest, str) or SHA256.fullmatch(digest) is None or digest != suite_digest(suite_path):
        raise FindingsError("findings suite digest does not match the repository suite")
    protocol = document["protocol"]
    if (
        not isinstance(protocol, dict)
        or protocol != PROTOCOL
        or any(type(protocol[key]) is not type(value) for key, value in PROTOCOL.items())
    ):
        raise FindingsError("findings protocol fields or values changed")
    if document["limitations"] != list(LIMITATIONS):
        raise FindingsError("findings limitations are missing, reordered or changed")

    environment = document["environment"]
    if not isinstance(environment, dict) or set(environment) != {"go_version", "goos", "goarch"}:
        raise FindingsError("findings environment fields are not closed")
    if (
        not isinstance(environment["go_version"], str)
        or re.fullmatch(r"go1\.27(?:\.\d+)?", environment["go_version"]) is None
        or not isinstance(environment["goos"], str)
        or re.fullmatch(r"[a-z0-9]+", environment["goos"]) is None
        or not isinstance(environment["goarch"], str)
        or re.fullmatch(r"[a-z0-9]+", environment["goarch"]) is None
    ):
        raise FindingsError("findings environment values are invalid")

    suite = run_red_team.load_suite(suite_path)
    run_red_team.validate_suite(suite, repository_root)
    scenarios = suite["scenarios"]
    findings = document["findings"]
    if not isinstance(findings, list) or len(findings) != len(scenarios):
        raise FindingsError("findings must cover every suite scenario exactly once")
    for finding, scenario in zip(findings, scenarios):
        if not isinstance(finding, dict) or set(finding) != FINDING_FIELDS:
            raise FindingsError("finding fields are not closed")
        expected = {
            "id": scenario["id"],
            "category": scenario["category"],
            "asset": scenario["asset"],
            "expected": scenario["expected"],
            "status": "passed",
            "remediation_status": "not_required",
            "test_refs": scenario["test_refs"],
        }
        if finding != expected:
            raise FindingsError(f"finding does not match its passed scenario contract: {scenario['id']}")

    summary = document["summary"]
    expected_summary = {"passed": len(scenarios), "failed": 0, "remediations_open": 0}
    if (
        not isinstance(summary, dict)
        or summary != expected_summary
        or any(type(summary[key]) is not int for key in expected_summary)
    ):
        raise FindingsError("findings summary does not match the scenario results")
    if not _git_commit_is_reachable(repository_root, source_commit):
        raise FindingsError("findings source commit is unavailable or not an ancestor of HEAD")


def execution_environment() -> dict[str, str]:
    environment = os.environ.copy()
    environment.update(
        {
            "GONOSUMDB": "*",
            "GOPROXY": "off",
            "GOSUMDB": "off",
            "GOTOOLCHAIN": "local",
            "GOFLAGS": "-mod=readonly",
        }
    )
    return environment


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


def require_clean_commit(repository_root: Path) -> str:
    status = _run(
        ["git", "status", "--porcelain=v1", "--untracked-files=all"], repository_root, os.environ.copy()
    )
    if status:
        raise FindingsError("findings reports require a clean Git checkout")
    commit = _run(["git", "rev-parse", "HEAD"], repository_root, os.environ.copy()).strip()
    if COMMIT.fullmatch(commit) is None:
        raise FindingsError("source commit is not a full Git object ID")
    return commit


def go_environment(repository_root: Path, environment: dict[str, str]) -> dict[str, str]:
    values = _run(["go", "env", "GOVERSION", "GOOS", "GOARCH"], repository_root, environment).splitlines()
    if len(values) != 3 or re.fullmatch(r"go1\.27(?:\.\d+)?", values[0]) is None:
        raise FindingsError("Go 1.27.x and a complete local environment are required")
    return {"go_version": values[0], "goos": values[1], "goarch": values[2]}


def build_report(repository_root: Path) -> dict[str, object]:
    source_commit = require_clean_commit(repository_root)
    suite_path = repository_root / "examples/redteam/suite-v2.json"
    suite = run_red_team.load_suite(suite_path)
    package_tests = run_red_team.validate_suite(suite, repository_root)
    environment = execution_environment()
    machine = go_environment(repository_root, environment)
    run_red_team.execute(package_tests, repository_root, False)
    findings = [
        {
            "id": scenario["id"],
            "category": scenario["category"],
            "asset": scenario["asset"],
            "expected": scenario["expected"],
            "status": "passed",
            "remediation_status": "not_required",
            "test_refs": scenario["test_refs"],
        }
        for scenario in suite["scenarios"]
    ]
    report = {
        "schema_version": SCHEMA_VERSION,
        "suite_version": SUITE_VERSION,
        "source_commit": source_commit,
        "suite_sha256": suite_digest(suite_path),
        "synthetic_only": True,
        "raw_deployment_records_used": False,
        "protocol": dict(PROTOCOL),
        "environment": machine,
        "summary": {"passed": len(findings), "failed": 0, "remediations_open": 0},
        "findings": findings,
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
        raise FindingsError("output must not already exist")
    if not output.name or output.name in {".", ".."}:
        raise FindingsError("output filename is invalid")
    try:
        parent = output.parent.resolve(strict=True)
        stat = parent.stat()
    except OSError as error:
        raise FindingsError(f"output parent is unavailable: {error}") from error
    if not parent.is_dir() or stat.st_uid != os.getuid() or stat.st_mode & 0o077:
        raise FindingsError("output parent must be an owner-only directory")
    if _inside_git_worktree(parent):
        raise FindingsError("output must be outside every Git worktree")

    payload = (json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + "\n").encode("utf-8")
    temporary_descriptor = -1
    temporary_name = ""
    published_path: Path | None = None
    try:
        temporary_descriptor, temporary_name = tempfile.mkstemp(prefix=".palisade-red-team-", dir=parent)
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
        raise FindingsError(f"cannot publish synthetic findings report: {error}") from error
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
    parser.add_argument("--output", type=Path, help="create a findings JSON report outside every Git worktree")
    parser.add_argument("--verify", type=Path, help="validate an existing synthetic findings report")
    arguments = parser.parse_args(argv)
    if sum((arguments.output is not None, arguments.verify is not None)) != 1:
        parser.error("choose exactly one of --output or --verify")
    repository_root = Path(__file__).resolve().parent.parent
    try:
        if arguments.verify is not None:
            report = load_report(arguments.verify)
            validate_report(report, repository_root)
        else:
            report = build_report(repository_root)
            write_report_create_only(arguments.output, report)
    except (FindingsError, run_red_team.SuiteError, FileNotFoundError, subprocess.CalledProcessError) as error:
        print(f"red-team-findings: failed: {error}", file=sys.stderr)
        return 1
    if arguments.verify is not None:
        print("red-team-findings: verified 12 passed synthetic scenarios; no deployment records")
        return 0
    print("red-team-findings: wrote 12 passed synthetic scenarios; no deployment records")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
