#!/usr/bin/env python3
"""Validate and execute PALISADE's closed synthetic red-team baseline."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys


EXPECTED = {
    "browser_challenge_humanity_evasion": ("evasion", "decision_integrity", "challenge_pass_never_confirms_human"),
    "verified_crawler_intent_evasion": ("evasion", "decision_integrity", "verified_identity_cannot_override_abuse_intent"),
    "signed_edge_payload_poisoning": ("poisoning", "trusted_signal_boundary", "reject_noncanonical_or_inconsistent_signal"),
    "signed_policy_threshold_poisoning": ("poisoning", "trusted_signal_boundary", "reject_uncompiled_or_invalid_policy"),
    "native_challenge_redemption_relay": ("proof_relay", "challenge_capability", "reject_replay_or_binding_mismatch"),
    "origin_flow_binding_relay": ("proof_relay", "challenge_capability", "bind_grant_to_target_sequence_session_and_instance"),
    "anonymous_session_reset": ("session_reset", "session_continuity", "new_session_is_isolated_and_not_verified"),
    "expired_event_receipt_reset": ("session_reset", "session_continuity", "expire_receipt_and_start_fresh_sequence"),
    "session_store_capacity_exhaustion": ("resource_exhaustion", "bounded_availability", "evict_within_fixed_capacity"),
    "offline_import_budget_exhaustion": ("resource_exhaustion", "bounded_availability", "fail_closed_without_published_output"),
    "signed_rollout_tampering": ("rollout_compromise", "rollout_authority", "reject_tampered_or_mismatched_rollout"),
    "expired_rollout_reuse": ("rollout_compromise", "rollout_authority", "downgrade_expired_rollout_to_shadow"),
}
CATEGORIES = {
    "evasion",
    "poisoning",
    "proof_relay",
    "session_reset",
    "resource_exhaustion",
    "rollout_compromise",
}
TOP_LEVEL_FIELDS = {"schema_version", "scope", "synthetic_only", "network_policy", "scenarios"}
SCENARIO_FIELDS = {"id", "category", "asset", "threat", "expected", "test_refs"}
TEST_REFERENCE = re.compile(r"^([A-Za-z0-9_./-]+_test\.go)#(Test[A-Za-z0-9_]+)$")


class SuiteError(ValueError):
    """The red-team manifest violates its closed local contract."""


def _closed_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise SuiteError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_suite(path: Path) -> dict[str, object]:
    if path.is_symlink() or not path.is_file():
        raise SuiteError("suite must be a regular non-symlink file")
    if path.stat().st_size > 128 * 1024:
        raise SuiteError("suite exceeds the 128 KiB contract budget")
    try:
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_closed_object)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SuiteError(f"cannot read closed suite: {error}") from error


def validate_suite(document: dict[str, object], repository_root: Path) -> dict[str, list[str]]:
    if not isinstance(document, dict):
        raise SuiteError("suite root must be an object")
    if set(document) != TOP_LEVEL_FIELDS:
        raise SuiteError("suite top-level fields are not closed")
    if document["schema_version"] != "palisade.red-team-suite.v1":
        raise SuiteError("unsupported suite version")
    if document["scope"] != "roadmap_v0_9_synthetic_baseline":
        raise SuiteError("unsupported suite scope")
    if document["synthetic_only"] is not True or document["network_policy"] != "module_downloads_disabled":
        raise SuiteError("suite must remain synthetic with module downloads disabled")
    scenarios = document["scenarios"]
    if not isinstance(scenarios, list) or len(scenarios) != len(EXPECTED):
        raise SuiteError("suite must contain the exact scenario count")

    seen: set[str] = set()
    categories: dict[str, int] = {category: 0 for category in CATEGORIES}
    package_tests: dict[str, list[str]] = {}
    for scenario in scenarios:
        if not isinstance(scenario, dict) or set(scenario) != SCENARIO_FIELDS:
            raise SuiteError("scenario fields are not closed")
        scenario_id = scenario["id"]
        if not isinstance(scenario_id, str) or scenario_id in seen or scenario_id not in EXPECTED:
            raise SuiteError("scenario ID is unknown or duplicated")
        seen.add(scenario_id)
        category, asset, expected = EXPECTED[scenario_id]
        if scenario["category"] != category or scenario["asset"] != asset or scenario["expected"] != expected:
            raise SuiteError(f"scenario contract mismatch: {scenario_id}")
        if category not in categories:
            raise SuiteError(f"unknown category: {category}")
        categories[category] += 1
        if not isinstance(scenario["threat"], str) or not 1 <= len(scenario["threat"]) <= 180:
            raise SuiteError(f"scenario threat is invalid: {scenario_id}")
        references = scenario["test_refs"]
        if not isinstance(references, list) or not 1 <= len(references) <= 3:
            raise SuiteError(f"scenario test references are invalid: {scenario_id}")
        if any(not isinstance(reference, str) for reference in references):
            raise SuiteError(f"scenario test reference is not text: {scenario_id}")
        if len(set(references)) != len(references):
            raise SuiteError(f"scenario test references are duplicated: {scenario_id}")
        for reference in references:
            match = TEST_REFERENCE.fullmatch(reference)
            if match is None:
                raise SuiteError(f"unsafe test reference: {reference}")
            relative_path, function = match.groups()
            candidate_path = Path(relative_path)
            if candidate_path.is_absolute() or ".." in candidate_path.parts:
                raise SuiteError(f"unsafe test reference: {reference}")
            unresolved_source_path = repository_root / relative_path
            if unresolved_source_path.is_symlink():
                raise SuiteError(f"test reference is a symlink: {reference}")
            source_path = unresolved_source_path.resolve()
            try:
                source_path.relative_to(repository_root.resolve())
            except ValueError as error:
                raise SuiteError(f"test reference escapes repository: {reference}") from error
            if source_path.is_symlink() or not source_path.is_file():
                raise SuiteError(f"test reference does not resolve: {reference}")
            if source_path.stat().st_size > 2 * 1024 * 1024:
                raise SuiteError(f"test source exceeds the 2 MiB contract budget: {reference}")
            try:
                source_text = source_path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError) as error:
                raise SuiteError(f"test source cannot be read: {reference}") from error
            if re.search(rf"(?m)^func\s+{re.escape(function)}\s*\(", source_text) is None:
                raise SuiteError(f"test function does not exist: {reference}")
            package = Path(relative_path).parent.as_posix()
            package_tests.setdefault(package, []).append(function)

    if seen != set(EXPECTED) or any(count != 2 for count in categories.values()):
        raise SuiteError("suite must contain two scenarios in every required category")
    return {package: sorted(set(tests)) for package, tests in sorted(package_tests.items())}


def execute(package_tests: dict[str, list[str]], repository_root: Path, list_only: bool) -> None:
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
    for package, tests in package_tests.items():
        expression = "^(?:" + "|".join(re.escape(test) for test in tests) + ")$"
        command = ["go", "test", f"./{package}", "-run", expression, "-count=1"]
        print("red-team:", " ".join(command), flush=True)
        if not list_only:
            subprocess.run(command, cwd=repository_root, env=environment, check=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--list", action="store_true", help="validate and print the offline execution plan without running Go")
    arguments = parser.parse_args(argv)
    repository_root = Path(__file__).resolve().parent.parent
    suite_path = repository_root / "examples/redteam/suite-v1.json"
    try:
        package_tests = validate_suite(load_suite(suite_path), repository_root)
        execute(package_tests, repository_root, arguments.list)
    except (SuiteError, subprocess.CalledProcessError, FileNotFoundError) as error:
        print(f"red-team: failed: {error}", file=sys.stderr)
        return 1
    print(
        f"red-team: {'planned' if arguments.list else 'passed'} {len(EXPECTED)} synthetic scenarios "
        f"across {len(CATEGORIES)} categories; module downloads disabled"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
