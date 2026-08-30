#!/usr/bin/env python3
"""Verify PALISADE's complete closed artifact lifecycle and migration matrix."""

from __future__ import annotations

import json
from pathlib import Path
import re
import sys

try:
    from scripts import check_compatibility_freeze
except ModuleNotFoundError:
    import check_compatibility_freeze


SCHEMA_VERSION = "palisade.migration-matrix.v2"
SCOPE = "all_frozen_and_historical_versioned_contracts"
INVARIANTS = [
    "writers_emit_current_only",
    "unknown_versions_are_rejected",
    "migration_is_local_bounded_and_create_only",
    "migration_never_overwrites_input",
    "migration_has_no_network_or_raw_export",
    "missing_linkage_is_never_synthesized",
]
TOP_LEVEL_FIELDS = {"schema_version", "scope", "invariants", "classifications", "transitions", "withdrawals"}
CLASSIFICATION_FIELDS = {"runtime_exchange", "local_persistence", "maintainer_evidence", "repository_control"}
TRANSITION_FIELDS = {
    "family", "current_schema", "previous_schemas", "previous_support", "strategy", "operator_command", "loss_boundary"
}
SAFE_PATH = re.compile(r"^(api|schemas)/[A-Za-z0-9_./-]+$")

EXPECTED_CLASSIFICATIONS = {
    "runtime_exchange": {
        "api/contracts/normalized-signal-v1.json", "api/openapi.yaml",
        *{f"api/proto/palisade/v1/{name}.proto" for name in ("challenge", "common", "coverage", "decision", "decoy", "event")},
        "schemas/crawler-registry-v1.schema.json", "schemas/detector-bundle-v1.schema.json",
        "schemas/edge-signal-envelope-v1.schema.json", "schemas/local-artifact-v1.schema.json",
        "schemas/normalized-signal-contract-v1.schema.json", "schemas/policy-bundle-v1.schema.json",
        "schemas/rollout-plan-v2.schema.json",
    },
    "local_persistence": {
        "schemas/local-evidence-event-v1.schema.json", "schemas/local-evidence-input-v1.schema.json",
        "schemas/local-evidence-manifest-v1.schema.json", "schemas/local-family-annotation-v1.schema.json",
        "schemas/local-holdout-report-v1.schema.json", "schemas/local-sequence-report-v1.schema.json",
        "schemas/rollout-review-v4.schema.json", "schemas/shadow-analysis-report-v4.schema.json",
        "schemas/shadow-holdout-report-v1.schema.json", "schemas/shadow-record-v1.schema.json",
        "schemas/shadow-record-v2.schema.json", "schemas/shadow-record-v3.schema.json",
        "schemas/sovereignty-report-v1.schema.json",
    },
    "maintainer_evidence": {
        "schemas/local-release-v1.schema.json", "schemas/release-reproduction-v1.schema.json",
        "schemas/synthetic-benchmark-report-v1.schema.json", "schemas/synthetic-red-team-findings-v1.schema.json",
    },
    "repository_control": {
        "schemas/adversarial-holdout-suite-v1.schema.json", "schemas/adversarial-suite-v1.schema.json",
        "schemas/compatibility-freeze-v2.schema.json", "schemas/data-map-v6.schema.json",
        "schemas/migration-matrix-v2.schema.json", "schemas/origin-adapter-conformance-v1.schema.json",
        "schemas/red-team-suite-v1.schema.json", "schemas/runtime-egress-v1.schema.json",
    },
}

EXPECTED_TRANSITIONS = {
    "compatibility_freeze": {
        "current_schema": "schemas/compatibility-freeze-v2.schema.json",
        "previous_schemas": ["schemas/compatibility-freeze-v1.schema.json"],
        "previous_support": "unsupported_historical", "strategy": "repository_replacement",
        "operator_command": "none", "loss_boundary": "repository_control_not_runtime_input",
    },
    "data_map": {
        "current_schema": "schemas/data-map-v6.schema.json",
        "previous_schemas": [f"schemas/data-map-v{version}.schema.json" for version in range(1, 6)],
        "previous_support": "unsupported_historical", "strategy": "repository_replacement",
        "operator_command": "none", "loss_boundary": "repository_control_not_runtime_input",
    },
    "migration_matrix": {
        "current_schema": "schemas/migration-matrix-v2.schema.json",
        "previous_schemas": ["schemas/migration-matrix-v1.schema.json"],
        "previous_support": "unsupported_historical", "strategy": "repository_replacement",
        "operator_command": "none", "loss_boundary": "repository_control_not_runtime_input",
    },
    "rollout_plan": {
        "current_schema": "schemas/rollout-plan-v2.schema.json",
        "previous_schemas": ["schemas/rollout-plan-v1.schema.json"],
        "previous_support": "unsupported_historical", "strategy": "reissue_from_current_review",
        "operator_command": "palisade prepare-rollout", "loss_boundary": "old_signed_authority_is_not_reused",
    },
    "rollout_review": {
        "current_schema": "schemas/rollout-review-v4.schema.json",
        "previous_schemas": [f"schemas/rollout-review-v{version}.schema.json" for version in range(1, 4)],
        "previous_support": "unsupported_historical", "strategy": "regenerate_from_authenticated_source",
        "operator_command": "palisade prepare-review", "loss_boundary": "historical_review_is_not_activation_authority",
    },
    "shadow_analysis": {
        "current_schema": "schemas/shadow-analysis-report-v4.schema.json",
        "previous_schemas": [f"schemas/shadow-analysis-report-v{version}.schema.json" for version in range(1, 4)],
        "previous_support": "unsupported_historical", "strategy": "regenerate_from_authenticated_source",
        "operator_command": "palisade analyze-shadow-log", "loss_boundary": "historical_report_is_not_rollout_authority",
    },
    "shadow_record": {
        "current_schema": "schemas/shadow-record-v3.schema.json",
        "previous_schemas": [f"schemas/shadow-record-v{version}.schema.json" for version in range(1, 3)],
        "previous_support": "legacy_read", "strategy": "legacy_read_no_rewrite",
        "operator_command": "palisade verify-shadow-log", "loss_boundary": "v1_outcome_has_no_decision_id",
    },
}


class MatrixError(ValueError):
    pass


def _closed_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise MatrixError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_matrix(path: Path) -> dict[str, object]:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 256 * 1024:
        raise MatrixError("migration matrix must be a regular bounded non-symlink file")
    try:
        document = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_closed_object)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise MatrixError(f"cannot read migration matrix: {error}") from error
    if not isinstance(document, dict):
        raise MatrixError("migration matrix root must be an object")
    return document


def _validate_path(root: Path, relative: str) -> None:
    if not isinstance(relative, str) or SAFE_PATH.fullmatch(relative) is None:
        raise MatrixError(f"unsafe contract path: {relative}")
    path = Path(relative)
    if path.is_absolute() or ".." in path.parts:
        raise MatrixError(f"unsafe contract path: {relative}")
    candidate = root / path
    if candidate.is_symlink() or not candidate.is_file() or candidate.stat().st_size > 2 * 1024 * 1024:
        raise MatrixError(f"missing, linked or oversized contract: {relative}")


def validate_matrix(document: dict[str, object], root: Path) -> None:
    if not isinstance(document, dict) or set(document) != TOP_LEVEL_FIELDS:
        raise MatrixError("migration matrix top-level fields are not closed")
    if document["schema_version"] != SCHEMA_VERSION or document["scope"] != SCOPE:
        raise MatrixError("unsupported migration matrix header")
    if document["invariants"] != INVARIANTS:
        raise MatrixError("migration safety invariants changed")

    if document["withdrawals"] != check_compatibility_freeze.WITHDRAWN_PRE_STABLE:
        raise MatrixError("pre-stable withdrawals and compatibility freeze disagree")

    freeze = check_compatibility_freeze.load_manifest(root / "manifests/compatibility-freeze-v2.json")
    check_compatibility_freeze.validate_manifest(freeze, root)
    expected_frozen = check_compatibility_freeze.STABLE_CURRENT | check_compatibility_freeze.LEGACY_READ

    classifications = document["classifications"]
    if not isinstance(classifications, dict) or set(classifications) != CLASSIFICATION_FIELDS:
        raise MatrixError("migration classifications are not closed")
    classified: set[str] = set()
    for name in sorted(CLASSIFICATION_FIELDS):
        values = classifications[name]
        if not isinstance(values, list) or not values or any(not isinstance(value, str) for value in values):
            raise MatrixError(f"classification {name} must be a non-empty path list")
        if values != sorted(values) or len(values) != len(set(values)):
            raise MatrixError(f"classification {name} must be sorted and unique")
        if set(values) != EXPECTED_CLASSIFICATIONS[name]:
            raise MatrixError(f"classification {name} changed without a lifecycle decision")
        if classified & set(values):
            raise MatrixError("contract paths appear in multiple lifecycle classes")
        for relative in values:
            _validate_path(root, relative)
        classified.update(values)
    if classified != expected_frozen:
        raise MatrixError("migration classifications do not exactly cover the compatibility freeze")

    transitions = document["transitions"]
    if not isinstance(transitions, list) or len(transitions) != len(EXPECTED_TRANSITIONS):
        raise MatrixError("migration transition count changed")
    if [entry.get("family") if isinstance(entry, dict) else None for entry in transitions] != sorted(EXPECTED_TRANSITIONS):
        raise MatrixError("migration transition families must be exact and sorted")
    historical: set[str] = set()
    for entry in transitions:
        if not isinstance(entry, dict) or set(entry) != TRANSITION_FIELDS:
            raise MatrixError("migration transition fields are not closed")
        family = entry["family"]
        expected = {"family": family, **EXPECTED_TRANSITIONS[family]}
        if entry != expected:
            raise MatrixError(f"migration transition changed without review: {family}")
        _validate_path(root, entry["current_schema"])
        for relative in entry["previous_schemas"]:
            _validate_path(root, relative)
            if relative in historical:
                raise MatrixError("historical schema appears in multiple transitions")
            historical.add(relative)

    frozen_schema_paths = {path for path in classified if path.startswith("schemas/")}
    all_schema_paths = {
        path.relative_to(root).as_posix() for path in (root / "schemas").glob("*.schema.json")
    }
    if (
        frozen_schema_paths | historical != all_schema_paths
        or frozen_schema_paths & historical != check_compatibility_freeze.LEGACY_READ
    ):
        raise MatrixError("schema files are not exactly classified as frozen or historical")
    expected_legacy = set(EXPECTED_TRANSITIONS["shadow_record"]["previous_schemas"])
    if expected_legacy != check_compatibility_freeze.LEGACY_READ:
        raise MatrixError("legacy-read schemas and the shadow transition disagree")


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    try:
        validate_matrix(load_matrix(root / "manifests/migration-matrix-v2.json"), root)
    except (MatrixError, check_compatibility_freeze.FreezeError) as error:
        print(f"migration-check: failed: {error}", file=sys.stderr)
        return 1
    print(
        "migration-check: passed "
        f"{sum(len(paths) for paths in EXPECTED_CLASSIFICATIONS.values())} frozen contracts, "
        f"{len(check_compatibility_freeze.LEGACY_READ)} legacy-read predecessors and "
        f"{sum(len(item['previous_schemas']) for item in EXPECTED_TRANSITIONS.values()) - len(check_compatibility_freeze.LEGACY_READ)} unsupported historical predecessors"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
