#!/usr/bin/env python3
"""Verify PALISADE's closed v2 compatibility freeze without network access."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import sys


API_PATHS = {
    "api/openapi.yaml",
    "api/openapi-assurance-v1.yaml",
    "api/contracts/normalized-signal-v1.json",
    *{f"api/proto/palisade/v1/{name}.proto" for name in ("challenge", "common", "coverage", "decision", "decoy", "event")},
}
CURRENT_SCHEMA_NAMES = {
    "adversarial-holdout-suite-v1", "adversarial-suite-v1", "compatibility-freeze-v2", "crawler-registry-v1", "data-map-v7",
    "detector-bundle-v1", "edge-signal-envelope-v1", "human-assurance-assertion-v1",
    "issuer-trust-list-v1",
    "local-artifact-v1", "local-evidence-event-v1",
    "local-evidence-input-v1", "local-evidence-manifest-v1", "local-family-annotation-v1",
    "local-holdout-report-v1", "local-release-v1", "local-sequence-report-v1", "migration-matrix-v2",
    "normalized-signal-contract-v1",
    "origin-adapter-conformance-v1", "policy-bundle-v1", "red-team-suite-v1", "release-reproduction-v1", "rollout-plan-v2",
    "rollout-review-v4", "runtime-egress-v1", "shadow-analysis-report-v5", "shadow-holdout-report-v1",
    "shadow-record-v4", "sovereignty-report-v1", "synthetic-benchmark-report-v1",
    "synthetic-red-team-findings-v1",
}
STABLE_CURRENT = API_PATHS | {f"schemas/{name}.schema.json" for name in CURRENT_SCHEMA_NAMES}
LEGACY_READ = {"schemas/shadow-record-v1.schema.json", "schemas/shadow-record-v2.schema.json", "schemas/shadow-record-v3.schema.json"}
SAFETY_MARKERS = {
    "docs/COMPATIBILITY.md": "palisade.compatibility-policy.v2",
    "docs/MIGRATIONS.md": "palisade.runbook.migrations.v2",
    "docs/THREAT_MODEL.md": "palisade.threat-model.v1",
    "docs/CHALLENGE.md": "palisade.runbook.challenge.v1",
    "docs/OPERATOR_SHADOW_DRILL.md": "palisade.runbook.operator-shadow-drill.v1",
    "docs/ORIGIN_ADAPTER.md": "palisade.runbook.origin-adapter.v1",
    "docs/RELEASING.md": "palisade.runbook.release.v1",
    "docs/REVERSE_PROXY_ADAPTER.md": "palisade.runbook.reverse-proxy-adapter.v1",
    "docs/ROLLOUT.md": "palisade.runbook.rollout.v1",
    "docs/SHADOW_LOG.md": "palisade.runbook.shadow-log.v1",
    "docs/privacy/DEPLOYMENT_CHECKLIST.md": "palisade.runbook.eu-privacy-deployment.v1",
}
WITHDRAWN_PRE_STABLE = {
    "palisade.offline-event.v1": "palisade.local-evidence-event.v1",
    "palisade.offline-manifest.v1": "palisade.local-evidence-manifest.v1",
}
TOP_LEVEL = {"schema_version", "scope", "stable_current", "legacy_read", "safety_documents", "withdrawn_pre_stable"}
SHA256 = re.compile(r"^[0-9a-f]{64}$")


class FreezeError(ValueError):
    pass


def _closed_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise FreezeError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_manifest(path: Path) -> dict[str, object]:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 256 * 1024:
        raise FreezeError("freeze manifest must be a regular bounded non-symlink file")
    try:
        document = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_closed_object)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise FreezeError(f"cannot read freeze manifest: {error}") from error
    if not isinstance(document, dict):
        raise FreezeError("freeze manifest root must be an object")
    return document


def _verify_group(root: Path, name: str, actual: object, expected: set[str]) -> None:
    if not isinstance(actual, dict) or set(actual) != expected:
        raise FreezeError(f"{name} path set changed")
    if list(actual) != sorted(actual):
        raise FreezeError(f"{name} paths must remain sorted")
    for relative, expected_hash in actual.items():
        path = Path(relative)
        if path.is_absolute() or ".." in path.parts or SHA256.fullmatch(expected_hash) is None:
            raise FreezeError(f"unsafe {name} entry: {relative}")
        candidate = root / path
        if candidate.is_symlink() or not candidate.is_file() or candidate.stat().st_size > 2 * 1024 * 1024:
            raise FreezeError(f"missing, linked or oversized frozen file: {relative}")
        digest = hashlib.sha256(candidate.read_bytes()).hexdigest()
        if digest != expected_hash:
            raise FreezeError(f"frozen file changed without a new compatibility decision: {relative}")


def validate_manifest(document: dict[str, object], root: Path) -> None:
    if set(document) != TOP_LEVEL:
        raise FreezeError("freeze manifest top-level fields are not closed")
    if document["schema_version"] != "palisade.compatibility-freeze.v2" or document["scope"] != "v2_public_contracts_and_operator_safety":
        raise FreezeError("unsupported freeze header")
    _verify_group(root, "stable_current", document["stable_current"], STABLE_CURRENT)
    _verify_group(root, "legacy_read", document["legacy_read"], LEGACY_READ)
    _verify_group(root, "safety_documents", document["safety_documents"], set(SAFETY_MARKERS))
    if document["withdrawn_pre_stable"] != WITHDRAWN_PRE_STABLE:
        raise FreezeError("pre-stable withdrawals changed without a compatibility decision")
    if STABLE_CURRENT & LEGACY_READ or (STABLE_CURRENT | LEGACY_READ) & set(SAFETY_MARKERS):
        raise FreezeError("freeze categories overlap")
    for relative, marker in SAFETY_MARKERS.items():
        try:
            text = (root / relative).read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as error:
            raise FreezeError(f"cannot read safety document: {relative}") from error
        if marker not in text:
            raise FreezeError(f"safety document lost contract marker: {relative}")


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    try:
        validate_manifest(load_manifest(root / "manifests/compatibility-freeze-v2.json"), root)
    except FreezeError as error:
        print(f"compatibility-check: failed: {error}", file=sys.stderr)
        return 1
    print(
        "compatibility-check: passed "
        f"{len(STABLE_CURRENT)} current contracts, {len(LEGACY_READ)} legacy readers and "
        f"{len(SAFETY_MARKERS)} safety documents"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
