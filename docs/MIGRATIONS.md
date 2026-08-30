# Artifact lifecycle and migrations

Runbook contract: `palisade.runbook.migrations.v1`.

PALISADE treats a version change as a trust-boundary change, not a JSON rewrite.
The machine-readable [`migration-matrix-v1.json`](../manifests/migration-matrix-v1.json)
classifies every contract in the compatibility freeze and records every
historical schema still present in the repository. `make migration-check` fails
when a path, lifecycle class, predecessor or transition strategy changes without
an explicit compatibility decision.

## Closed lifecycle

```text
new contract
    |
    v
compatibility freeze -----> one lifecycle class
    |                       runtime_exchange
    |                       local_persistence
    |                       maintainer_evidence
    |                       repository_control
    v
has an older schema? --no--> current writer/reader only
    |
   yes
    v
reviewed transition ------> legacy read, regenerate, reissue, or repository replacement
```

Runtime exchanges include the versioned HTTP/protobuf contracts and signed local
artifacts. Their version marker may be a `/v1` path, protobuf package, `version`
field or `schema_version`; it is not required to use the same JSON field name.
Local persistence includes encrypted Shadow records and owner-controlled import,
analysis, review and sovereignty artifacts. Maintainer evidence includes release,
benchmark and synthetic findings records. Repository-control schemas describe
fixtures and inventories and are never runtime authority.

## Supported transitions

| Family | Current | Older inputs | Strategy |
|---|---|---|---|
| Shadow record | v3 | authenticated v1/v2 are `legacy_read` | verify and read in place; no rewrite |
| Shadow analysis | v4 | v1-v3 unsupported as rollout evidence | regenerate with `palisade analyze-shadow-log` |
| Rollout review | v4 | v1-v3 unsupported | regenerate with `palisade prepare-review` from a current report |
| Rollout plan | v2 | v1 unsupported | reissue with `palisade prepare-rollout` from a current review |
| Data map | v6 | v1-v5 repository history only | replace through reviewed repository change |

Shadow v1 outcomes do not contain a `decision_id`. PALISADE cannot reconstruct
that linkage without guessing, so it retains the authenticated legacy reader
instead of creating a misleading v3 record. This is an explicit no-safe-rewrite
decision. Operators may regenerate current aggregate reports from the original
authenticated record stream, but a regenerated report cannot manufacture
ground truth that was absent from the input.

Historical analysis reports, reviews and signed rollout plans never retain
activation authority merely because their JSON is parseable. Reissue always
flows forward from current authenticated evidence and current operator review.
Inputs remain untouched; commands create new owner-controlled artifacts outside
Git. No transition needs network access or sends an artifact to PALISADE.

## Adding or changing a version

1. Add a new schema or wire contract rather than changing stable semantics in
   place.
2. Add it to the compatibility freeze and exactly one lifecycle class.
3. If it has a predecessor, declare reader support, the transition strategy,
   operator command and any information-loss boundary.
4. Add downgrade, poisoning and mixed-version tests.
5. Update the compatibility freeze hashes and run `make verify` locally.

The current matrix is intentionally explicit and small. If PALISADE later adds
database-backed multi-instance storage, revisit the local create-only assumption
and design transactional migrations separately; do not silently reuse this file
workflow for a shared database.
