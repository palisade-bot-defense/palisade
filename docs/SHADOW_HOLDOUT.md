# Chronological linked shadow holdout

`palisade evaluate-shadow-holdout` measures the authenticated encrypted shadow
decision stream on a predeclared chronological boundary. It joins delayed
closed outcomes to the exact decision in bounded memory, partitions by the
decision's authenticated record time and writes only an owner-only aggregate
report.

This complements two existing tools:

- `analyze-shadow-log` describes the complete retained window and produces
  rollout recommendations;
- `evaluate-local-holdout` evaluates generic normalized sequence features and
  can optionally isolate operator-annotated unseen families.

The shadow holdout answers the narrower question those tools could not answer
together: how did PALISADE's actual computed decisions perform before and after
a time boundary when measured only against exactly linked confirmed outcomes?

## Predeclare the boundary

Choose the boundary before inspecting holdout labels or changing detector and
policy thresholds. It must be an exact UTC whole-second RFC 3339 value:

```sh
palisade evaluate-shadow-holdout \
  --dir /private/local/palisade-shadow/logs \
  --key-file /private/local/palisade-shadow/shadow.key \
  --holdout-start 2026-09-20T00:00:00Z \
  --output /private/local/palisade-shadow/shadow-holdout.json
```

A decision recorded before the cutoff belongs to the baseline. A decision at
or after the cutoff belongs to holdout. Outcomes may be recorded later; their
timestamp never moves the decision between partitions. Duplicate decision IDs
are excluded from both partitions, while unknown decision IDs, endpoint
mismatches, duplicate outcomes, conflicting ground truth and missing labels
remain explicit aggregate counters.

Each partition reports:

- confirmed-human and operator-confirmed-abuse decision counts;
- explicit unlabeled and ambiguous decisions;
- confusion counts with Wilson 95% intervals;
- challenge completion, failure, abandonment, fallback and unresolved counts;
- endpoint-class and accessibility-cohort slices; and
- an evidence-readiness state that always keeps automatic enforcement false.

Defaults require 100 confirmed-human and 100 confirmed-abuse decisions in both
partitions. These are minimum sufficiency checks, not representativeness proof.
Use `--min-confirmed-human` and `--min-confirmed-abuse` only to predeclare a
stricter campaign contract or to exercise synthetic tests; do not lower them
after viewing private outcomes to manufacture readiness.

## Privacy and resource boundary

The evaluator authenticates the same encrypted files as `verify-shadow-log` and
uses SHA-256 decision-ID digests as in-memory equality keys. Neither decision
IDs nor digests enter the report. Scan and linkage budgets fail closed. The
output follows
[`palisade.shadow-holdout.v2`](../schemas/shadow-holdout-report-v2.schema.json),
whose partitions each carry `assurance_slices`: the same linked evaluation per
endpoint class and human assurance level. That is what the decision to raise
the assurance ceiling is read from — a level earns its ceiling on a holdout,
not on the population its thresholds came from — and `unknown` is kept separate
from level 0 so an unevaluated decision is never counted as a measured absence
of human presence.
is create-only, exactly `0600`, and must be placed in a canonical owner-only
directory outside every Git worktree. The repository privacy guard rejects the
report even after renaming.

The aggregate remains private because its time range, traffic volume, endpoint
mix and security performance can reveal operational posture. Do not commit it,
attach it to public issues or send it to PALISADE maintainers.

## Interpretation limits

- Confirmed labels remain deployment or operator assertions, not causality.
- Unknown and missing labels are not humans.
- Challenge completion is never a human label.
- Chronological separation does not prove that endpoint and accessibility
  cohorts are representative.
- This report has no attack-family input and makes no unseen-family claim; use
  the separate generic local holdout contract for that diagnostic.
- `chronological_ready` is not rollout approval. Signed review, latency,
  coverage, accessibility, abandonment and rollback gates remain separate.
