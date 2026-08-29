# Local chronological holdout evaluation

`palisade evaluate-local-holdout` evaluates the fixed local sequence features
against confirmed labels on a predeclared chronological split. It reads the
same authenticated, owner-only shards as `analyze-local-events`, runs without a
network connection and writes only a bounded aggregate report.

The evaluator is intentionally not a trainer. Its five diagnostic candidate
rules are versioned constants, not thresholds selected after viewing holdout
labels and not production enforcement policy. The report always sets
`automatic_enforcement` to `false`.

## Predeclare the split

Choose `--holdout-start` before inspecting holdout labels or changing feature
definitions. It must be an absolute UTC RFC 3339 timestamp with a `Z` suffix.
Random request or row splits are unsupported because repeated sessions and
campaign behavior would leak across partitions.

```sh
palisade evaluate-local-holdout \
  --dir /private/palisade/normalized-run-001 \
  --holdout-start 2026-09-20T00:00:00Z \
  --output /private/palisade/reports/local-holdout-report.json
```

A sequence belongs to the baseline only when its final event precedes the
boundary. It belongs to holdout only when its first event is at or after the
boundary. A window that crosses the boundary is excluded from both and counted
with its labels and event total. This prevents partial windows from sharing
behavior across the split.

The baseline and holdout each retain:

- confirmed-human, operator-confirmed-abuse, unknown and ambiguous windows;
- clean versus partial/missing collection windows;
- fixed candidate-rule confusion counts and Wilson 95% intervals;
- seven non-exclusive endpoint-membership slices; and
- the number of events and sequence windows in the denominator.

Unknown is never a human label. A sequence with both confirmed label classes is
`ambiguous` and excluded from both confirmed-label rates. Endpoint slices are
membership views: a sequence that touched multiple endpoint classes appears in
each applicable slice, so endpoint totals must not be added together.

## Fixed diagnostic rules

The v1 contract evaluates exactly five diagnostics:

1. `burst_behavior`: clustered or high-rate burst shape;
2. `automation_high`: maximum operator-declared automation evidence is high;
3. `abuse_intent_high`: maximum operator-declared abuse-intent evidence is high;
4. `active_decoy`: a decoy was touched or submitted; and
5. `combined_candidate`: any of the preceding conditions.

The report provides confirmed-human flag rate, confirmed-abuse capture rate and
unknown flag rate for each rule globally and by endpoint. These estimates
measure association under the supplied evidence mapping. They do not establish
causality, prove identity or justify enforcement.

## Optional unseen-family holdout

An optional owner-only JSONL maps a normalized daily sequence pseudonym to an
operator attack/tool family reference:

```json
{"schema_version":"palisade.local-family-annotation.v1","sequence_kind":"session","sequence_id":"MTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTE","family_ref":"synthetic-family-alpha"}
```

The example pseudonym and family are synthetic.

Pass it with `--family-annotations`. The file must be a 0600 regular file in an
owner-only directory outside every Git worktree. Duplicate sequence
assignments, unknown fields, invalid pseudonyms and resource-budget overflow
abort evaluation. Family references and sequence pseudonyms are reduced to
domain-separated SHA-256 map keys in memory and never enter the report.

A holdout family is `unseen` only when no annotated baseline window has the
same family reference. The report contains counts and an input fingerprint,
not family names or identifiers. Because pseudonyms rotate daily, the operator
must annotate each relevant daily subject/session pseudonym. Annotations should
be fixed by an independent review or campaign taxonomy before holdout results
are inspected; otherwise the unseen-family claim is vulnerable to post-hoc
grouping.

Full unseen-family readiness also requires every confirmed-abuse window in the
evaluated baseline and holdout to have a family annotation. Missing abuse-family
coverage remains an explicit reason; incomplete annotations can never produce
the full readiness state. “Unseen” always means unseen relative to the supplied
operator taxonomy, not globally novel.

```sh
palisade evaluate-local-holdout \
  --dir /private/palisade/normalized-run-001 \
  --holdout-start 2026-09-20T00:00:00Z \
  --family-annotations /private/palisade/annotations/families.jsonl \
  --output /private/palisade/reports/local-holdout-report.json
```

Default hard working limits are 100,000 active sequences, one million family
records, 256 MiB of annotations and 4 KiB per annotation line. Scan limits for
normalized shards remain independently configurable. Lower them for the real
deployment size.

## Readiness is not rollout approval

By default, both chronological partitions require at least 100 confirmed-human
and 100 confirmed-abuse windows. Full unseen-family readiness additionally
requires 100 confirmed-abuse windows in the unseen-family holdout. The closed
states distinguish missing chronology, insufficient confirmed labels,
chronological readiness and chronological-plus-unseen-family readiness.

These are dataset sufficiency checks only. They do not compare PALISADE with an
upstream baseline, test calibration, account for site-traffic coverage or
authorize a rollout. Signed rollout review continues to depend on the separate
authenticated shadow-decision/outcome pipeline.

The output follows
[`palisade.local-holdout-report.v1`](../schemas/local-holdout-report-v1.schema.json),
is bounded to 2 MiB and is create-only with mode 0600. It remains private: its
input fingerprint, volumes, time ranges and label composition may expose
operational information. The repository privacy guard rejects both generated
holdout reports and family annotation inputs even after renaming.

The public
[synthetic adversarial suite](../examples/holdout/adversarial-scenarios-v1.json)
defines fail-closed expectations for random-split leakage, boundary windows,
unknown labels, conflicting labels, collection loss, seen/unseen families,
annotation poisoning, challenge-humanity inference and resource exhaustion. It
contains no deployment records or reusable identifiers.

The broader [public adversarial conformance suite](ADVERSARIAL_FIXTURES.md)
connects this holdout contract with executable replay, missing-signal,
header-spoofing, accessibility and origin-adapter failure scenarios.
