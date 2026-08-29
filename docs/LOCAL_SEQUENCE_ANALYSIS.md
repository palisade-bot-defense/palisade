# Local sequence analysis

`palisade analyze-local-events` verifies a completed generic local-evidence
import and derives deterministic, minute-scale behavior aggregates. The entire
operation runs on the operator's filesystem. It performs no network request,
does not train a model and does not write row-level events, subject pseudonyms
or session pseudonyms to the report.

This is an evaluation primitive, not a bot verdict. Burst rates, endpoint
transitions, decoy interactions and challenge outcomes can raise or lower
confidence only after measurement against independently confirmed outcomes.
They do not establish whether a person or bot is present.

## Run it locally

Keep the normalized input directory and report outside every Git worktree. The
input directory and report parent must be owner-only and contain no symlink in
the resolved path. The report is create-only: an existing file is never
replaced.

```sh
palisade analyze-local-events \
  --dir /private/palisade/normalized-run-001 \
  --output /private/palisade/reports/local-sequence-report.json
```

The reader requires `LOCAL_COMPLETE`, authenticates every manifest-declared
shard by exact size and SHA-256 hash, rejects undeclared directory entries,
enforces the closed event schema and verifies global chronological order. Scan
limits for shards, events and bytes fail closed before or during processing.
`--max-active-sequences` bounds the number of in-memory linkage windows; the
analyzer keeps exactly one expiration-heap entry per active window.

Defaults are 10,000 shards, 50 million events, 64 GiB of verified input and
100,000 active sequence windows. The compiled hard ceilings are 999,999
shards, 100 million events, 1 TiB and one million active windows. Operators
should lower these values to realistic deployment bounds.

## Window and feature contract

Events use the daily session pseudonym when present and otherwise the daily
subject pseudonym. Those values are transient map keys and never report fields.
A window closes after five minutes of inactivity, at 15 minutes maximum age or
at the end of input. An event exactly on a boundary begins a new window.

The versioned report records fixed definitions alongside counts:

- burst shape: `single`, `sparse`, `clustered`, `sustained` or `high_rate`;
- peak events in one UTC minute, in five closed buckets;
- same-class, cross-class, sensitive-escalation and decoy-entry transitions;
- event and sequence counts for each closed endpoint class;
- complete, partial and missing collection status;
- separate maximum automation, abuse-intent and continuity evidence levels;
- maximum decoy interaction and closed challenge lifecycle outcome; and
- unknown, confirmed-human, confirmed-abuse or internally ambiguous label
  windows.

`clustered` means at least 20 events over at most 60 seconds. `high_rate` takes
precedence when one UTC minute contains at least 60 events. `sustained` means at
least 20 events over at least five minutes. Everything else with more than one
event is `sparse`. These are transparent descriptive bins, not learned
thresholds and not production enforcement policy.

The output uses
[`palisade.local-sequence-report.v1`](../schemas/local-sequence-report-v1.schema.json).
It is bounded to 1 MiB and written as a 0600 owner-only file. The source section
contains only verification counts, byte total and observation range. Even this
aggregate report may disclose operational volume or timing and is therefore a
private artifact blocked by the repository privacy guard.

## Interpretation limits

- Operator evidence mappings are declarations, not independently verified
  measurements.
- Daily pseudonyms and window association are continuity handles, not identity.
- A relationship between a sequence and outcome is observational and does not
  establish that a detector or challenge caused the outcome.
- Passing a challenge does not prove humanity; conflicting terminal challenge
  states are counted instead of silently selecting one.
- Partial or missing collection remains explicit and must not be interpreted as
  suspicious behavior by itself.

The follow-on [local holdout evaluator](LOCAL_HOLDOUT_EVALUATION.md) implements
a predeclared chronological split, independently confirmed label denominators,
optional unseen-family grouping, collection-failure slices and Wilson
intervals. Private inputs, annotations, shards and reports remain on the
operator-controlled machine. Only reviewed aggregates or synthetic fixtures
are candidates for publication.
