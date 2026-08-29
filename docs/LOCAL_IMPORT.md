# Generic local evidence import

`palisade import-local-events` is the vendor-neutral, local-only boundary for
operator-authorized exports. It reads one chronological JSONL file, immediately
replaces direct subject and optional session references with daily rotating,
dataset-and-pilot-separated HMAC-SHA256 pseudonyms, and publishes only closed
evidence fields into owner-controlled local shards. It makes no network request
and has no integration with a PALISADE maintainer's private systems.

This command complements the source-specific `import-offline` adapter. It does
not attempt to recognize arbitrary log formats. Operators transform their own
export into the closed input schema locally, which keeps vendor payloads, URLs,
request bodies and parser-specific trust decisions outside PALISADE.

## Private input boundary

The input schema is
[`palisade.local-evidence-input.v1`](../schemas/local-evidence-input-v1.schema.json).
Each line requires:

- an RFC 3339 UTC observation time and nondecreasing global event order;
- a local `subject_ref` and optional `session_ref`, each bounded to 512 bytes;
- one closed source, endpoint, action and status class;
- separate collection, automation, abuse-intent and continuity evidence lanes;
- closed decoy interaction and challenge lifecycle states; and
- an explicit label class, provenance and confidence.

`subject_ref` and `session_ref` may be personal data. They exist only in the
operator-owned input file and transient importer memory. They are never copied
to a shard, manifest, error message or stdout. A reference can be an address or
local identifier, but its meaning and lawful use remain the operator's
responsibility. Use a stable reference only within the approved evaluation
scope; do not create a cross-site identity key.

Unknown labels must use `none` provenance and `unknown` confidence.
`human_confirmed` requires an authenticated-account event or operator review.
`operator_confirmed_abuse` requires operator review. A passed challenge remains
a challenge outcome and can never establish humanity by itself.

The adapter that creates this JSONL file is part of the deployment trust
boundary. PALISADE verifies the closed syntax and label consistency, not the
truth of an adapter-supplied `high` evidence value. Mapping documentation and
tests must stay with the operator.

## Local operation

Keep the input file, key and output directory outside every Git worktree. The
input and key must be real, owner-only files; the output parent must already
exist and be owner-controlled. The command refuses symlinks and overwrite.

```sh
palisade import-local-events \
  --input-file /private/operator-export/events.jsonl \
  --output-dir /private/palisade/normalized-run-001 \
  --pseudonym-key-file /private/keys/palisade-import.key \
  --dataset-id operator-export-001 \
  --pilot-id local-shadow-pilot
```

The key must contain 32–4096 bytes and is never trimmed. Dataset and pilot IDs
are KDF domains; the manifest contains only a short derived domain ID. Reusing
the master key across pilots does not make their pseudonyms equal. Pseudonyms
rotate at the UTC day boundary.

Input lines default to a 1 MiB limit. Total input, record, event, shard and
output budgets fail closed and are configurable with `--max-*` flags. Unlike
the source-specific importer, the generic contract requires chronological
input and therefore needs no temporary external sort. Empty lines, duplicate
JSON keys, unknown fields, invalid enum combinations and decreasing timestamps
abort the entire run.

## Published local artifacts

The output contract consists of:

- `local-manifest.json` using
  [`palisade.local-evidence-manifest.v1`](../schemas/local-evidence-manifest-v1.schema.json);
- chronological `evidence-NNNNNN.jsonl` shards using
  [`palisade.local-evidence-event.v1`](../schemas/local-evidence-event-v1.schema.json); and
- `LOCAL_COMPLETE`, written only after every shard and the manifest are synced.

The manifest records only bounded configuration, a logical input name, input
size/hash, counts, time range, shard hashes, the derived domain ID and fixed
limitations. The original filename and filesystem paths are omitted. Input
hashes remain sensitive operational metadata and are not publication-ready.

Publication uses a private staging directory, exact file permissions, fsync and
an atomic same-filesystem rename. Consumers accept a directory only when the
manifest and `LOCAL_COMPLETE` exist. A failed import removes staging output and
never publishes the requested final directory.

Pseudonymization reduces disclosure but is not anonymization. Anyone holding
the key and candidate references may test guesses. Retain inputs, key, shards
and manifests for the shortest approved period, use encrypted operator storage
where the risk assessment requires it, and keep the key in a separately
controlled location. Do not send these artifacts to GitHub, hosted CI, public
issue trackers or PALISADE maintainers.

## Aggregate sequence analysis

After import, `palisade analyze-local-events` can verify the completed manifest
and every shard, then derive bounded five-minute sequence aggregates into a new
owner-only report:

```sh
palisade analyze-local-events \
  --dir /private/palisade/normalized-run-001 \
  --output /private/palisade/reports/local-sequence-report.json
```

Subject and session pseudonyms are used only as transient local linkage keys.
They and all row-level events are absent from the report. See the
[local sequence-analysis contract](LOCAL_SEQUENCE_ANALYSIS.md) for exact
feature definitions, resource ceilings and interpretation limits.

For confirmed-label measurement, run the separate
[`evaluate-local-holdout`](LOCAL_HOLDOUT_EVALUATION.md) workflow with a cutoff
chosen before viewing holdout outcomes. It does not modify the normalized
shards or authorize enforcement.
