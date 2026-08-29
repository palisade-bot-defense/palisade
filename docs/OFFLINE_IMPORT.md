# Offline Shield import

`palisade import-offline` is a local, read-only normalization boundary for an authorized Shield export. It does not upload, deploy or fetch anything. The command accepts only `offline_export`; other provenance categories remain intentionally rejected by this source-specific CLI. Operators with another source format can create the closed, chronological input described by the separate [generic local evidence import](LOCAL_IMPORT.md).

## Safety boundary

Keep the raw bundle, pseudonym key and every normalized output directory outside this repository and outside every other Git worktree. The importer enforces all three boundaries, requires no group/world permission bits on the input directory, input files and key, resolves paths before opening, rejects file and non-system parent symlinks, creates a private `0700` staging directory with exact `0600` outputs and refuses overwrite. On macOS, supply canonical `/private/var/...` or `/private/tmp/...` paths rather than the final `/var` or `/tmp` symlink itself. It never recursively scans the input directory and requires these exact files:

- `access.log.gz`
- `anubis-strain.jsonl.gz`
- `crowdsec-alerts.json`
- `crowdsec-decisions.json`
- `error.log.gz`

The HMAC key file must contain 32–4096 bytes. Every byte is key material: trailing LF/CRLF bytes are deliberately **not** trimmed. Generate and retain it locally according to the operator's key-management policy. Never put the key, raw inputs or output shards in Git, CI artifacts, public links, cloud tasks or external services.

```sh
go run ./cmd/palisade import-offline \
  --input-dir /local/authorized-shield-export \
  --output-dir /local/new-private-normalized-output \
  --pseudonym-key-file /local/private/palisade-import.key \
  --dataset-id authorized-export-2026 \
  --pilot-id offline-pilot
```

Anubis peer selection defaults to `--anubis-peer-source direct_peer_only`. The
only alternative, `trusted_x_real_ip`, is an explicit operator assertion: use
it only when the exported stack validates the TCP peer against Cloudflare's
network ranges before accepting `CF-Connecting-IP`, overwrites `x-real-ip`
itself, and falls back to the actual `$remote_addr` for direct connections.
The supplied offline export meets that documented boundary. The importer
cannot reconstruct this network trust decision from the offline row, so it
records the selected mode and a fixed warning in the manifest. Even in trusted
mode it reads only the known top-level Anubis `x-real-ip` field; arbitrary
`headers`, `Forwarded` and `X-Forwarded-For` values remain ignored.

Successful stdout contains aggregate event, invalid and skipped counts plus the local manifest path. It never prints rows, identifiers or key material. Dataset and pilot identifiers are required KDF domains but are not written verbatim; only a short derived domain ID is recorded. `--shard-size` is bounded to 100–100000 records and defaults to 10000. `--sort-chunk-size` bounds in-memory event sorting and defaults to 50000. `--max-line-bytes` bounds decompressed lines and individual JSON-array objects to 4 KiB–8 MiB and defaults to 1 MiB.

The importer also fails closed on configurable total budgets. Defaults are 128 GiB decompressed input, 50 million input records, 50 million emitted events, 10000 shards, 64 GiB final output and 256 GiB temporary sort data. Shards are capped at 999999, and configuration is rejected when the event/chunk limits could require more than 4096 initial sort runs. These defaults allow the known roughly 22-million-row access export while still bounding gzip bombs, malformed record floods, open-file metadata and disk amplification. Tighten them for smaller runs with the corresponding `--max-*` flags.

## Normalization contract

The event contract is [`palisade.offline-event.v1`](../schemas/offline-event-v1.schema.json). Only closed enums, booleans, coarse buckets and UTC observation time are emitted:

- canonical direct peer IP addresses are used transiently to compute a dataset-and-pilot-separated, daily rotating HMAC-SHA256 `subject_id`; IPv4/IPv6 ports are removed and invalid addresses are skipped;
- a same-day `session_id` is emitted only when a user-agent value was present and uses a separate HMAC namespace over peer plus user agent;
- query strings and fragments are removed before known-locale endpoint classification;
- Anubis normally requires an explicit direct `remote_addr`, `remote_address` or `peer_ip`; `x-real-ip` is accepted only under the explicit audited `trusted_x_real_ip` mode described above, and no peer value is ever emitted;
- referer, raw user agent, raw path, auth, cookies, messages, raw challenge/rule text and CrowdSec free text are never emitted;
- Anubis challenge/check fields become only closed presence/verdict categories and a quantized weight bucket;
- CrowdSec alert and decision rows, including supported nested `alert`/`decision` objects, are labeled `probable_abuse` with provenance and trust fixed to `weak_policy_label`. Scenario/rule/path free text is mapped only to closed categories and is never retained. They are not independent truth labels;
- `error.log.gz` is decompressed for integrity and line counts only and produces no event rows or time range.

The deterministic [`palisade.offline-manifest.v1`](../schemas/offline-manifest-v1.schema.json) contains sanitized configuration, the Anubis peer trust mode, local input size/hash/count/range metadata, shard hashes and fixed warnings. Parseable records contribute to a source time range even when they are skipped for lack of a safe subject. The manifest intentionally contains no run timestamp, raw domain identifier or filesystem/key path. Input hashes remain sensitive local metadata and must not be published.

Events are externally sorted with bounded memory and a stable input-order tie-break. Every shard, and the sequence across shard boundaries, is nondecreasing by `observed_at`; equal timestamps are allowed. A consumer must accept a run only when both `manifest.json` and `COMPLETE` exist. The entire staging directory is fsynced and atomically renamed, so the final output directory is not visible before those files and all shards are complete.

Use a private, owner-controlled output parent and do not create the requested final path concurrently. The importer checks immediately before publication and refuses an observed target. Portable Go `os.Rename` does not provide an atomic no-replace directory operation on every supported platform, so a hostile concurrent creator with write access to the output parent remains a narrow race; filesystem permissions are the required control for that residual risk.

## Threat and privacy notes

This boundary reduces accidental disclosure; it does not anonymize a person against an attacker who possesses the HMAC key and candidate identifiers. Daily rotation limits longitudinal linkability, while explicit dataset/pilot KDF domains prevent accidental cross-pilot joins even if an operator reuses a master key. Protect and eventually destroy the key. Normalized shards can still be sensitive because behavior and timestamps may permit inference, so retain them only as long as the approved evaluation requires.

Inputs are opened read-only and fingerprinted from the opened file descriptor before parsing. The exact byte stream consumed by a successful parser must match that size/hash, and the original descriptor is then rehashed and identity-checked after parsing; mutation or partial consumption fails the import. Gzip inputs have per-line and aggregate decompression limits; CrowdSec arrays are decoded one bounded object at a time. A failed import removes its private staging directory and never publishes the requested final directory. The importer does not join events into replay decisions; label/session join validity must be established first.

## Offline evaluation

`scripts/evaluate_offline.py` evaluates a completed normalized directory without
writing identifiers or row-level events to its report. It groups access events
into five-minute inactivity windows, links CrowdSec events only as weak labels
within a five-minute time boundary, and reports fixed transparent candidate
rules for the full dataset and a chronological split at the median weak-label
time. Optional derived inputs are joined only in memory through an ephemeral
keyed digest; their IP addresses and user agents are never written to the
report. Both derived files must be owner-only. Run it only with a private output
path outside Git:

```sh
python3 scripts/evaluate_offline.py \
  --input-dir /local/private-normalized-output \
  --client-features /local/authorized-export/client-features.jsonl \
  --challenge-outcomes /local/authorized-export/challenge-outcomes.jsonl \
  --output /local/private-evaluation/report.json
```

The report calls every non-linked window `unknown`, never `human`, and therefore
cannot establish a human false-positive rate. `campaign_signature` is a weak,
definition-bound compare-enumeration label; `unlabeled` is not a negative class,
and a solved challenge is an outcome rather than evidence of humanity. The
derived cohort contains only 16 authenticated-admin clients, which is too small
and unrepresentative for false-positive estimation. No enforcement threshold
may be approved from this export alone. A confirmed-human and accessibility
cohort is required before challenge or block promotion.

Before committing any change, run `make privacy-check`. The guard reads only exact Git index blobs and rejects tracked symlinks. It rejects the five raw bundle names, data/export extensions anywhere (except the explicit synthetic replay fixture), normalized shard/marker names, renamed data signatures, normalized manifest/event markers, every blob over 5 MiB and high-confidence private-key/credential markers. Its synthetic self-test covers clean, renamed-raw, renamed-normalized and symlink cases. It never scans user directories or the network.
