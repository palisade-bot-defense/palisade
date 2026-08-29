# Local encrypted shadow log

The shadow sink is an optional, local-only measurement channel. It records PALISADE decisions and normalized delayed outcomes without placing raw requests, browser events or direct session identifiers on disk. It is disabled unless both `--shadow-log-dir` and `--shadow-log-key-file` are supplied.

## Closing the sensor-only measurement loop

`POST /v1/events` normally updates only the five-minute in-memory event store.
For deployments that have a sensor but no origin decision stream yet, enable
the server-trusted event shadow profile:

```sh
palisade serve \
  --require-session-cookie \
  --event-shadow-action read \
  --event-shadow-endpoint-class public_content \
  --shadow-log-dir /private/local/palisade-shadow/logs \
  --shadow-log-key-file /private/local/palisade-shadow/shadow.key
```

The static profile intentionally classifies every event batch the same way. To
measure multiple route classes in production, use the mutually exclusive
proof-classified mode:

```sh
palisade serve \
  --require-session-cookie \
  --event-shadow-from-proof \
  --shadow-log-dir /private/local/palisade-shadow/logs \
  --shadow-log-key-file /private/local/palisade-shadow/shadow.key
```

For each page class, the trusted origin requests the ordinary one-time event
proof with its closed route-table classification:

```json
{
  "action": "events",
  "request_action": "compare",
  "endpoint_class": "compare_noindex",
  "ttl_seconds": 60
}
```

`POST /v1/token` is backend-authenticated. Go origins can use
`palisadehttp.Middleware.IssueEventProof` from a fixed same-origin backend
route. Browser code receives only the
signed proof and forwards it as `X-Palisade-Proof`; it never selects or submits
the action, endpoint class, path, URL or referer. The proof is session-bound,
expires after at most five minutes and is usable for at most one event request
attempt. A missing, partial, raw or
unrecognized context is rejected
before event ingestion, so the sensor can retry without creating a gap in the
server-owned batch sequence. Static and proof-classified modes cannot run
together.

Each authenticated, accepted batch then produces one internal shadow decision
using a server-owned contiguous batch sequence and the fresh aggregate event
count. Browser event numbers remain inputs to bounded event deduplication; they
are never interpreted as a request sequence. The original event proof must be
minted for `events`; PALISADE creates and consumes a second
internal proof for the configured decision action. Neither proof reaches the
recorder. The browser gets no decision body, scores or evidence.

The `X-Palisade-Shadow-Evaluation` response header is `recorded` when the closed
decision was queued and `dropped` when evaluation or queueing failed. The event
response remains `202` in both cases because retrying an accepted batch would
duplicate or reorder sequences. Drops are counted in process logs and must be
included as measurement loss.

The local Operator Console exposes a process-local collection funnel for this
bridge: successfully issued route-context proofs, accepted event batches,
recorded shadow decisions, rejected proof/context attempts and post-ingest
drops. Endpoint counts use only PALISADE's nine closed endpoint classes; paths,
URLs and referers never enter the counters. This funnel measures internal
collection completeness only. PALISADE does not observe the total traffic that
reached the protected site, so it cannot derive or claim a site-wide evaluation
rate from these counters.

Event-shadow decisions written by model versions before
`transparent-baseline-v9` used the last browser event number as the decision
sequence. Those authenticated records remain valid for chain integrity,
non-sequence facts and linked outcomes, but sequence-derived reasons, scores
and actions are instrument artifacts and must not be used for calibration.
Reanalysis cannot rewrite a historical decision; begin a new comparison window
after deploying v9.

`transparent-baseline-v10` and policy `default-v5` narrow beneficial crawler
handling to a complete verified-purpose tuple on an indexable public endpoint.
Earlier `verified_bot`-only decisions are not evidence that a crawler identity
was cryptographically or network verified and must not be used to estimate SEO
or answer-engine false-positive rates. Start a new comparison window after the
v10 deployment and monitor the aggregate crawler-identity posture separately.

`transparent-baseline-v11` adds only closed edge-fingerprint and network-context
classes. Raw JA4/JA3 or HTTP/2 fingerprints, addresses, ASNs and vendor labels
remain outside PALISADE. These new classes create conservative suspicious
evidence only and must begin a fresh shadow comparison window; a browser-like,
residential or low-risk class is never a confirmed-human label.

`transparent-baseline-v12` adds downgrade-only response-cost scaling inside a
signed rollout. Throttle and temporary-block durations now range from fixed
minimums to the plan's signed maxima using closed endpoint, evidence-confidence,
recent-session and retry-history factors. Stable factor reason codes make this
visible in encrypted decisions. Existing v11 decisions remain valid historical
measurements, but a v11-signed rollout cannot load into the v12 runtime.

This collection bridge requires the encrypted sink and signed session cookie.
It rejects signed rollout configuration and therefore cannot enforce. Disable
it before enabling the origin middleware or a rollout; otherwise flush-based
and request-based decisions would double-count the same session.

## Data contract

Decision records contain a keyed 128-bit session link, decision ID, allowlisted request-action class, normalized endpoint class, enforced and computed actions, runtime mode, three scores, bounded stable reason codes, and policy/model versions. Unknown or dynamic action strings are stored as `other`. Outcome records contain the same session link, optional PALISADE decision ID, normalized endpoint class, a closed outcome label, provenance and confidence. Record times are UTC and quantized to whole seconds.

The sink must not receive or persist IP addresses, user agents, cookies, proof tokens, form content, URLs, request bodies, exact interaction paths or raw external-vendor rows. A session link is HMAC-derived under a domain-separated key and is useful only for records produced with the same master key; it is not an identity claim.

Accepted outcome combinations are:

| Outcome | Allowed provenance | Confidence |
|---|---|---|
| `human_confirmed` | `authenticated_account`, `operator_review` | `confirmed` |
| `operator_confirmed_abuse` | `operator_review` | `confirmed` |
| `successful_action`, challenge results | `server_observed` | `confirmed` |
| `appeal_requested`, `fallback_used` | `server_observed`, `user_feedback` | `confirmed` |
| `unknown` | `unknown` | `unknown` |

`POST /v1/outcome` is backend-only and requires the configured bearer API key plus the exact `decision_id`. When strict session-cookie binding is enabled, the submitted session must also match the signed cookie. A solved challenge is only `challenge_passed`, never `human_confirmed`. Native challenge outcomes inherit the originating decision ID automatically.

The Operator Console exposes process-local outcome ingestion health separately
from analysis: successful encrypted writes, authorized invalid submissions and
validated writes lost to an unavailable sink. Unauthorized internet noise is
not included. These counters diagnose the feedback path but never infer label
kind, false-positive rate or human status; those require uniquely linked,
provenance-valid records in the local aggregate analysis.

## Storage and cryptography

- The master key is 32–4096 raw bytes in a regular owner-only file. The file, its parent and the log directory must be outside every Git worktree and inaccessible to group/other users.
- HMAC-SHA-256 domain separation derives independent AES-256-GCM encryption and session-link keys.
- Every file has a random 64-bit nonce prefix. Every encrypted record uses the prefix plus a strictly increasing 32-bit counter as its 96-bit GCM nonce. The file marker, prefix and counter are authenticated as additional data.
- A file is created once with `0600`, receives only appended frames, is synced at least once per second and is closed on rotation or graceful shutdown. Rotation creates a new file after 64 MiB or one hour by default.
- Retention is seven days by default and may be configured up to 90 days. Cleanup matches only `shadow-YYYYMMDDTHHMMSSZ-<16 lowercase hex>.plog`; unrelated files are untouched.
- One directory may contain records from only one key. Startup rejects retained files with a different key identifier or format. Rotate the key into a new empty directory.

The asynchronous queue is bounded. A full or failed writer never adds request latency: decision records are dropped and only aggregate drop counters are emitted. The outcome endpoint returns `503` if it cannot enqueue a record. This loss must be included in evaluation coverage.

Runtime controls are `--shadow-log-max-bytes`, `--shadow-log-max-age`, `--shadow-log-retention` and `--shadow-log-queue`. Accepted bounds are 4 KiB–1 GiB, one minute–one day, max-file-age–90 days, and 1–1,000,000 queued records respectively. Defaults are 64 MiB, one hour, seven days and 4096 records.

## Verification and operational limits

Run verification before evaluation and after copying files:

```sh
palisade verify-shadow-log --dir /private/local/palisade-shadow/logs --key-file /private/local/palisade-shadow/shadow.key
```

Verification authenticates every retained record, rejects malformed permissions, counters, ciphertext and closed-schema values, and prints aggregates only. It does not print decrypted records or session links.

## Local analysis and recommendations

Analyze the authenticated records on the deployment host:

```sh
palisade analyze-shadow-log \
  --dir /private/local/palisade-shadow/logs \
  --key-file /private/local/palisade-shadow/shadow.key \
  --output /private/local/palisade-shadow/analysis.json
```

The command streams decrypted records through bounded aggregation and writes only the closed `palisade.shadow-analysis.v3` report. It reports decision/action distributions, shadow/canary/enforce counts, exact canary rollout counts, score summaries, raw outcome-event coverage and bounded reason/policy/model counts. A separate bounded SHA-256 decision-ID join produces endpoint/cohort confusion matrices, false-positive rate, abuse recall/precision and mature challenge completion/failure/abandonment/fallback rates with Wilson 95% intervals. Decision IDs and digests are never emitted. Duplicate decisions, conflicting labels, duplicate terminal outcomes, endpoint mismatches, unknown IDs, legacy unlinked outcomes and unresolved mature challenges remain explicit. Canary comparisons remain grouped by rollout ID and endpoint and are descriptive rather than causal. `--output` creates a new `0600` file outside Git and never overwrites an existing report.

Default scan budgets are 4096 managed files, 10 million records, 16 GiB of encrypted input and one million decision links. `--max-files`, `--max-records`, `--max-encrypted-bytes` and `--max-decision-links` may lower or raise them only within compiled hard caps; the linkage hard maximum is five million. Distinct reason, policy and model values are also bounded; exceeding a budget fails closed instead of growing memory without limit.

The v3 recommendation gates are deliberately conservative:

- at least 1000 decisions across a representative traffic cycle;
- at least 24 hours between the first and last authenticated record before a rollout can be signed;
- at least 10% unique decisions with a linked, unambiguous confirmed label;
- at least 100 linked confirmed-human decisions and 100 linked operator-confirmed-abuse decisions;
- review when computed challenge rate exceeds 5%;
- after at least 100 mature challenged decisions, review when linked failure, abandonment, unresolved or ambiguous outcomes together exceed 10%;
- any risky action actually enforced by a record marked `shadow` is a critical safety violation.

Meeting the data gates produces only `operator_review_candidate` and `review_reversible_canary`. `automatic_enforcement` is always `false`. Wilson intervals quantify sampling uncertainty for the named aggregate proportion; they do not repair missing linkage, contaminated labels or cohort selection and therefore do not establish a false-positive rate. Accessibility results, rollback readiness and operator approval remain external release gates. Sparse or contaminated labels produce concrete data-collection recommendations rather than an enforcement recommendation.

To evaluate the exact linked decision stream on a time-separated boundary, run
the separate [`evaluate-shadow-holdout`](SHADOW_HOLDOUT.md) command. Delayed
outcomes remain assigned to baseline or holdout by their decision's record
time, never by outcome arrival time. Its report is aggregate, owner-only and
cannot authorize enforcement.

Promotion uses the separate [signed rollout workflow](ROLLOUT.md). Full enforcement review requires at least 1000 recorded decisions attributed to the exact named predecessor canary on the exact recommended endpoint; unrelated historical canaries or a different endpoint do not satisfy that gate.

The current contracts are [`schemas/shadow-record-v3.schema.json`](../schemas/shadow-record-v3.schema.json), [`schemas/shadow-analysis-report-v3.schema.json`](../schemas/shadow-analysis-report-v3.schema.json) and [`schemas/shadow-holdout-report-v1.schema.json`](../schemas/shadow-holdout-report-v1.schema.json). Shadow-record v3 adds the closed `delay` action; the reader keeps authenticated v1 and v2 records readable, while rejecting `delay` in older record versions. Aggregate report v3 treats the zero-valued `delay` counter as an optional additive field so existing validated reports remain readable. All newly written decisions include a canonical cohort and all new outcomes require linkage. Historical v1/v2 analysis reports are rejected by the v3 runtime and must be regenerated locally from encrypted logs. Keep generated reports beside the private logs, outside Git. They are aggregate but may still disclose operational security posture and should not be published automatically.

AES-GCM detects changes to records that are present, while sequential counters detect internal gaps and reordering. It cannot prove that an entire file was deleted or rolled back, and a crash can leave the newest frame incomplete; verification then fails that file. Use host audit logging, a protected append-only filesystem or independent encrypted backups when deletion resistance or crash recovery is required. Retention intentionally deletes complete managed files, so the sink is append-only within its active retention set rather than immutable forever.

Never store the directory or key in Git, attach logs to public issues, upload them to external services, or expose them through public share links. Run `make privacy-check` before every commit.
