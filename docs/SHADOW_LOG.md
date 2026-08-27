# Local encrypted shadow log

The shadow sink is an optional, local-only measurement channel. It records PALISADE decisions and normalized delayed outcomes without placing raw requests, browser events or direct session identifiers on disk. It is disabled unless both `--shadow-log-dir` and `--shadow-log-key-file` are supplied.

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

`POST /v1/outcome` is backend-only and requires the configured bearer API key. When strict session-cookie binding is enabled, the submitted session must also match the signed cookie. A solved challenge is only `challenge_passed`, never `human_confirmed`.

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
  > /private/local/palisade-shadow/analysis.json
```

The command streams decrypted records through bounded aggregation and writes only the closed `palisade.shadow-analysis.v1` report. It reports decision/action distributions, shadow-versus-enforce counts, score minimum/maximum/mean values, outcome coverage, challenge failure/abandonment, endpoint totals, bounded reason-code counts and policy/model versions. It does not emit decision IDs, session links or individual records.

Default scan budgets are 4096 managed files, 10 million records and 16 GiB of encrypted input. `--max-files`, `--max-records` and `--max-encrypted-bytes` may lower or raise them only within compiled hard caps. Distinct reason, policy and model values are also bounded; exceeding a budget fails closed instead of growing memory without limit.

The v1 recommendation gates are deliberately conservative:

- at least 1000 decisions across a representative traffic cycle;
- at least 10% normalized outcome coverage;
- at least 100 confirmed-human outcomes and 100 operator-confirmed abuse outcomes;
- review when computed challenge rate exceeds 5%;
- after at least 100 challenge results, review when failure plus abandonment exceeds 10%;
- any risky action actually enforced by a record marked `shadow` is a critical safety violation.

Meeting the data gates produces only `operator_review_candidate` and `review_reversible_canary`. `automatic_enforcement` is always `false`. The report cannot establish a false-positive rate by itself: endpoint-specific confidence intervals, cohort coverage, accessibility results, rollback readiness and operator approval remain external release gates. Sparse or contaminated labels produce concrete data-collection recommendations rather than an enforcement recommendation.

The JSON contract is [`schemas/shadow-analysis-report-v1.schema.json`](../schemas/shadow-analysis-report-v1.schema.json). Keep generated reports beside the private logs, outside Git. They are aggregate but may still disclose operational security posture and should not be published automatically.

AES-GCM detects changes to records that are present, while sequential counters detect internal gaps and reordering. It cannot prove that an entire file was deleted or rolled back, and a crash can leave the newest frame incomplete; verification then fails that file. Use host audit logging, a protected append-only filesystem or independent encrypted backups when deletion resistance or crash recovery is required. Retention intentionally deletes complete managed files, so the sink is append-only within its active retention set rather than immutable forever.

Never store the directory or key in Git, attach logs to public issues, upload them to external services, or expose them through public share links. Run `make privacy-check` before every commit.
