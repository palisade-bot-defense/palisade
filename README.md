<p align="center">
  <img src="brand/logo/palisade-horizontal.svg" width="410" alt="PALISADE">
</p>

<p align="center">
  Open-source, explainable signal fusion for bot and abuse decisions.
</p>

> [!IMPORTANT]
> PALISADE is an early defensive prototype. It does not claim perfect bot detection and must begin in shadow mode. Its false-positive rate is not yet calibrated on a representative confirmed-human cohort. No CAPTCHA, fingerprint or behavior model can guarantee 100% separation against an adaptive attacker.

## Project focus

PALISADE is developed as a self-hosted open-source project: an explainable
fusion and policy layer for bounded bot and abuse signals. The current priority
is a reproducible local experience, representative shadow evaluation and useful
adapters—not hosted SaaS, managed operations, billing or commercial product
tiers. Strong edge signals such as protocol fingerprints and reputation can be
normalized by a trusted deployment adapter; PALISADE does not need to own every
detector to make their combined decision auditable.

## What exists today

The first vertical slice is runnable: a Go decision service, short-lived replay-protected proof tokens, an optional server-issued signed continuity cookie, bounded in-memory sessions, detector evidence, three-dimensional score fusion, CEL policy evaluation, deterministic JSONL replay, a privacy-limited browser sensor, an embedded control-room dashboard, encrypted local analysis, signed reversible rollout plans and a session/action/endpoint-bound native challenge lifecycle.

PALISADE keeps three questions separate:

- **Automation risk:** how likely is the client automated?
- **Abuse intent:** how likely is the current action harmful?
- **Account continuity:** how consistent is this session with its established behavior?

Every decision response includes the enforced `action`, the unmodified `computed_action`, the runtime `mode`, stable reason codes, policy/model versions and an expiry time. The current reported versions are policy `default-v5` and model `transparent-baseline-v10`. The progressive action vocabulary is `allow → observe → delay → throttle → challenge → block`: `delay` is a one-second retry response, never a sleep in the PALISADE hot path, and is enforced only by a valid signed rollout. Beneficial crawler handling requires a purpose class, a strong local verification method and an indexable public endpoint; a user-agent or `verified_bot` boolean alone is never allowlisted, and training crawlers are policy-controlled. The Go origin adapter can atomically watch a signed, expiring local crawler registry and falls back to `unknown` after expiry without performing vendor or DNS lookups in the request path. See [crawler identity and SEO/GEO safety](docs/CRAWLER_IDENTITY.md). Session volume, fast bursts and broad navigation sweeps remain conservative evidence because the current offline evaluation has too few confirmed-human clients to calibrate a false-positive rate. Completing a proof-of-work challenge is an outcome, not benign-automation evidence; browser automation may complete the same challenge routinely. Browser-event counts create benign continuity evidence only after PALISADE verifies them against its own bounded event store. A score fixed at `0.5` means that no evidence moved that dimension away from its neutral prior; it is not a measured 50% abuse probability.

## Quick start

Requirements: Go 1.27, Node.js 24 and pnpm 11.24.

```sh
pnpm install --frozen-lockfile
pnpm build
go test ./...
go run ./cmd/palisade serve --dev
```

Open the local Operator Console at `http://127.0.0.1:8081` and enter
`development-only-admin`. The decision API remains separate on
`http://127.0.0.1:8080`. Run the deterministic sample:

```sh
go run ./cmd/palisade replay --file examples/replay/synthetic.jsonl
```

The server always starts from `--mode shadow`. In shadow mode, risky computed actions remain visible as `computed_action`, while the enforced `action` is limited to `allow` or `observe`. Canary/enforcement requires a valid, expiring operator-signed rollout plan; `serve --mode enforce` is rejected. Production refuses to start without `PALISADE_HMAC_KEY`, `PALISADE_API_KEY` and a distinct `PALISADE_ADMIN_KEY` of at least 32 bytes. The Operator Console is served only from the separate loopback-only `--admin-listen` address and its key remains in browser memory; the public decision listener never serves admin assets or summaries. Development mode intentionally disables proof enforcement, rejects rollout plans and must never face public traffic. `--require-session-cookie` is a separate integration gate: enable it only after the origin adapter forwards the backend-issued `__Host-palisade_session` cookie on token, event and decision requests.

For a sensor-only shadow deployment, a static `--event-shadow-action` plus `--event-shadow-endpoint-class` can classify a single surface. Multi-surface pilots should use `--event-shadow-from-proof`: the trusted backend mints each one-time `events` proof with a closed request action and endpoint class derived from its route table, while the browser only forwards the signed proof. A server-owned contiguous batch counter drives the decision sequence; browser event numbers remain event-store deduplication data and cannot create request-sequence-gap evidence. Neither mode accepts URLs, paths or referers. Both require the encrypted sink and signed session cookie, are unavailable with a signed rollout, and must be disabled once origin middleware becomes the authoritative decision stream.

## HTTP surface

| Route | Purpose |
|---|---|
| `GET /health/live` | Process health |
| `GET /health/ready` | Readiness |
| `POST /v1/session` | Backend-authenticated issuance of a Secure, HttpOnly, SameSite=Lax continuity cookie |
| `POST /v1/events` | Same-origin, privacy-limited browser event batches; one-time proof required in production |
| `POST /v1/token` | Authenticated, short-lived action proof issuance |
| `POST /v1/decision` | Explainable risk decision |
| `POST /v1/origin-check` | Score once and return the bounded HTTP enforcement result for origin middleware |
| `POST /v1/origin-coverage` | Accept authenticated cumulative protected-handler counts from reference adapters |
| `GET /v1/challenge/{id}` | Retrieve the signed-session-bound accessible step-up metadata |
| `POST /v1/challenge/verify` | Exchange a ready challenge for a short-lived redemption capability |
| `POST /v1/challenge/redeem` | Consume that capability exactly once for its bound action and endpoint class |
| `POST /v1/challenge/fallback` | Close the challenge and record use of the deployment fallback |
| `POST /v1/outcome` | Backend-authenticated, normalized delayed outcome for the encrypted local shadow sink |

The separate administrative listener exposes `GET /v1/admin/summary` plus the
embedded Operator Console. Its response contains only process counters,
configuration versions and an optional validated aggregate report. It never
contains decisions, sessions, tokens, source paths or raw shadow-log records.
See the [Operator Console guide](docs/OPERATOR_CONSOLE.md).

The signed cookie prevents clients from inventing a trusted session identifier, but does not prove that a person, account or unique device is present; starting fresh sessions remains possible. A valid cookie contributes only continuity evidence. The browser sensor never sends keystrokes, form values, DOM text or exact pointer coordinates. See [privacy boundaries](docs/privacy/DATA_BOUNDARIES.md).
The HTTP contract is documented in [OpenAPI](api/openapi.yaml); protobuf contracts live under [`api/proto`](api/proto). The [signal-source guide](docs/SIGNAL_SOURCES.md) contains trust boundaries, request examples and the checked detector extension procedure. The [native challenge guide](docs/CHALLENGE.md) documents the origin handshake, accessibility contract, exact one-time binding and single-instance limit.

Applications built with Go `net/http` can use the included [`pkg/palisadehttp`](pkg/palisadehttp) reference middleware. It creates signed continuity sessions, submits only normalized signals, applies pass/delay/throttle/challenge/block results, renders the same-origin accessible challenge and grants exactly one retry for the original method and request target. It also provides a backend-only route-classified sensor-proof helper and, after a validated pass, an opaque request-scoped outcome handle for linking a closed result to the exact decision without handling a raw PALISADE session ID. Its availability policy is an explicit deployment choice. See the [origin-adapter guide](docs/ORIGIN_ADAPTER.md).

The reference middleware can explicitly enable privacy-safe coverage reporting.
It sends cumulative counts for completed requests in the protected handler,
split only by PALISADE's nine endpoint classes and closed handling outcomes.
The Operator Console displays evaluated requests, bound challenge retries,
availability bypasses and adapter rejections. This is not total website
traffic: CDN, proxy and routes outside the middleware remain outside the
denominator.

## Local encrypted shadow logging

Shadow decisions and explicitly submitted outcomes can be recorded to an optional local sink. The sink writes authenticated AES-GCM records to new append-only files, rotates by encrypted size or age, deletes only exactly named managed files after the configured retention period, and never stores the raw session ID. Both the key and log directory must be owner-only and outside every Git worktree.

```sh
go run ./cmd/palisade serve \
  --require-session-cookie \
  --event-shadow-action read \
  --event-shadow-endpoint-class public_content \
  --shadow-log-dir /private/local/palisade-shadow/logs \
  --shadow-log-key-file /private/local/palisade-shadow/shadow.key

# Production multi-surface collection. The origin requests route-specific
# events proofs from /v1/token with request_action and endpoint_class.
go run ./cmd/palisade serve \
  --require-session-cookie \
  --event-shadow-from-proof \
  --shadow-log-dir /private/local/palisade-shadow/logs \
  --shadow-log-key-file /private/local/palisade-shadow/shadow.key

go run ./cmd/palisade verify-shadow-log \
  --dir /private/local/palisade-shadow/logs \
  --key-file /private/local/palisade-shadow/shadow.key

go run ./cmd/palisade analyze-shadow-log \
  --dir /private/local/palisade-shadow/logs \
  --key-file /private/local/palisade-shadow/shadow.key \
  --output /private/local/palisade-shadow/analysis.json \
  --watch-interval 5m

go run ./cmd/palisade serve \
  --admin-analysis-report /private/local/palisade-shadow/analysis.json \
  --shadow-log-dir /private/local/palisade-shadow/logs \
  --shadow-log-key-file /private/local/palisade-shadow/shadow.key
```

The default rotation limits are 64 MiB or one hour; default retention is seven days. `POST /v1/outcome` requires the backend bearer credential, the exact `decision_id`, and a closed label with compatible provenance and confidence. `analyze-shadow-log` authenticates and decrypts retained files locally, joins outcomes to decisions under a fixed memory budget, and emits only aggregate counts, endpoint/cohort Wilson 95% intervals, same-endpoint shadow/canary comparisons and deterministic recommendations. False-positive rate, abuse recall and precision use only uniquely linked confirmed labels; ambiguous, duplicate, mismatched and legacy-unlinked outcomes are counted separately. Challenge rates use only challenged decisions old enough for the 15-minute outcome window, with unresolved and conflicting results explicit. The coarse cohort vocabulary is deployment-supplied and never inferred as identity, disability or fingerprint evidence. The Operator Console polls the atomically replaced report, retains the last valid version after a rejected update and never receives the log key. Recommendations can hold the deployment in shadow mode or nominate a reversible canary for operator review; they never activate enforcement. `prepare-review` requires risky shadow actions plus at least 100 uniquely linked confirmed-human and 100 uniquely linked operator-confirmed-abuse decisions on the exact proposed endpoint. `prepare-rollout` can sign only that exact reviewed hash and scope. See the [automated analysis operations](docs/ANALYSIS_AUTOMATION.md), [signed review and rollout guide](docs/ROLLOUT.md) and [shadow-log threat model](docs/SHADOW_LOG.md) before enabling it.

The browser sensor defaults to—and enforces a minimum of—one bounded flush every 15 seconds. Its proof callback is called with the literal action `events`; minting that proof for `read` or another action is rejected. Accepted batches receive `202`. With event-triggered shadow evaluation enabled, `X-Palisade-Shadow-Evaluation` reports `recorded` or `dropped`; a dropped evaluation never causes the already accepted batch to be retried.

The local Operator Console shows the privacy-safe, process-local collection
funnel from closed route-context proofs through accepted event batches to
recorded shadow decisions, with rejected and dropped counts visible. It does
not claim site-traffic coverage: PALISADE has no authenticated denominator for
all requests reaching the protected origin. See the
[Operator Console guide](docs/OPERATOR_CONSOLE.md).

## Architecture

PALISADE starts as a modular monolith so detector APIs, policy behavior and replay fixtures can stabilize before services are split. The hot path stays in Go. TypeScript is limited to the browser sensor and static dashboard; Python is reserved for offline research and evaluation.

```text
browser sensor ────┐
reverse proxy ─────┼─> evidence registry -> 3 score fusion -> CEL policy -> action + reasons
external verdicts ─┤
policy alerts ─────┘                         └-> deterministic replay/evaluation
```

The supported normalized signal classes are browser event counts, server/session continuity, honeypot interactions, challenge verdicts, external risk scores, deployment policy alerts and verified-bot identity. Trusted backend or reverse-proxy adapters submit them through `POST /v1/decision`; browser telemetry uses `POST /v1/events`; delayed ground-truth outcomes use `POST /v1/outcome`. Raw vendor payloads are not accepted by the public decision API.

The required test pyramid, coverage and in-process latency gates are documented in [the testing strategy](docs/TESTING.md). All committed fixtures are synthetic; deployment logs and private analysis reports are excluded from tests and CI.

The first deployment should ingest normalized challenge, external-risk and policy-alert verdicts in **shadow mode**, then tune thresholds on labeled replay data before any automatic blocking. Every replay record must carry an RFC 3339 `observed_at` timestamp that drives session TTLs and decision expiry; records must be globally chronological with equal timestamps allowed. Fixtures can assert `expected_action` and `expected_computed_action` independently.

Authorized historical exports can be normalized with the local-only `palisade import-offline` command. Raw inputs and normalized outputs must stay outside every Git worktree. The importer accepts only `offline_export`, never emits raw rows, and treats upstream policy outcomes as weak labels rather than ground truth. Deployment-local and opt-in community ingestion are future, separate trust boundaries and are not accepted by this command.

See the [architecture and stack](docs/ARCHITECTURE.md), [reference origin adapter](docs/ORIGIN_ADAPTER.md), [signal-source integration guide](docs/SIGNAL_SOURCES.md), [native challenge lifecycle](docs/CHALLENGE.md), [automated local analysis](docs/ANALYSIS_AUTOMATION.md), [signed rollout guide](docs/ROLLOUT.md), [roadmap](ROADMAP.md), [evaluation protocol](docs/EVALUATION.md) and [shadow-log operations guide](docs/SHADOW_LOG.md).

## Project status and license

The PALISADE server, dashboard, policies, CLI and documentation are licensed under **GNU AGPL-3.0-only**. The browser sensor under [`sensor/`](sensor/) is independently licensed under **Apache-2.0** for straightforward integration. See [the licensing map](LICENSING.md), the root [`LICENSE`](LICENSE) and [`sensor/LICENSE`](sensor/LICENSE).

No software license grants rights to PALISADE names or logos beyond reasonable attribution.
Bundled dependency notices are recorded in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

The public project website lives in [`website/`](website/). It contains no
analytics, forms or customer-data collection and describes only capabilities
available in this repository.

## Contributing and security

Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a change. Please report security vulnerabilities privately as described in [SECURITY.md](SECURITY.md); do not publish bypass techniques against real installations.

The publish-ready GitHub organization profile and its separate-repository setup checklist are maintained under [`docs/github-org`](docs/github-org/SETUP.md).
