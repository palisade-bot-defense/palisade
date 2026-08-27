<p align="center">
  <img src="brand/logo/palisade-horizontal.svg" width="410" alt="PALISADE">
</p>

<p align="center">
  Behavior-first bot defense with explainable, privacy-limited decisions.
</p>

> [!IMPORTANT]
> PALISADE is an early defensive prototype. It does not claim perfect bot detection and must begin in shadow mode. No CAPTCHA or behavior model can guarantee 100% separation against an adaptive attacker.

## What exists today

The first vertical slice is runnable: a Go decision service, short-lived replay-protected proof tokens, an optional server-issued signed continuity cookie, bounded in-memory sessions, detector evidence, three-dimensional score fusion, CEL policy evaluation, deterministic JSONL replay, a privacy-limited browser sensor, an embedded control-room dashboard, encrypted local analysis and signed reversible rollout plans.

PALISADE keeps three questions separate:

- **Automation risk:** how likely is the client automated?
- **Abuse intent:** how likely is the current action harmful?
- **Account continuity:** how consistent is this session with its established behavior?

Every decision response includes the enforced `action`, the unmodified `computed_action`, the runtime `mode`, stable reason codes, policy/model versions and an expiry time. The current reported versions are policy `default-v3` and model `transparent-baseline-v6`. Verified beneficial bots can be allowed independently from abusive automation. Session volume and fast bursts remain conservative evidence because the current offline evaluation has too few confirmed-human clients to calibrate a false-positive rate. Completing a proof-of-work challenge is an outcome, not benign-automation evidence; browser automation may complete the same challenge routinely.

## Quick start

Requirements: Go 1.27, Node.js 24 and pnpm 11.24.

```sh
pnpm install --frozen-lockfile
pnpm build
go test ./...
go run ./cmd/palisade serve --dev
```

Open `http://127.0.0.1:8080`. Run the deterministic sample:

```sh
go run ./cmd/palisade replay --file examples/replay/synthetic.jsonl
```

The server always starts from `--mode shadow`. In shadow mode, risky computed actions remain visible as `computed_action`, while the enforced `action` is limited to `allow` or `observe`. Canary/enforcement requires a valid, expiring operator-signed rollout plan; `serve --mode enforce` is rejected. Production refuses to start without `PALISADE_HMAC_KEY` and `PALISADE_API_KEY`; development mode intentionally disables proof enforcement, rejects rollout plans and must never face public traffic. `--require-session-cookie` is a separate integration gate: enable it only after the origin adapter forwards the backend-issued `__Host-palisade_session` cookie on token, event and decision requests.

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
| `POST /v1/outcome` | Backend-authenticated, normalized delayed outcome for the encrypted local shadow sink |

The signed cookie prevents clients from inventing a trusted session identifier, but does not prove that a person, account or unique device is present; starting fresh sessions remains possible. A valid cookie contributes only continuity evidence. The browser sensor never sends keystrokes, form values, DOM text or exact pointer coordinates. See [privacy boundaries](docs/privacy/DATA_BOUNDARIES.md).
The HTTP contract is documented in [OpenAPI](api/openapi.yaml); protobuf contracts live under [`api/proto`](api/proto). The [signal-source guide](docs/SIGNAL_SOURCES.md) contains trust boundaries, request examples and the checked detector extension procedure.

## Local encrypted shadow logging

Shadow decisions and explicitly submitted outcomes can be recorded to an optional local sink. The sink writes authenticated AES-GCM records to new append-only files, rotates by encrypted size or age, deletes only exactly named managed files after the configured retention period, and never stores the raw session ID. Both the key and log directory must be owner-only and outside every Git worktree.

```sh
go run ./cmd/palisade serve \
  --shadow-log-dir /private/local/palisade-shadow/logs \
  --shadow-log-key-file /private/local/palisade-shadow/shadow.key

go run ./cmd/palisade verify-shadow-log \
  --dir /private/local/palisade-shadow/logs \
  --key-file /private/local/palisade-shadow/shadow.key

go run ./cmd/palisade analyze-shadow-log \
  --dir /private/local/palisade-shadow/logs \
  --key-file /private/local/palisade-shadow/shadow.key \
  --output /private/local/palisade-shadow/analysis.json
```

The default rotation limits are 64 MiB or one hour; default retention is seven days. `POST /v1/outcome` requires the backend bearer credential and accepts only closed labels with explicit provenance and confidence. `analyze-shadow-log` authenticates and decrypts the retained files locally, emits aggregate counts, score ranges, endpoint summaries and deterministic recommendations, and never prints records or session links. Its recommendations can hold the deployment in shadow mode or nominate a reversible canary for operator review; they never activate enforcement. The [signed rollout guide](docs/ROLLOUT.md) explains operator approval, exact-canary promotion, origin handling and rollback. See the [shadow-log operations, analysis gates and threat model](docs/SHADOW_LOG.md) before enabling it.

## Architecture

PALISADE starts as a modular monolith so detector APIs, policy behavior and replay fixtures can stabilize before services are split. The hot path stays in Go. TypeScript is limited to the browser sensor and static dashboard; Python is reserved for offline research and evaluation.

```text
browser sensor ────┐
reverse proxy ─────┼─> evidence registry -> 3 score fusion -> CEL policy -> action + reasons
external verdicts ─┤
policy alerts ─────┘                         └-> deterministic replay/evaluation
```

The supported normalized signal classes are browser event counts, server/session continuity, honeypot interactions, challenge verdicts, external risk scores, deployment policy alerts and verified-bot identity. Trusted backend or reverse-proxy adapters submit them through `POST /v1/decision`; browser telemetry uses `POST /v1/events`; delayed ground-truth outcomes use `POST /v1/outcome`. Raw vendor payloads are not accepted by the public decision API.

The first deployment should ingest normalized challenge, external-risk and policy-alert verdicts in **shadow mode**, then tune thresholds on labeled replay data before any automatic blocking. Every replay record must carry an RFC 3339 `observed_at` timestamp that drives session TTLs and decision expiry; records must be globally chronological with equal timestamps allowed. Fixtures can assert `expected_action` and `expected_computed_action` independently.

Authorized historical exports can be normalized with the local-only `palisade import-offline` command. Raw inputs and normalized outputs must stay outside every Git worktree. The importer accepts only `offline_export`, never emits raw rows, and treats upstream policy outcomes as weak labels rather than ground truth. Deployment-local and opt-in community ingestion are future, separate trust boundaries and are not accepted by this command.

See the [architecture and stack](docs/ARCHITECTURE.md), [signal-source integration guide](docs/SIGNAL_SOURCES.md), [signed rollout guide](docs/ROLLOUT.md), [roadmap](ROADMAP.md), [evaluation protocol](docs/EVALUATION.md) and [shadow-log operations guide](docs/SHADOW_LOG.md).

## Project status and license

The PALISADE server, dashboard, policies, CLI and documentation are licensed under **GNU AGPL-3.0-only**. The browser sensor under [`sensor/`](sensor/) is independently licensed under **Apache-2.0** for straightforward integration. See [the licensing map](LICENSING.md), the root [`LICENSE`](LICENSE) and [`sensor/LICENSE`](sensor/LICENSE).

Commercial support, managed hosting and alternative licensing may be offered separately. The published AGPL-3.0-only and Apache-2.0 grants remain valid for their respective code. No software license grants rights to PALISADE names or logos beyond reasonable attribution.
Bundled dependency notices are recorded in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

## Contributing and security

Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a change. Please report security vulnerabilities privately as described in [SECURITY.md](SECURITY.md); do not publish bypass techniques against real installations.

The publish-ready GitHub organization profile and its separate-repository setup checklist are maintained under [`docs/github-org`](docs/github-org/SETUP.md).
