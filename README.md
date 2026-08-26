<p align="center">
  <img src="brand/logo/palisade-horizontal.svg" width="410" alt="PALISADE">
</p>

<p align="center">
  Behavior-first bot defense with explainable, privacy-limited decisions.
</p>

> [!IMPORTANT]
> PALISADE is an early defensive prototype. It does not claim perfect bot detection and must begin in shadow mode. No CAPTCHA or behavior model can guarantee 100% separation against an adaptive attacker.

## What exists today

The first vertical slice is runnable: a Go decision service, short-lived replay-protected proof tokens, bounded in-memory sessions, detector evidence, three-dimensional score fusion, CEL policy evaluation, deterministic JSONL replay, a privacy-limited browser sensor and an embedded control-room dashboard.

PALISADE keeps three questions separate:

- **Automation risk:** how likely is the client automated?
- **Abuse intent:** how likely is the current action harmful?
- **Account continuity:** how consistent is this session with its established behavior?

Every response includes stable reason codes, policy/model versions and an expiry time. Verified beneficial bots can be allowed independently from abusive automation.

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

Production mode refuses to start without `PALISADE_HMAC_KEY` and `PALISADE_API_KEY`. Development mode intentionally disables proof enforcement and must never face public traffic.

## HTTP surface

| Route | Purpose |
|---|---|
| `GET /health/live` | Process health |
| `GET /health/ready` | Readiness |
| `POST /v1/events` | Same-origin, privacy-limited browser event batches; one-time proof required in production |
| `POST /v1/token` | Authenticated, short-lived action proof issuance |
| `POST /v1/decision` | Explainable risk decision |

The browser sensor never sends keystrokes, form values, DOM text or exact pointer coordinates. See [privacy boundaries](docs/privacy/DATA_BOUNDARIES.md).
The HTTP contract is documented in [OpenAPI](api/openapi.yaml); protobuf contracts live under [`api/proto`](api/proto).

## Architecture

PALISADE starts as a modular monolith so detector APIs, policy behavior and replay fixtures can stabilize before services are split. The hot path stays in Go. TypeScript is limited to the browser sensor and static dashboard; Python is reserved for offline research and evaluation.

```text
browser sensor ──┐
reverse proxy ───┼─> evidence registry -> 3 score fusion -> CEL policy -> action + reasons
Anubis/Cannai ───┤
CrowdSec ────────┘                         └-> deterministic replay/evaluation
```

The first Strain DB deployment should ingest Anubis, Cannai Shield and CrowdSec verdicts in **shadow mode**, then tune thresholds on labeled replay data before any automatic blocking.

See the [roadmap](ROADMAP.md), [evaluation protocol](docs/EVALUATION.md) and [Strain DB pilot plan](docs/STRAIN_DB_PILOT.md).

## Project status and license

The intended core license is **PolyForm Shield 1.0.0**: companies may use and modify PALISADE, including internally and commercially, but may not sell a competing PALISADE-based product. The browser sensor is intended to use Apache-2.0 for frictionless integration.

That resale restriction makes the core **source-available**, not OSI-approved open source. It can still be community-developed and free for companies to use under the final terms.

The exact legal rights holder has not yet been supplied, so the repository currently grants **no license**. See [LICENSE-PENDING.md](LICENSE-PENDING.md). Do not deploy or redistribute this snapshot until the final license notice is completed.
Bundled dependency notices are recorded in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

## Contributing and security

Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a change. Please report security vulnerabilities privately as described in [SECURITY.md](SECURITY.md); do not publish bypass techniques against real installations.
