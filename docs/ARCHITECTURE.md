# Architecture and technology stack

PALISADE is a privacy-limited bot-defense control plane. It is designed to sit
behind an origin adapter or reverse proxy, receive normalized signals, produce
explainable decisions and measure those decisions locally before enforcement.
It is not a packet sniffer, a general log warehouse or a raw-vendor-event bus.

## Stack

| Layer | Technology | Responsibility |
|---|---|---|
| Request hot path | Go 1.27 | HTTP API, session state, detectors, score fusion, policy, replay and encrypted shadow records |
| Policy | CEL via `cel-go` | Ordered, deterministic rules over three scores and closed contextual fields |
| Browser sensor | TypeScript, Node.js 24, pnpm 11.24 | Same-origin, bucketed interaction events without text, form values or exact pointer paths |
| Dashboard | React and TypeScript | Embedded operational view; it is not a raw-data explorer |
| Contracts | OpenAPI 3.1 and protobuf | HTTP and future typed service contracts |
| Offline research | Python and Go CLIs | Local-only import, replay, evaluation and aggregate reporting |
| Runtime state | Bounded in-memory stores | Five-minute event/session windows for the current single-process baseline |
| Local measurement | AES-256-GCM files | Optional append-only decision/outcome stream with rotation and retention |

The initial deployment is a modular monolith. A database, message broker or
distributed cache is not required by the baseline. Shared state should be added
only after multi-instance requirements and replay semantics are measured.

## Decision flow

```text
trusted origin or proxy ── POST /v1/decision ─┐
browser sensor ─────────── POST /v1/events ───┼─> session snapshot
                                             │       │
                                             │       v
                                             │  detector registry
                                             │       │ validated evidence
                                             │       v
                                             │  three-score fusion
                                             │       │
                                             │       v
                                             └── CEL policy
                                                     │
                                  action + computed_action + reasons
                                                     │
                            encrypted local shadow decision record

trusted backend ─────────── POST /v1/outcome ─> encrypted outcome record
encrypted records ───────── analyze-shadow-log ─> aggregate recommendations
```

`automation`, `intent` and `continuity` remain separate dimensions. Automation
alone is not abuse. In `shadow` mode, a computed `throttle`, `challenge` or
`block` is returned for measurement but the enforced action is only `allow` or
`observe`. The analysis command can recommend operator review or a reversible
canary; it cannot turn enforcement on.

## Trust and persistence boundaries

- Browser-supplied event batches are untrusted and bounded.
- Deployment policy alerts, verified-bot identity, honeypot counts and external
  scores must be set by a trusted server-side adapter, never copied from a
  client-controlled header without an authenticated proxy boundary.
- The public API accepts only closed normalized fields. Raw upstream payloads,
  IP addresses, cookies, tokens and request bodies are not detector inputs.
- Live session/event state is currently process-local and expires in memory.
- Decision and outcome persistence is optional and local. It is enabled only
  with `--shadow-log-dir` and `--shadow-log-key-file`.

See [signal sources](SIGNAL_SOURCES.md), [privacy boundaries](privacy/DATA_BOUNDARIES.md),
[shadow logging](SHADOW_LOG.md) and the [OpenAPI contract](../api/openapi.yaml).
