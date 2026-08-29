# Architecture and technology stack

PALISADE is a privacy-limited bot-defense control plane. It is designed to sit
behind an origin adapter or reverse proxy, receive normalized signals, produce
explainable decisions and measure those decisions locally before enforcement.
It is not a packet sniffer, a general log warehouse or a raw-vendor-event bus.

## Stack

| Layer | Technology | Responsibility |
|---|---|---|
| Request hot path | Go 1.27 | HTTP API, session state, detectors, score fusion, policy, replay and encrypted shadow records |
| Reference origin adapter | Go `net/http` | Closed request classification, proof/session exchange, result application and same-origin challenge relay |
| Policy | CEL via `cel-go` | Ordered, deterministic rules over three scores and closed contextual fields |
| Browser sensor | TypeScript, Node.js 24, pnpm 11.24 | Same-origin, bucketed interaction events without text, form values or exact pointer paths |
| Dashboard | React and TypeScript | Embedded operational view; it is not a raw-data explorer |
| Contracts | OpenAPI 3.1 and protobuf | HTTP and future typed service contracts |
| Offline research | Python and Go CLIs | Local-only import, replay, evaluation and aggregate reporting |
| Runtime state | Bounded in-memory stores | Five-minute event/session windows for the current single-process baseline |
| Challenge state | Bounded in-memory capability store | Short-lived session/action/endpoint binding and atomic one-time redemption |
| Local measurement | AES-256-GCM files | Optional append-only decision/outcome stream with rotation and retention |
| Rollout review | Deterministic closed JSON | Report-hash binding, machine gates, narrow recommended scope and explicit operator checklist; never executable |
| Rollout approval | Ed25519 signed JSON | Expiring endpoint/action/cohort scope reviewed by an operator |
| Sovereignty inventory | Deterministic closed JSON | Product invariants separated from unverified, non-identifying operator declarations |

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
encrypted records ───────── analyze-shadow-log ─> aggregate endpoint intervals
                                  periodic worker ─> atomic owner-only report
                                                        │
loopback console ─────────── validated report feed <─────┘
aggregate report ───────── prepare-review ─────> non-executable hash-bound proposal
review proposal ────────── operator signature ─> bounded canary/enforce plan
origin middleware ───────── POST /v1/origin-check ─> 204 / 429 / 403
                                                      │ challenge
                                                      v
signed browser session ──── /v1/challenge/* ────────> one-time bound redemption

loopback admin listener ─── /v1/admin/summary ──────> counters + validated aggregate report
```

In a sensor-only shadow deployment, an optional server-trusted profile turns
each accepted event batch into one internal shadow decision after ingestion.
This path uses the fresh aggregate event count, returns no decision body to the
browser and writes only the same closed encrypted decision record. It is a
temporary collection bridge, not an enforcement path, and is mutually exclusive
with signed rollouts and the authoritative origin decision stream.

`automation`, `intent` and `continuity` remain separate dimensions. Automation
alone is not abuse. In `shadow` mode, a computed `throttle`, `challenge` or
`block` is returned for measurement but the enforced action is only `allow` or
`observe`. The analysis command reports linked endpoint/cohort Wilson 95%
intervals and aggregate shadow/canary comparisons; it cannot turn enforcement
on. New outcomes require the exact decision ID. False-positive rate, recall and
precision include only unique decisions with one unambiguous confirmed label;
legacy unlinked, duplicate, unknown and endpoint-mismatched outcomes remain
explicit measurement loss. Canary comparisons are not a causal experiment.
`prepare-review` deterministically selects at most one eligible public endpoint
that has risky shadow actions and at least 100 uniquely linked decisions from
each confirmed label class. It records every
machine and operator gate, but its artifact is not accepted by the runtime.

An expiring Ed25519-signed plan binds operator approval to the exact aggregate
report hash and reproducible review proposal, including runtime policy/model,
endpoint class, stable canary cohort and maximum action. The signing CLI has no
scope-widening flags. Full enforcement review must reference the exact measured
predecessor canary on the exact same endpoint.

## Trust and persistence boundaries

- Browser-supplied event batches are untrusted and bounded.
- Deployment policy alerts, verified-bot identity, honeypot counts and external
  scores must be set by a trusted server-side adapter, never copied from a
  client-controlled header without an authenticated proxy boundary.
- The public API accepts only closed normalized fields. Raw upstream payloads,
  IP addresses, cookies, tokens and request bodies are not detector inputs.
- The reference decision service has no mandatory vendor control-plane,
  telemetry-export or external runtime call. Optional hosting, proxy,
  reputation, monitoring and support services remain deployment-owned choices;
  `sovereignty-report` records only a closed operator attestation and does not
  discover or certify those external flows.
- The reference middleware never forwards the application URL, query, body or
  user-agent value. A process-random HMAC of method and request target binds a
  completed challenge to one local retry without persisting that target.
- Live session/event state is currently process-local and expires in memory.
- Challenge state is process-local, bounded to 100,000 entries and expires in
  at most 15 minutes. Restart invalidates outstanding capabilities; replicas
  must not share challenge traffic until an atomic shared-state implementation
  preserves the same bindings.
- Decision and outcome persistence is optional and local. It is enabled only
  with `--shadow-log-dir` and `--shadow-log-key-file`.
- Administrative assets and summaries are absent from the public listener. A
  separate loopback-only listener requires a distinct admin bearer credential,
  exposes no row-level data and does not read the encrypted log at request time.
- Periodic analysis is a separate local process. It owns log/key access and
  publishes only a validated aggregate report through a same-directory atomic
  rename. The serving process polls that report and retains its last valid
  snapshot when an update is missing, partial or invalid.

See [Sovereignty Report](SOVEREIGNTY.md), [reference origin adapter](ORIGIN_ADAPTER.md), [signal sources](SIGNAL_SOURCES.md), [privacy boundaries](privacy/DATA_BOUNDARIES.md),
[native challenge](CHALLENGE.md), [shadow logging](SHADOW_LOG.md), [automated analysis](ANALYSIS_AUTOMATION.md), [Operator Console](OPERATOR_CONSOLE.md), [signed rollout](ROLLOUT.md) and the [OpenAPI contract](../api/openapi.yaml).
