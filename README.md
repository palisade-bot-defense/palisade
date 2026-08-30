<p align="center">
  <img src="brand/logo/palisade-horizontal.svg" width="410" alt="PALISADE">
</p>

<p align="center">
  EU-first, self-hosted bot defense with explainable, privacy-limited decisions.
</p>

> [!IMPORTANT]
> PALISADE is an early defensive prototype. It does not claim perfect bot detection and must begin in shadow mode. Its false-positive rate is not yet calibrated on a representative confirmed-human cohort. No CAPTCHA, fingerprint or behavior model can guarantee 100% separation against an adaptive attacker.

## Project focus

PALISADE is an EU-first, self-hosted and open-source fusion and policy layer for
bounded bot and abuse signals. It runs on infrastructure selected and controlled
by the operator—including on-premises or in an EU region—without a mandatory
PALISADE cloud account, hosted control plane, central telemetry service or
cross-site identity graph. The operator chooses the processing location,
retention, keys, enabled signals and enforcement policy.

The current priority is a reproducible local experience, representative shadow
evaluation and useful adapters—not hosted SaaS, managed operations, billing or
commercial product tiers. Strong edge signals such as protocol fingerprints and
reputation can be normalized at the trusted deployment boundary; PALISADE does
not need to receive their raw values or own every detector to make the combined
decision auditable.

## Data sovereignty by architecture

| Area | PALISADE default |
|---|---|
| **Deployment** | The service runs in the operator's environment. Requests do not need to pass through a PALISADE-operated network. |
| **Data flow** | The decision API accepts closed, normalized signal classes. Raw IP addresses, ASNs, user agents, URLs, protocol fingerprints and vendor payloads stay outside PALISADE. |
| **Browser collection** | The first-party sensor excludes form content, keystrokes, DOM text and exact pointer coordinates. Missing sensor data remains neutral. |
| **Storage** | Runtime state is bounded and local. Optional shadow logs are encrypted with operator-held keys, retained locally and deleted on an operator-defined schedule. |
| **Evaluation** | Historical exports are imported and analyzed offline. Raw inputs, normalized deployment data and private reports must remain outside Git worktrees and are never required to be shared with the project. |
| **Decisions** | Every result carries stable reason codes plus policy and model versions instead of relying on an opaque remote score. |
| **Software freedom** | The server is AGPL-3.0-only and the embeddable sensor is Apache-2.0, allowing inspection, independent operation and community review. |

When PALISADE and its selected upstream adapters are operated entirely on
operator-controlled EU infrastructure, PALISADE itself requires no
PALISADE-initiated transfer to a third country. External hosting, reputation,
monitoring or support providers remain explicit deployment choices and must be
assessed separately.

> [!NOTE]
> Self-hosting and data minimization do not automatically make a deployment
> GDPR-, ePrivacy- or TDDDG-compliant. The operator remains responsible for the
> purpose, legal basis, transparency, data-subject rights, retention, security,
> processor relationships and any required DPIA. The browser sensor and
> first-party cookie need a deployment-specific terminal-access assessment. Use
> the [EU privacy deployment checklist](docs/privacy/DEPLOYMENT_CHECKLIST.md)
> before enabling real traffic or enforcement.

Generate the deterministic [Sovereignty Report](docs/SOVEREIGNTY.md) to keep
PALISADE product invariants separate from closed, operator-declared deployment
facts:

```sh
go run ./cmd/palisade sovereignty-report \
  --processing-location eu_region \
  --storage-location eu_only \
  --external-runtime-services none \
  --operator-held-keys yes
```

The result is machine-readable but deliberately not a compliance certificate.
See [product differentiation](docs/DIFFERENTIATION.md) for the target users,
market boundary, defensible open-source assets and claims policy.
The companion [runtime egress inventory](docs/RUNTIME_EGRESS.md) accounts for
every reviewed outbound source callsite, while the [machine-readable data
map](docs/DATA_MAP.md) records accepted classes, destinations and persistence.

## What exists today

The first vertical slice is runnable: a Go decision service, short-lived replay-protected proof tokens, an optional server-issued signed continuity cookie, bounded in-memory sessions, detector evidence, three-dimensional score fusion, CEL policy evaluation, deterministic JSONL replay, a privacy-limited browser sensor, an embedded control-room dashboard, encrypted local analysis, signed reversible rollout plans and a session/action/endpoint-bound native challenge lifecycle.

PALISADE keeps three questions separate:

- **Automation risk:** how likely is the client automated?
- **Abuse intent:** how likely is the current action harmful?
- **Account continuity:** how consistent is this session with its established behavior?

Every decision response includes the enforced `action`, the unmodified
`computed_action`, the runtime `mode`, stable reason codes, policy/model
versions and an expiry time. The current reported versions are policy
`default-v5` and model `transparent-baseline-v13`. The progressive action
vocabulary is `allow → observe → delay → throttle → challenge → block`:
`delay` is a one-second retry response, never a sleep in the PALISADE hot path,
and is enforced only by a valid signed rollout.

Signed rollouts treat their throttle and temporary-block durations as hard
maxima. Model v12 scales only those durations from a humane minimum using
closed endpoint value, sufficiently strong suspicious-evidence confidence,
bounded recent session behavior and short-lived retry history. It never raises
the policy action, exceeds the signed maximum or persists this response state.

Beneficial crawler handling requires a purpose class, a strong local
verification method and an indexable public endpoint; a user-agent or
`verified_bot` boolean alone is never allowlisted, and training crawlers are
policy-controlled. The Go origin adapter can atomically watch a signed,
expiring local crawler registry and falls back to `unknown` after expiry without
performing vendor or DNS lookups in the request path. See
[crawler identity and SEO/GEO safety](docs/CRAWLER_IDENTITY.md).

Trusted edge adapters may normalize TLS/JA4, HTTP/2, ASN and IP-reputation
results into closed classes. Raw fingerprints, addresses, ASNs and vendor
labels never enter PALISADE, and no browser-like, residential or low-risk class
is treated as human evidence. Session volume, fast bursts and broad navigation
sweeps remain conservative evidence because the current offline evaluation has
too few confirmed-human clients to calibrate a false-positive rate. Completing
a proof-of-work challenge is an outcome, not benign-automation evidence;
browser automation may complete the same challenge routinely. Browser-event
counts create benign continuity evidence only after PALISADE verifies them
against its own bounded event store. A score fixed at `0.5` means that no
evidence moved that dimension away from its neutral prior; it is not a measured
50% abuse probability.

## Quick start

The fastest path is the loopback-only synthetic demo. It never loads private
traffic and cannot enforce a risky action:

```sh
docker compose up --build
```

Open `http://127.0.0.1:8081/?demo=1`. The banner and all sample values are
explicitly marked synthetic; they demonstrate the Operator Console contract,
not measured detection efficacy. The demo-only container exception binds the
admin listener inside the container while Docker publishes it only on host
loopback. Do not copy `--dev-container-admin` into a deployment configuration.

After building locally, run `make operator-shadow-drill` to exercise the
production-secret, signed-session, one-time-proof, encrypted Shadow recording,
aggregate analysis and fail-safe restart path entirely on loopback with
synthetic records. See the [Operator Shadow drill](docs/OPERATOR_SHADOW_DRILL.md)
for its exact assertions and limitations.

For local source development, requirements are Go 1.27, Node.js 24 and pnpm
11.24:

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
| `POST /v1/decoy/issue` | Backend-authenticated issuance of a session/endpoint-bound opaque decoy capability |
| `POST /v1/decoy/hit` | Consume a native decoy capability once and queue closed evidence for the next matching decision |
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
The HTTP contract is documented in [OpenAPI](api/openapi.yaml); protobuf contracts live under [`api/proto`](api/proto). Their closed classes are frozen together by the language-neutral [normalized signal contract](docs/NORMALIZED_SIGNAL_CONTRACT.md) and executable drift tests. The [signal-source guide](docs/SIGNAL_SOURCES.md) contains trust boundaries, request examples and the checked detector extension procedure. The [native decoy guide](docs/DECOYS.md) specifies the backend lifecycle and evidence semantics. The [native challenge guide](docs/CHALLENGE.md) documents the origin handshake, accessibility contract, exact one-time binding and single-instance limit.

The [v1 compatibility policy](docs/COMPATIBILITY.md) distinguishes current stable contracts from legacy read-only artifacts and unlisted historical drafts. A machine-readable [freeze manifest](manifests/compatibility-freeze-v1.json) pins public APIs, current schemas, the threat model and operator runbooks; `make compatibility-check` rejects silent drift. This is a compatibility control, not independent security or legal assurance.

Applications built with Go `net/http` can use the included [`pkg/palisadehttp`](pkg/palisadehttp) reference middleware. It creates signed continuity sessions, submits only normalized signals, applies pass/delay/throttle/challenge/block results, renders the same-origin accessible challenge and grants exactly one retry for the original method and request target. It also provides a backend-only route-classified sensor-proof helper and, after a validated pass, an opaque request-scoped outcome handle for linking a closed result to the exact decision without handling a raw PALISADE session ID. Its availability policy is an explicit deployment choice. See the [origin-adapter guide](docs/ORIGIN_ADAPTER.md) and the fully synthetic [portable conformance suite](docs/ADAPTER_CONFORMANCE.md).

Deployments that need a standalone handler in front of an upstream can use the
independently implemented [`pkg/palisadeproxy`](pkg/palisadeproxy) reference
adapter. It enforces the same pass, delay, throttle, challenge-metadata and
temporary-block contract with explicit fail-open/fail-closed behavior, while
never forwarding application request data to PALISADE. Both adapters run the
same nine-case portable suite. See the [reverse-proxy guide](docs/REVERSE_PROXY_ADAPTER.md)
for its intentionally narrower challenge and single-process state boundary.

Both adapters can authenticate vendor-neutral local WAF, reputation,
TLS/HTTP-fingerprint and request-time challenge context with the signed
[`palisade.edge-signals.v1`](docs/UPSTREAM_SIGNALS.md) envelope. The bridge
accepts only existing closed classes from an allowlisted direct peer, enforces
fresh single-use HMAC authentication and never sends raw upstream values or the
envelope itself to PALISADE.

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

The default rotation limits are 64 MiB or one hour; default retention is seven days. `POST /v1/outcome` requires the backend bearer credential, the exact `decision_id`, and a closed label with compatible provenance and confidence. `analyze-shadow-log` authenticates and decrypts retained files locally, joins outcomes to decisions under a fixed memory budget, and emits only aggregate counts, endpoint/cohort Wilson 95% intervals, same-endpoint shadow/canary comparisons and deterministic recommendations. False-positive rate, abuse recall and precision use only uniquely linked confirmed labels; ambiguous, duplicate, mismatched and legacy-unlinked outcomes are counted separately. Challenge rates use only challenged decisions old enough for the 15-minute outcome window, with unresolved and conflicting results explicit. The coarse cohort vocabulary is deployment-supplied and never inferred as identity, disability or fingerprint evidence. The Operator Console polls the atomically replaced report, retains the last valid version after a rejected update and never receives the log key. Recommendations can hold the deployment in shadow mode or nominate a reversible canary for operator review; they never activate enforcement. `prepare-review` requires risky shadow actions plus at least 100 uniquely linked confirmed-human and 100 uniquely linked operator-confirmed-abuse decisions on the exact proposed endpoint. Promotion from a challenge-capable canary additionally requires 1,000 decisions and 100 mature uniquely linked challenges from the exact rollout and endpoint, with conservative Wilson bounds for terminal-outcome coverage, abandonment and accessible fallback. `prepare-rollout` can sign only that exact reviewed hash, scope and budget. See the [automated analysis operations](docs/ANALYSIS_AUTOMATION.md), [signed review and rollout guide](docs/ROLLOUT.md) and [shadow-log threat model](docs/SHADOW_LOG.md) before enabling it.

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

The required test pyramid, coverage and in-process latency gates are documented in [the testing strategy](docs/TESTING.md). The [synthetic benchmark protocol](docs/BENCHMARKS.md) records p50/p95/p99 and repeated allocation aggregates for exact clean commits with explicit non-production limitations. All committed fixtures are synthetic; deployment logs and private analysis reports are excluded from tests and CI.

The first [published synthetic baseline](benchmarks/synthetic-baseline-afc23a3.json), measured with Go 1.27.0 in a network-disabled Linux/arm64 container, records p95 of **5.958 µs** for the production Shadow decision path and **7.250 µs** for signed adaptive Enforcement against the 10 ms in-process gate. These figures exclude proxy/network/TLS/browser latency, concurrent capacity, production detection efficacy and false-positive rates; they are reproducible engineering evidence, not production performance guarantees.

The first [public synthetic red-team findings record](reports/red-team/synthetic-findings-25aaba7.json) binds all **12 passed controls** across evasion, poisoning, proof relay, session reset, resource exhaustion and rollout compromise to exact source commit `25aaba7` and the hashed closed suite. It contains no deployment records and is regression evidence only—not an independent audit or a claim that unknown vulnerabilities, production detection efficacy or false-positive rates have been resolved.

The first deployment should ingest normalized challenge, external-risk and policy-alert verdicts in **shadow mode**, then tune thresholds on labeled replay data before any automatic blocking. Every replay record must carry an RFC 3339 `observed_at` timestamp that drives session TTLs and decision expiry; records must be globally chronological with equal timestamps allowed. Fixtures can assert `expected_action` and `expected_computed_action` independently.

Authorized historical exports can be normalized locally in two ways. The
source-specific `palisade import-offline` command understands the documented
five-file Shield bundle. The vendor-neutral `palisade import-local-events`
command accepts an operator-created, chronological closed JSONL contract and
immediately pseudonymizes its direct local references. Neither command uploads,
fetches or emits raw rows. Inputs, keys and normalized outputs must stay outside
every Git worktree. See the [generic local import contract](docs/LOCAL_IMPORT.md)
and [source-specific offline import](docs/OFFLINE_IMPORT.md). The follow-on
`palisade analyze-local-events` command verifies the completed local shards and
emits only bounded aggregate sequence features under a versioned contract; see
[local sequence analysis](docs/LOCAL_SEQUENCE_ANALYSIS.md). A separate
`palisade evaluate-local-holdout` command measures fixed diagnostic rules on a
predeclared chronological boundary and optional unseen-family slice without
persisting sequence or family identifiers; see
[local holdout evaluation](docs/LOCAL_HOLDOUT_EVALUATION.md).
For the authenticated encrypted decision stream itself,
`palisade evaluate-shadow-holdout` assigns exactly linked delayed outcomes by
decision time and reports separate baseline/holdout endpoint and accessibility
slices; see [chronological linked shadow holdout](docs/SHADOW_HOLDOUT.md).

See the [architecture and stack](docs/ARCHITECTURE.md), [threat model](docs/THREAT_MODEL.md), [synthetic red-team baseline](docs/RED_TEAM.md), [synthetic benchmark protocol](docs/BENCHMARKS.md), [product differentiation](docs/DIFFERENTIATION.md), [Sovereignty Report](docs/SOVEREIGNTY.md), [runtime egress inventory](docs/RUNTIME_EGRESS.md), [machine-readable data map](docs/DATA_MAP.md), [normalized signal contract](docs/NORMALIZED_SIGNAL_CONTRACT.md), [signed upstream signals](docs/UPSTREAM_SIGNALS.md), [generic local import](docs/LOCAL_IMPORT.md), [local sequence analysis](docs/LOCAL_SEQUENCE_ANALYSIS.md), [local holdout evaluation](docs/LOCAL_HOLDOUT_EVALUATION.md), [chronological linked shadow holdout](docs/SHADOW_HOLDOUT.md), [public adversarial fixtures](docs/ADVERSARIAL_FIXTURES.md), [maintainer process](MAINTAINERS.md), [local release process](docs/RELEASING.md), [reference origin adapter](docs/ORIGIN_ADAPTER.md), [standalone reverse-proxy adapter](docs/REVERSE_PROXY_ADAPTER.md), [portable adapter conformance](docs/ADAPTER_CONFORMANCE.md), [signal-source integration guide](docs/SIGNAL_SOURCES.md), [native challenge lifecycle](docs/CHALLENGE.md), [automated local analysis](docs/ANALYSIS_AUTOMATION.md), [signed local runtime artifacts](docs/LOCAL_ARTIFACTS.md), [signed rollout guide](docs/ROLLOUT.md), [roadmap](ROADMAP.md), [evaluation protocol](docs/EVALUATION.md), [EU privacy deployment checklist](docs/privacy/DEPLOYMENT_CHECKLIST.md) and [shadow-log operations guide](docs/SHADOW_LOG.md).

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
