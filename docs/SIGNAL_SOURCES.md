# Signal-source integration

PALISADE consumes normalized evidence, not arbitrary raw logs. A deployment
adapter owns authentication and source-specific parsing, maps an upstream event
to the closed `Observations` contract and calls the decision API. This prevents
vendor payloads, headers and free text from silently becoming trusted features.
The authoritative value sets, cross-field invariants and compatibility policy
are defined by the versioned [normalized signal contract](NORMALIZED_SIGNAL_CONTRACT.md).
The two Go adapters can also consume the vendor-neutral
[signed local upstream envelope](UPSTREAM_SIGNALS.md), which requires an
allowlisted direct peer, HMAC, freshness and one-time nonce before merging only
those same closed classes.

## Supported source classes

| Normalized source | API field or route | Trust boundary | Current use |
|---|---|---|---|
| Bucketed browser behavior | `POST /v1/events` | Untrusted same-origin client plus one-time proof; server-side bounded event store is authoritative | Verified browser-event count and sequence consistency |
| Server-issued session | `__Host-palisade_session` | PALISADE-signed HttpOnly cookie | Continuity only; never human identity |
| Protocol presence | `user_agent_present` | Trusted origin observation | Automation consistency |
| Transport normalization | `transport_protocol`, `transport_security`, `client_address_source` | Reference origin adapter plus explicit trusted-proxy CIDRs | Closed data-quality context; not scored until calibrated |
| Edge fingerprint classification | `edge_fingerprint_class` + `edge_fingerprint_method` | Trusted reverse proxy or edge adapter | Suspicious automation context only; never human proof |
| Network context | `network_reputation` + `network_type` | Trusted local reputation/ASN adapter | Conservative automation/intent context; never a standalone allow or block |
| Honeypot interaction | `honeypot_hits` | Trusted origin adapter | Abuse intent |
| Challenge result | `challenge_verdict` | Trusted challenge adapter | Suspicious automation only; pass is not human proof |
| External score | `external_risk_score` | Trusted server-side adapter | Abuse intent, bounded to 0..1 |
| Deployment policy alert | `policy_alert` | Trusted policy adapter | Abuse intent |
| Verified public crawler | `verified_bot` + `crawler_class` + `crawler_verification` | Trusted origin verifier plus public endpoint class | Offsets automation only for eligible public crawlers; never abusive intent |
| Delayed outcome | `POST /v1/outcome` with exact `decision_id` | Backend bearer credential | Linked local evaluation and recommendation gates |

Client-controlled forwarding headers must not set trusted observations. Resolve
the actual TCP peer and proxy allowlist in the deployment adapter first. If a
proxy supplies a client address, accept it only when the direct peer belongs to
the configured trusted proxy network.

JA4/JA3 and HTTP/2 fingerprints, client addresses, ASNs, reverse-DNS results and
provider-specific reputation values are processed only inside the trusted edge
adapter. The adapter maps them to the closed fingerprint method/class, network
type and reputation enums before calling PALISADE. It must reject unknown
provider values rather than forwarding or hashing them. A fingerprint class is
valid only together with its method. `browser_consistent`, `low_risk`,
`residential` and `mobile` produce no benign evidence: they do not establish a
person, a unique device or acceptable intent.

The event proof is action-bound to the literal `events`. A token minted for
`read` is valid cryptographically but is correctly rejected by `/v1/events`.
The sensor asks its proof callback explicitly for `events`, defaults to and
enforces a minimum 15-second interval, serializes flushes and keeps at most 256
events locally.

`browser_event_count` in a decision request is retained for wire compatibility,
but the live service replaces it with the count in its own bounded event store.
Only that server-observed count may produce benign continuity evidence. A
missing or late sensor is neutral rather than suspicious, and a forged count
cannot lower risk. Offline Go tests may set the internal verification marker to
exercise deterministic detector behavior; it is not a JSON or protobuf field.

Sensor-only deployments may configure a server-trusted event shadow profile:

```sh
palisade serve \
  --require-session-cookie \
  --event-shadow-action read \
  --event-shadow-endpoint-class public_content \
  --shadow-log-dir /private/local/palisade-shadow/logs \
  --shadow-log-key-file /private/local/palisade-shadow/shadow.key
```

After an event batch is authenticated and ingested, PALISADE mints and consumes
an internal one-time proof for that configured action, evaluates the fresh
in-memory event count and queues one closed encrypted shadow decision. The
decision uses a server-owned contiguous batch counter, not the browser's event
number, so normal multi-event flushes cannot create request-sequence gaps. The
browser receives only `202` and the closed `recorded|dropped` status header,
never scores, evidence, credentials or the server-side classification. Event
acceptance remains final if the decision queue is full, preventing duplicate
sequence retries. This bridge is shadow-only, requires the encrypted sink and
signed session cookie, cannot run with a signed rollout, and must not be used in
parallel with the origin adapter's authoritative decision stream.

For multiple endpoint classes, replace the two static profile flags with
`--event-shadow-from-proof`. The backend then calls `POST /v1/token` with
`action: events` plus a closed `request_action` and `endpoint_class` derived
from the backend route table. PALISADE signs those fields into the same
short-lived one-time proof already required by `/v1/events`; the sensor only
forwards that proof. Proof-classified mode rejects development mode, raw route
values, missing claim pairs and non-event proofs. It never adds browser-chosen
classification fields to the event batch. Invalid or cross-mode contexts are
rejected before ingestion so they cannot advance the event-shadow sequence.
Go origins can use `palisadehttp.Middleware.IssueEventProof` from a fixed
same-origin backend route; the helper forwards only the PALISADE session cookie
and closed server configuration, never the page request target or headers.

## HTTP integration

The origin creates or reuses a stable session ID, obtains a short-lived proof
with `POST /v1/token`, then submits a normalized decision request:

```json
{
  "session_id": "session-12345678",
  "action": "read",
  "endpoint_class": "public_content",
  "evaluation_cohort": "standard",
  "sequence": 42,
  "proof_token": "server-issued-one-time-proof",
  "observations": {
    "user_agent_present": true,
    "browser_event_count": 7,
    "honeypot_hits": 0,
    "challenge_verdict": "unknown",
    "external_risk_score": 0.35,
    "policy_alert": false,
    "verified_bot": false,
    "crawler_class": "unknown",
    "crawler_verification": "unknown",
    "edge_fingerprint_class": "automation_consistent",
    "edge_fingerprint_method": "tls_http2",
    "network_reputation": "elevated_risk",
    "network_type": "hosting"
  }
}
```

The response separates what PALISADE recommends from what it actually applies:

```json
{
  "decision_id": "...",
  "action": "observe",
  "computed_action": "challenge",
  "mode": "shadow",
  "directive": {
    "handling": "pass",
    "http_status": 200,
    "expires_at": "2026-08-27T12:00:30Z"
  },
  "scores": {
    "automation_risk": 0.71,
    "abuse_intent_risk": 0.55,
    "account_continuity": 0.43
  },
  "reason_codes": ["STEP_UP_REQUIRED", "SHADOW_ACTION_OVERRIDDEN"],
  "evidence": [],
  "policy_version": "default-v5",
  "model_version": "transparent-baseline-v13",
  "expires_at": "2026-08-27T12:00:30Z"
}
```

The complete authentication, bounds and schemas are authoritative in
[`api/openapi.yaml`](../api/openapi.yaml). `additionalProperties: false` rejects
unknown observation fields instead of retaining them.

Crawler identity is a conjunction, not a user-agent rule. The reference Go
adapter compares the normalized direct client address (or the client address
from an explicitly trusted proxy) with a locally maintained vendor CIDR
registry and separately requires a crawler-specific user-agent product token.
Only the closed result reaches PALISADE; addresses and user-agent strings do
not. A verified search indexer, answer-engine retriever, user-triggered agent or
preview service may offset automation risk on `public_content`,
`compare_index` or `other_public`. Login, account, checkout, challenge-worker,
noindex and unknown surfaces never receive that exception. Training crawlers
are intentionally not beneficial by default. Full configuration, update and
spoofing rules are in [CRAWLER_IDENTITY.md](CRAWLER_IDENTITY.md).

`evaluation_cohort` is optional input and normalizes to `unknown`. It is a
trusted coarse measurement slice, not a signal source: detectors and policy do
not consume it. Use only the closed vocabulary and never derive it from a
fingerprint, identity, diagnosis or free-form browser metadata. Delayed outcome
writes must repeat the exact response `decision_id`; PALISADE rejects new
unlinked outcomes. The Go reference middleware exposes an opaque outcome handle
only after a validated pass decision and can submit a normalized outcome with
the signed session cookie, so application code does not need the raw session ID.

## Adding a new source

1. Define the threat model, owner, provenance and proxy/authentication boundary.
2. Decide whether an existing normalized field is semantically sufficient. Do
   not overload a field merely because its numeric type fits.
3. If a new field is necessary, add a bounded or closed value to
   `core.Observations`, OpenAPI and protobuf using the same name and semantics.
4. Reject unknown, non-finite, oversized or out-of-range values in the request
   validator before any scoring.
5. Implement the Go `detector.Detector` interface. Emit only stable codes, one
   of the three dimensions, a benign/suspicious direction, strength and
   confidence in 0..1, plus a positive bounded TTL.
6. Register the detector in `buildEngine`. Startup rejects nil detectors,
   invalid or duplicate IDs; runtime rejects malformed or excessive evidence.
7. Add unit tests for benign, suspicious, absent, malformed and spoofed inputs.
   Update deterministic replay fixtures and the exact CEL drift test if policy
   uses the new signal.
8. Run `go test ./...`, `go vet ./...`, `go test -race ./...`, frontend checks,
   `make privacy-check` and `make license-check` before publication.
9. Deploy in shadow mode, submit normalized outcomes, analyze the encrypted
   local log and require operator review before any canary.

Minimal detector shape:

```go
type ReputationSignal struct{}

func (ReputationSignal) ID() string { return "reputation_signal_v1" }

func (ReputationSignal) Evaluate(_ context.Context, input core.DetectorInput) ([]core.Evidence, error) {
    // Read only a normalized, validated field from input.Request.Observations.
    return []core.Evidence{{
        Code: "REPUTATION_RISK",
        Detector: "reputation_signal_v1",
        Dimension: core.DimensionIntent,
        Direction: core.DirectionSuspicious,
        Strength: 0.6,
        Confidence: 0.8,
        TTL: 5 * time.Minute,
    }}, nil
}
```

This is a compile-time Go extension point inside the PALISADE module, not a
runtime plugin loader. Arbitrary executable plugins and unbounded webhook
payloads are intentionally unsupported on the request hot path. A future
out-of-process adapter API must preserve the same closed schema, budgets,
authentication and privacy rules.

## Processing and measurement

The registry evaluates each detector, validates its evidence and passes the
bounded result to score fusion. CEL maps scores and closed context to a computed
action. Shadow mode prevents risky enforcement. If the optional sink is enabled,
every successful decision is asynchronously encrypted and appended locally; a
full queue drops the record without delaying the request and increments only an
aggregate drop counter. Delayed outcomes are appended through `/v1/outcome`.
`analyze-shadow-log` then produces aggregate coverage, cohort and recommendation
gates without printing individual records or session links.

For an enforcing integration, call `POST /v1/origin-check` instead of
`/v1/decision`. It evaluates and records the same closed request exactly once,
then returns only `204 pass`, `429 delay/throttle`, or `403 challenge/block` with
bounded `X-Palisade-*` headers. Risky results are possible only under a valid
operator-signed rollout. Go applications can use the checked reference
[`palisadehttp`](../pkg/palisadehttp) middleware described in
[ORIGIN_ADAPTER.md](ORIGIN_ADAPTER.md). See [signed rollout and rollback](ROLLOUT.md).
