# Signal-source integration

PALISADE consumes normalized evidence, not arbitrary raw logs. A deployment
adapter owns authentication and source-specific parsing, maps an upstream event
to the closed `Observations` contract and calls the decision API. This prevents
vendor payloads, headers and free text from silently becoming trusted features.

## Supported source classes

| Normalized source | API field or route | Trust boundary | Current use |
|---|---|---|---|
| Bucketed browser behavior | `POST /v1/events` | Untrusted same-origin client plus one-time proof | Browser-event count and sequence consistency |
| Server-issued session | `__Host-palisade_session` | PALISADE-signed HttpOnly cookie | Continuity only; never human identity |
| Protocol presence | `user_agent_present` | Trusted origin observation | Automation consistency |
| Honeypot interaction | `honeypot_hits` | Trusted origin adapter | Abuse intent |
| Challenge result | `challenge_verdict` | Trusted challenge adapter | Suspicious automation only; pass is not human proof |
| External score | `external_risk_score` | Trusted server-side adapter | Abuse intent, bounded to 0..1 |
| Deployment policy alert | `policy_alert` | Trusted policy adapter | Abuse intent |
| Verified beneficial bot | `verified_bot` | Authenticated server-side verification | Offsets automation only, never abusive intent |
| Delayed outcome | `POST /v1/outcome` | Backend bearer credential | Local evaluation and recommendation gates |

Client-controlled forwarding headers must not set trusted observations. Resolve
the actual TCP peer and proxy allowlist in the deployment adapter first. If a
proxy supplies a client address, accept it only when the direct peer belongs to
the configured trusted proxy network.

The event proof is action-bound to the literal `events`. A token minted for
`read` is valid cryptographically but is correctly rejected by `/v1/events`.
The sensor asks its proof callback explicitly for `events`, defaults to and
enforces a minimum 15-second interval, serializes flushes and keeps at most 256
events locally.

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
browser receives only `202` and the closed `recorded|dropped` status header,
never scores, evidence, credentials or the server-side classification. Event
acceptance remains final if the decision queue is full, preventing duplicate
sequence retries. This bridge is shadow-only, requires the encrypted sink and
signed session cookie, cannot run with a signed rollout, and must not be used in
parallel with the origin adapter's authoritative decision stream.

## HTTP integration

The origin creates or reuses a stable session ID, obtains a short-lived proof
with `POST /v1/token`, then submits a normalized decision request:

```json
{
  "session_id": "session-12345678",
  "action": "read",
  "endpoint_class": "public_content",
  "sequence": 42,
  "proof_token": "server-issued-one-time-proof",
  "observations": {
    "user_agent_present": true,
    "browser_event_count": 7,
    "honeypot_hits": 0,
    "challenge_verdict": "unknown",
    "external_risk_score": 0.35,
    "policy_alert": false,
    "verified_bot": false
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
  "policy_version": "default-v3",
  "model_version": "transparent-baseline-v6",
  "expires_at": "2026-08-27T12:00:30Z"
}
```

The complete authentication, bounds and schemas are authoritative in
[`api/openapi.yaml`](../api/openapi.yaml). `additionalProperties: false` rejects
unknown observation fields instead of retaining them.

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
then returns only `204 pass`, `429 throttle`, or `403 challenge/block` with
bounded `X-Palisade-*` headers. Risky results are possible only under a valid
operator-signed rollout. Go applications can use the checked reference
[`palisadehttp`](../pkg/palisadehttp) middleware described in
[ORIGIN_ADAPTER.md](ORIGIN_ADAPTER.md). See [signed rollout and rollback](ROLLOUT.md).
