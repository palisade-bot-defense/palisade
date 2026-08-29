# Signed local upstream signals

`palisade.edge-signals.v1` is a vendor-neutral bridge from a trusted local WAF,
edge classifier, fingerprint mapper, reputation service or challenge layer into
the two Go reference adapters. It transports only PALISADE's existing closed
classes. It is not a raw event bus and adds no vendor names, addresses, ASNs,
fingerprints, user agents, URLs or provider payloads to the decision request.

The decoded JSON shape is closed by
[`edge-signal-envelope-v1.schema.json`](../schemas/edge-signal-envelope-v1.schema.json):

```json
{
  "version": "palisade.edge-signals.v1",
  "issued_at": 1788084000,
  "nonce": "AQAAAAAAAAAAAAAAAAAAAA",
  "signals": {
    "policy_alert": true,
    "external_risk_score": 0.82,
    "edge_fingerprint_class": "automation_consistent",
    "edge_fingerprint_method": "tls_http2",
    "network_reputation": "high_risk",
    "network_type": "hosting"
  }
}
```

The UTF-8 JSON is base64url-encoded without padding in
`X-Palisade-Edge-Signals`. `X-Palisade-Edge-Signature` is base64url without
padding of:

```text
HMAC-SHA256(key, "palisade:edge-signals:v1\0" || exact_decoded_json_bytes)
```

`issued_at` is an integral Unix second. `nonce` is exactly 16 random bytes. The
reference verifier defaults to a 30-second maximum age, five seconds of future
clock skew and 100,000 live nonce digests. Every envelope is single-use per
adapter process. The HMAC key is 32–4096 random bytes and must be distinct from
PALISADE API, cookie, proof, shadow-log and artifact-signing keys.
An envelope must carry at least one meaningful class: `true`, a positive risk
score or a known non-`unknown` categorical value. Empty, all-zero and
unknown-only envelopes are rejected.

Size `MaxNonces` above the maximum number of signed requests expected during
`MaxAge + FutureSkew`; reaching the bound fails closed. Expired entries are
reclaimed when the bound is approached, keeping normal verification free of an
unbounded cleanup scan.

## Trust boundary

Authentication requires both conditions:

1. the direct TCP peer is inside an explicit, masked CIDR allowlist; and
2. the envelope has a valid HMAC, fresh timestamp, strict closed payload and
   unused nonce.

Envelope-looking headers from any other direct peer are ignored, so an Internet
client cannot create a fail-closed denial by sending the header names. Once a
peer is allowlisted, a partial, malformed, expired, replayed or conflicting
envelope fails closed even when the adapter's dependency policy is `fail_open`.
The authorized proxy must strip client-supplied copies and generate a fresh
signed envelope for each request. Protect the hop against header modification;
the HMAC authenticates the normalized fields but does not encrypt them.
After verification, both reference adapters remove both envelope headers before
calling the application or upstream handler.

The adapter uses the request address only for the local peer check and never
serializes it. It rejects overlapping, overly broad, unspecified and multicast
CIDRs. A deployment behind multiple proxies must allowlist only the immediate
signing peer, not an entire public provider range unless that exact boundary is
operationally controlled.

## Go integration

```go
edgeVerifier, err := palisadeedge.NewVerifier(palisadeedge.VerifierConfig{
    Key:              edgeHMACKey,
    TrustedPeerCIDRs: []string{"10.42.0.0/24"},
})
if err != nil {
    log.Fatal(err)
}

guard, err := palisadehttp.New(palisadehttp.Config{
    BaseURL:     "https://palisade.internal",
    APIKey:      os.Getenv("PALISADE_API_KEY"),
    FailureMode: palisadehttp.FailClosed,
    Classifier:  routeClassifier,
    EdgeSignals: edgeVerifier,
})
```

`pkg/palisadeproxy.Config` accepts the same `EdgeSignals` verifier. A Go-based
local normalizer can create compact header values with `palisadeedge.Sign`;
other languages may use any valid field ordering and insignificant whitespace,
but must sign the exact decoded JSON bytes they transmit. Duplicate and unknown
fields are rejected. Never call `Sign` in browser code or expose the key to a
public proxy configuration surface.

## Source mapping

| Local source | Closed target | Required local rule |
|---|---|---|
| WAF or policy match | `policy_alert`, optionally `external_risk_score` | Map only reviewed rules; do not forward rule names or provider scores |
| TLS/HTTP classifier | fingerprint class plus method | Both fields are required together; never forward JA3/JA4 or HTTP/2 values |
| Reputation/ASN mapper | network reputation and type | Resolve locally; reject unknown provider labels instead of guessing |
| Request-time challenge layer | `challenge_verdict` | A pass is not a human label; delayed confirmed outcomes still use `/v1/outcome` |

When a local `SignalProvider` and signed envelope both contribute, numeric risk
uses the higher value and policy alerts combine with logical OR. Equal closed
categorical values are accepted. Two different known categorical values fail
closed instead of selecting a source silently. Low-risk, residential,
browser-consistent and passed classes remain non-benign under the normalized
signal contract.

Start in shadow mode and inspect encrypted aggregate results. The signature
establishes source authenticity, not detector accuracy, label quality or a
legal basis for processing the source data.
