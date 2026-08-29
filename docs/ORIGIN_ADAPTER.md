# Go reference origin adapter

`pkg/palisadehttp` is the deployable reference integration for Go `net/http`
applications. It owns the browser-facing session, calls PALISADE exactly once
per protected request, validates the bounded origin result and applies pass,
throttle, challenge or block behavior. It does not parse raw vendor payloads.

## Minimal integration

```go
guard, err := palisadehttp.New(palisadehttp.Config{
    BaseURL: "http://127.0.0.1:8080",
    APIKey: os.Getenv("PALISADE_API_KEY"),
    FailureMode: palisadehttp.FailClosed,
    CoverageReporting: true,
    FallbackPath: "/support/verification",
    Classifier: func(r *http.Request) (palisadehttp.Classification, error) {
        if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/articles/") {
            return palisadehttp.Classification{Action: "read", EndpointClass: "public_content"}, nil
        }
        return palisadehttp.Classification{Action: "other", EndpointClass: "other"}, nil
    },
})
if err != nil { log.Fatal(err) }

http.ListenAndServeTLS(":443", "cert.pem", "key.pem", guard.Handler(application))
```

For a separate local WAF, reputation mapper or fingerprint classifier, attach
the [signed upstream-signal verifier](UPSTREAM_SIGNALS.md) through
`Config.EdgeSignals`. It authenticates a short-lived closed envelope from an
allowlisted direct peer and never forwards the envelope, address or raw source
values to PALISADE.

With `CoverageReporting` enabled, the middleware asynchronously reports only
cumulative counts for completed requests routed through `guard.Handler`. The
first completion is reported immediately; later snapshots are coalesced to 100
additional completions or 30 seconds of continued traffic by default. A random
128-bit source epoch is created in memory for each middleware process. It is
not a customer, host, account or browser identifier. Reports contain the nine
closed endpoint classes and exactly one terminal disposition per request:
freshly evaluated, availability-bypassed, adapter-rejected or a bound
challenge retry. They contain no method, path, URL, query, headers, client
address, account value or request row.

PALISADE authenticates reports with the adapter API key, accepts idempotent
retries, and rejects changed replays, decreasing counters and unbalanced
totals. Reports from an adapter process that predates the current PALISADE
process are baselined on first receipt, so earlier history is not mixed into a
new runtime window. The in-memory server store is bounded to 1,024 source
epochs and resets on PALISADE restart. Coverage delivery is measurement-only:
failure never changes the request handling selected by `FailureMode`. With
continued traffic, the adapter reoffers the exact pending snapshot on the first
completed request after its bounded retry interval.

During graceful shutdown, call `guard.FlushCoverage(ctx)` with a short bounded
context after the application listener stops accepting new requests. It sends
the latest below-threshold snapshot synchronously. A concurrent automatic send
returns `ErrCoverageBusy`; retry only within the same bounded shutdown window.

This is **protected-handler coverage**, not website coverage. Requests outside
`guard.Handler`, at an upstream CDN or rejected before reaching the Go origin
are not in its denominator. The Operator Console preserves that scope instead
of presenting the number as a share of all site traffic.

## Linking application outcomes

Requests that pass PALISADE carry an opaque, request-scoped outcome handle in
their Go context. Authenticated application code can use it to link a closed
result to the exact decision without reading a PALISADE session ID:

```go
func accountPage(w http.ResponseWriter, r *http.Request) {
    handle, ok := palisadehttp.OutcomeHandleFromRequest(r)
    if ok && currentAccount(r) != nil {
        if err := guard.RecordOutcome(r, handle, palisadehttp.Outcome{
            Kind: "human_confirmed", Provenance: "authenticated_account", Confidence: "confirmed",
        }); err != nil {
            // Count or log only the closed failure class; do not log the handle.
        }
    }
    // Render the application response.
}
```

The handle contains only the stable decision ID and closed endpoint class; the
signed PALISADE cookie remains in private request context. `RecordOutcome` sends no URL, query, request
body, response body, client address or account identifier. The service derives
the session from the signed cookie and rejects incompatible combinations such
as `human_confirmed` with `server_observed` provenance. Challenge lifecycle
outcomes are already recorded by PALISADE and must not be relabeled as human.
Keep this helper request-local. A deployment that needs a result after the
request has finished must implement a separate audited, bounded backend
workflow that preserves the same decision, session and endpoint binding.

The Operator Console separately reports accepted, rejected and dropped outcome
events. Those are ingestion-health counters only. An accepted event is not
automatically a confirmed-human or confirmed-abuse label; only the linked local
aggregate analysis applies provenance rules and computes label coverage.

## Issuing route-classified sensor proofs

Proof-classified sensor-only shadow deployments can use `IssueEventProof` from
a same-origin backend route. The application fixes the classification in its
route table; browser input does not supply it:

```go
func compareEventProof(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
        return
    }
    proof, err := guard.IssueEventProof(r, palisadehttp.Classification{
        Action: "compare", EndpointClass: "compare_noindex",
    })
    if err != nil {
        http.Error(w, "proof unavailable", http.StatusServiceUnavailable)
        return
    }
    w.Header().Set("Cache-Control", "no-store")
    w.Header().Set("Content-Type", "application/json")
    _ = json.NewEncoder(w).Encode(proof)
}
```

The helper reads only `__Host-palisade_session`, sends the adapter bearer key
server-to-server and returns the bounded proof response. It does not forward
the request URL, query, Referer, User-Agent, body, other cookies or arbitrary
headers. Register separate fixed handlers for the closed route classes you
actually measure. Never accept action or endpoint class values from a request
body or query parameter, never log the returned proof, and do not use this
shadow-only measurement bridge as enforcement evidence by itself.

`FailureMode` is mandatory. Choose `fail_open` only when availability is more
important than protection during a PALISADE outage; bypassed requests receive
`X-Palisade-Adapter: bypass_unavailable`. Choose `fail_closed` for sensitive
routes that must return `503` if evaluation is unavailable. Classification or
signal-provider errors always fail closed because they are local integration
bugs, not dependency outages.

## Request and trust boundary

The classifier maps local routes to the closed action and endpoint enums. It may
also set one closed `EvaluationCohort` for aggregate measurement. That field is
never policy input and must not contain free text, identity, fingerprint or a
diagnosis; leave it empty to record `unknown`. The
optional signal provider may read only already authenticated, normalized facts
from trusted application context. Do not trust client headers for proxy,
crawler identity, policy-alert or external-score values. The reference adapter
overwrites crawler fields from its own local registry boundary, so a custom
signal provider cannot promote a user-agent claim.

Without a signal provider the adapter submits only whether a User-Agent header
is present. It never sends the User-Agent value, application method/path/query,
request or response body, IP address, Referer, application cookies or arbitrary
headers. PALISADE session and proof credentials are exchanged only with the
configured PALISADE base URL. Redirect following is disabled and response
bodies are bounded to 64 KiB. A supplied HTTP client's cookie jar is disabled
on the adapter's private clone so browser sessions cannot mix through shared
client state; cookies are forwarded explicitly per request.

The backend URL must use HTTPS. Plain HTTP is accepted only for `localhost` or
a loopback IP so the bearer credential cannot be configured over a remote
cleartext connection.

The adapter accepts these normalized signals: browser event count, honeypot
hits, closed challenge verdict, 0..1 external risk score and policy alert.
Crawler identity is derived separately from `CrawlerRegistry`, the validated
transport address and a product-specific user-agent token. Values outside their
documented bounds are rejected locally. See
[crawler identity and SEO/GEO safety](CRAWLER_IDENTITY.md).

The adapter itself owns three additional closed transport fields. Configure a
trusted proxy only with explicit CIDRs and one supported single-address header:

```go
guard, err := palisadehttp.New(palisadehttp.Config{
    // ...normal required settings...
    TrustedProxyCIDRs: []string{"203.0.113.0/24"}, // replace with the proxy's published ranges
    TrustedClientIPHeader: "CF-Connecting-IP",    // or X-Real-IP
    TrustedProtoHeader: "X-Forwarded-Proto",
})
```

`CF-Connecting-IP`, `X-Real-IP` and `X-Forwarded-Proto` are used only when the
actual TCP peer in `RemoteAddr` belongs to `TrustedProxyCIDRs`. On a direct
connection they are ignored, so a client cannot promote its own forwarding
headers. Lists such as `X-Forwarded-For`, catch-all CIDRs and arbitrary header
names are rejected. A malformed single-address header becomes only the closed
`invalid_trusted_proxy` provenance class. PALISADE receives `http1|http2|http3`,
`direct_tls|trusted_proxy_tls|plaintext|unknown` and
`direct|trusted_proxy|invalid_trusted_proxy|unknown`; it never receives the
parsed client or peer address. Keep proxy ranges current in deployment
configuration and restart the adapter after an audited range update.
Place the adapter before any application middleware that rewrites `RemoteAddr`;
the trust check is valid only while `RemoteAddr` still represents the socket
peer supplied by Go's HTTP server. For a trusted proxy,
`X-Forwarded-Proto` describes the browser-to-proxy edge even when the
proxy-to-origin hop also uses TLS.

## Challenge behavior

Applied challenges on `GET` requests render an accessible same-origin page
below `/__palisade`. The page uses a restrictive content-security policy,
same-origin credentialed fetches, keyboard controls and an ARIA live status.
It relays metadata, verification, redemption and fallback calls without
exposing the backend credential.

The fallback control is a real same-origin POST form and therefore remains
usable when JavaScript is blocked or fails. JavaScript only enhances that form;
both paths reach the same backend fallback call, record the same closed
`fallback_used` outcome and close the same pending state. Form parsing is
bounded and closed to one `challenge_id`; browser-supplied redirects, queries
and extra fields are rejected. `FallbackPath` is configuration-only and must be
a clean local path without query or fragment. The bundled stylesheet is served
from the adapter under the same prefix, includes visible focus and forced-color
states and disables motion under `prefers-reduced-motion` without reporting the
preference.

The initial request creates an HttpOnly, Secure, SameSite=Strict pending cookie
and bounded in-memory entry. On every origin check it also derives a 32-byte
server-only flow capability from the process-random key, signed session, target
digest, action, endpoint class and sequence. PALISADE receives its base64url
form in `X-Palisade-Challenge-Binding` and later requires the same value during
backend redemption. The adapter stores it only in the pending entry: browser
HTML, JavaScript, request bodies and cookies never contain it. After successful backend redemption the adapter
issues a second HttpOnly one-time cookie. It authorizes only the original
method, escaped path, raw query, action and endpoint class. Those request-target
values are represented in state only by a process-random HMAC digest. A changed
query or path does not pass and does not consume the valid grant. The browser
then reloads its current location; no return URL is put into HTML, JavaScript,
cookies or PALISADE requests.

Non-`GET` challenges return `403`, the challenge ID and same-origin `Location`
metadata. The middleware never buffers or automatically replays an unsafe
request body. The application must design an explicit idempotent continuation
flow if it wants step-up protection for writes.

## State and deployment limits

The defaults bound session counters, pending retries and granted retries to
100,000 entries each. Session sequence state expires after 10 minutes, pending mappings after
15 minutes and retry grants after 30 seconds. All state is process-local; a
restart invalidates it. Keep a challenged session on one replica. Do not spread
traffic across multiple replicas until an atomic shared-state implementation
preserves the same expiry and consume-once semantics.

Custom adapters must generate an equivalent unpredictable server-only flow
capability, bind it to their own pending request state and keep it out of every
browser-controlled field. Merely forwarding a browser redemption token is not
a conforming implementation.

The browser-facing baseline uses one pending and one redemption cookie name.
Concurrent challenge completions in several tabs can therefore supersede one
another and require a fresh challenge; they fail closed rather than authorizing
the wrong request.

The adapter requires HTTPS at the browser-facing origin because all continuity
and challenge cookies are `Secure` and use the `__Host-` prefix. Keep the
PALISADE API key only in server-side secret management. Exclude `/__palisade`
from application route rewriting, authentication redirects and caches. Also
exclude the challenge stylesheet, script and fallback POST from content
transformation; retain the adapter's CSP and `no-store` headers on dynamic
pages.

## Rollout order

1. Start PALISADE and the adapter in shadow mode with no signed rollout.
2. Enable the encrypted local shadow sink and collect normalized outcomes linked to the exact decision IDs.
3. Review linked `analyze-shadow-log` endpoint/cohort aggregates and select explicit false-positive,
   availability and accessibility budgets.
4. Sign a small reversible canary and test pass, delay, throttle, challenge, fallback,
   block and PALISADE-outage paths.
5. Promote only the exact measured canary under the signed-rollout gates.

The adapter never promotes a recommendation or changes runtime mode. See
[ROLLOUT.md](ROLLOUT.md), [CHALLENGE.md](CHALLENGE.md) and the authoritative
[OpenAPI contract](../api/openapi.yaml).

Custom implementations can verify the same pass, response, failure-policy and
privacy boundary against the versioned [origin adapter conformance
suite](ADAPTER_CONFORMANCE.md). The suite is entirely synthetic and does not
require production traffic or PALISADE-operated infrastructure.
