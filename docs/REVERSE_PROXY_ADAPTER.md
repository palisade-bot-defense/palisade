# Standalone reverse-proxy adapter

`pkg/palisadeproxy` is the second, independently implemented reference consumer
of `palisade.origin-adapter.v1`. It is a standard `http.Handler`: place it in
front of an `httputil.ReverseProxy` or another upstream handler. It does not
wrap or call `pkg/palisadehttp`, so the two implementations exercise separate
session, proof, state, response-validation and failure-policy code paths.

```go
upstreamURL, _ := url.Parse("http://127.0.0.1:8080")
adapter, err := palisadeproxy.New(palisadeproxy.Config{
    BaseURL:     "https://palisade.internal",
    APIKey:      os.Getenv("PALISADE_API_KEY"),
    FailureMode: palisadeproxy.FailClosed,
    Upstream:    httputil.NewSingleHostReverseProxy(upstreamURL),
    Classifier:  palisadeproxy.StaticClassification("read", "public_content"),
})
if err != nil {
    log.Fatal(err)
}
log.Fatal(http.ListenAndServe("127.0.0.1:8081", adapter))
```

The listener should sit behind the deployment's TLS terminator. Use HTTPS for
the PALISADE service; plaintext service URLs are accepted only for loopback
development. The adapter never trusts forwarding headers. It classifies the
direct TCP peer only as `direct` or `unknown`, records only whether a User-Agent
is present and never sends the peer address or raw User-Agent to PALISADE.
Deployment-specific edge, WAF and reputation signals may be supplied only
through the closed `Signals` type or the independently authenticated
[signed upstream-signal envelope](UPSTREAM_SIGNALS.md). This adapter has no
crawler registry and therefore always normalizes crawler identity to
unverified/unknown.

The availability choice is mandatory. `fail_closed` rejects dependency outages
with a closed 503 response. `fail_open` sends the original request to the
upstream unchanged and marks the response `X-Palisade-Adapter:
bypass_unavailable`. Local classifier and signal-provider failures always fail
closed because they are configuration defects rather than dependency outages.

Pass, delay, throttle and temporary-block results are enforced directly. A
challenge returns same-origin continuation metadata and never replays the
application request body. The generic adapter deliberately does not invent a
browser UI or redemption protocol; deployments that need PALISADE's complete
accessible HTML challenge and exact one-time retry should use
`pkg/palisadehttp` or supply an equivalently reviewed challenge frontend. This
limitation is outside the v1 portable conformance certification and must be
included in deployment documentation.

## State and privacy boundary

The adapter keeps only a bounded, expiring map from a SHA-256 session-cookie
digest to the next sequence number. A process-random HMAC binds challenge
evaluation to the session, method, private request target, action, endpoint
class and sequence. The target and query are used only inside that local MAC;
they are not serialized, logged or sent to PALISADE. Restarting the process
resets this adapter-local sequence state, so multi-replica deployments need
sticky routing or a reviewed shared-state implementation before enforcement.

Both reference adapters execute the exact canonical synthetic fixture:

```sh
make adapter-conformance
```

Passing the suite certifies response handling, explicit outage policy and the
negative privacy sentinels only. It does not certify detector accuracy,
production placement, accessibility or availability.
