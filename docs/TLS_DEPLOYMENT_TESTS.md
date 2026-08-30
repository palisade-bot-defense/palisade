# Local TLS and reverse-proxy deployment tests

The local deployment suite exercises both reference adapters over real
loopback TCP connections with ephemeral TLS certificates and HTTP/2. All
requests, addresses and credentials are synthetic test values. The suite does
not read deployment logs, contact external services or persist certificates.

Run it from the repository root with Go 1.27 or newer:

```sh
make deployment-tls-test
```

The same tests are also included in `go test -race ./...` and therefore in the
complete local release verification.

## Trusted TLS terminator boundary

`TestTrustedTLSTerminatorDeploymentRejectsDirectHeaderSpoof` constructs this
local path:

```text
HTTP/2 TLS client -> HTTP/2 TLS edge proxy -> HTTP/2 TLS Go origin adapter
                                            -> HTTP/2 TLS PALISADE fixture
```

The edge proxy is the exact configured TCP peer. It supplies one supported
single-address client header and the edge scheme. The adapter consequently
normalizes only closed values: `http2`, `trusted_proxy_tls` and
`trusted_proxy`. A registry entry can verify the synthetic crawler only on
that trusted path.

A second HTTP/2 TLS client connects directly from a distinct loopback address
and sends the same forwarding and crawler claims. Because its TCP peer is not
allowlisted, the adapter ignores the forwarding headers and reports
`http2`, `direct_tls`, `direct`, with crawler identity remaining unknown. This
is the executable regression boundary for direct header spoofing.

The PALISADE fixture is also checked for absence of request paths, queries,
User-Agent values, addresses and forwarding-header names.

## Standalone TLS reverse-proxy boundary

`TestTLSHTTP2ReverseProxyDeploymentKeepsPrivateRequestAtUpstream` constructs a
separate path:

```text
HTTP/2 TLS client -> standalone adapter/reverse proxy -> HTTP/2 TLS upstream
                                 |
                                 +-> HTTP/2 TLS PALISADE fixture
```

The application path, query, body, cookie and User-Agent still reach the
application upstream because they are application data. The test proves that
none of those raw values or spoofed forwarding headers appear in PALISADE
request bodies or headers. PALISADE receives only the adapter's closed
`http2`, `direct_tls`, `direct` transport classification and an
unknown/unverified crawler class.

## Deliberate limits

This suite proves the behavior of the two repository reference adapters on a
single local machine. It is not evidence for:

- a particular CDN, load balancer, nginx build or cloud proxy configuration;
- public-PKI validation, certificate issuance, rotation or revocation;
- HTTP/3, QUIC, cross-host routing or production DNS;
- multi-replica state sharing, failover or distributed one-time redemption;
- sustained proxy capacity, network latency, detector efficacy or false-positive rates.

Before enforcement, operators must still validate their exact immediate proxy
ranges, header rewriting, TLS trust, failure policy and rollback path in the
deployment they control. Production safety and efficacy require linked local
outcomes; this synthetic suite cannot substitute for them.
