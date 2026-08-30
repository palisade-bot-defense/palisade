# Pinned nginx deployment contract

PALISADE includes an opt-in, fully synthetic integration test for one exact
nginx build. It proves the immediate-proxy trust boundary with an actual nginx
process instead of treating a Go test proxy as evidence for nginx.

The tested path is:

```text
HTTP/2 + TLS verifier (192.0.2.30)
    -> pinned nginx (192.0.2.10)
    -> HTTP/1.1 origin middleware (192.0.2.20)
    -> loopback PALISADE service fixture
```

The verifier also connects directly to the origin while supplying forged
`X-Real-IP`, `X-Forwarded-Proto`, `CF-Connecting-IP`, `X-Forwarded-For` and
`Forwarded` values. Only the exact nginx TCP peer `192.0.2.10/32` is trusted.
nginx overwrites `X-Real-IP` and `X-Forwarded-Proto` from its connection and
scheme and clears the other forwarding headers. The direct request remains a
`direct`/`plaintext` request regardless of its supplied headers.

The topology uses an internal Docker network, publishes no host port, disables
nginx access logging and generates a one-hour self-signed certificate inside an
ephemeral volume. Application path, query, body, User-Agent and cookie markers
must reach the protected application handler but must never cross the PALISADE
service boundary. The test reports only closed pass/fail conditions.

## Run it

Docker Engine and Docker Compose v2 are required. The script deliberately uses
`pull_policy: never` for the runtime topology. Make the reviewed image digest
available locally first:

```sh
docker pull nginx@sha256:db35bfc6b2951e7f8a72db5db120288c127ffaeeb4a6d4b95a26fead017d5913
make nginx-deployment-plan
make nginx-deployment-test
```

The currently pinned manifest resolved to nginx 1.31.4 on the local arm64 test
host. The digest, not the mutable version label, is the executable contract.
The runner refuses an absent digest instead of silently pulling a replacement.
It removes its containers, private network and certificate volume on success or
failure.

The plan command is Docker-independent and emits a closed JSON document. Its
static tests are part of `make test`; the actual container test remains opt-in
because Docker is not part of the base Go/Node toolchain.

## Operational translation

The fixture addresses are documentation-only TEST-NET values. A deployment
must substitute the exact address or addresses of its immediate, operator-
controlled TLS terminator. Do not trust a client-reachable subnet. If proxy
addresses are dynamic, establish and validate a stable network identity before
enabling forwarded-header trust. Direct access to the origin must be blocked at
the network boundary even though PALISADE still ignores forwarding headers from
an untrusted peer.

Keep nginx-to-origin traffic on an authenticated or otherwise isolated private
network appropriate to the deployment. This fixture uses HTTP/1.1 plaintext
only inside its one-host internal Docker network; it is not a general claim
that plaintext origin links are safe.

## Deliberate limits

This contract covers one nginx digest on one local Docker engine. It is not
evidence for:

- another nginx build, ingress controller, CDN or cloud load balancer;
- public-PKI issuance, renewal, revocation or certificate rotation;
- HTTP/3, QUIC, cross-host routing or production DNS;
- multiple PALISADE replicas or distributed challenge/redemption state;
- representative capacity, latency, detection efficacy or false-positive rate.

Each additional proxy or topology needs its own pinned configuration and the
same direct-spoof, raw-boundary, rollback and failure-policy checks. Production
promotion still requires linked local outcomes and operator review.
