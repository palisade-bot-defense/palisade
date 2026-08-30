# Local proxy/TLS load diagnostic

This opt-in diagnostic exercises both Go reference adapters through complete
synthetic protected requests over real loopback TCP, TLS and HTTP/2. It is a
bounded integration and stability tool, not a production benchmark or a
detection-efficacy claim.

The implementation lives entirely in Go test files. It is not linked into the
`palisade` runtime binary and therefore adds no production HTTP client or
runtime egress. It reads no deployment configuration, logs or private report,
uses no external destination, and persists neither certificates nor request
records.

## Profiles

The fixed profiles are:

1. `origin_middleware_trusted_proxy_http2_tls`: synthetic client -> TLS edge ->
   TLS Go origin middleware -> TLS PALISADE fixture -> protected handler.
2. `standalone_reverse_proxy_http2_tls`: synthetic client -> TLS standalone
   adapter -> TLS PALISADE fixture and TLS protected upstream.

Each worker obtains a session on its first operation. Every operation includes
a fresh one-time proof, a closed origin check and the protected upstream
request. The trusted-edge profile overwrites the supported forwarding headers
at the exact allowlisted loopback peer. The service fixture requires the closed
transport classes expected for each profile and rejects application path,
query, body, User-Agent or cookie markers at the PALISADE boundary.

## Inspect and run

Inspect the closed execution plan first:

```sh
make proxy-tls-load-plan
```

Run the defaults: five seconds per profile, four workers, and no more than
200,000 operations per profile:

```sh
make proxy-tls-load-local
```

Override any bound explicitly:

```sh
make proxy-tls-load-local \
  DURATION_SECONDS=30 \
  CONCURRENCY=16 \
  MAX_OPERATIONS=200000
```

Hard limits are 1–300 seconds, 1–64 workers and 1–200,000 operations per
profile. Each client request has a five-second timeout and every response is
capped at 64 KiB. Invalid values fail before a listener starts. The normal
`go test -race ./...` path executes a 32-operation contract regression and
skips the opt-in sustained run.

## Closed report

With `-v`, the opt-in test logs one compact
`palisade.proxy-tls-load-diagnostic.v1` JSON object. It contains only:

- the configured bounds and two fixed profile names;
- attempted, completed and failed operation counts;
- service and protected-upstream request counts;
- successful operations per second;
- nearest-rank p50, p95, p99 and maximum successful-operation latency;
- closed failure and protocol/privacy/service/upstream boundary counters;
- a fixed stop reason, result and limitations.

The report validator rejects counter conflicts, negative or over-budget
values, non-finite or misordered latency values, profile reordering, false pass
or failure states, and any claim that deployment records were used. Tests also
scan serialized output for fixture paths, queries, bodies, user agents,
cookies, addresses, session IDs, proof tokens and URLs.

Results vary with hardware, operating system, scheduler and concurrent local
work. If an operator retains the aggregate JSON, machine and toolchain context
must be recorded separately and no private inputs should be added.

## Deliberate limits

This diagnostic covers only the two repository reference adapters with an
ephemeral self-signed loopback fixture. It does not cover:

- a particular CDN, nginx build, load balancer or other external proxy;
- public PKI, certificate issuance, rotation or revocation;
- HTTP/3, QUIC, production DNS or cross-host latency;
- multiple replicas, shared challenge state, failover or rolling deployment;
- encrypted Shadow-log storage performance;
- representative traffic, detector efficacy, false-positive rates,
  accessibility or challenge abandonment.

Production capacity and safety require a deployment-owned test with the exact
proxy/TLS topology and representative, lawfully handled traffic. Detection and
promotion claims additionally require linked outcomes; synthetic success does
not supply them.
