# Local HTTP load diagnostic

The local load diagnostic exercises PALISADE's real production-configured HTTP
path under bounded synthetic concurrency. It is intended to find protocol,
stability and obvious capacity regressions before an operator builds a
deployment-specific test environment. It is not a benchmark publication or an
efficacy claim.

## What it exercises

The runner starts one PALISADE process in Shadow mode on two random loopback
ports with independently generated process-local credentials. The public
listener requires the server-issued session cookie. Every worker owns one
session and repeats this measured transaction:

1. request a fresh one-time `read` proof from `POST /v1/token`;
2. submit closed synthetic observations to `POST /v1/origin-check` with an
   opaque server-side challenge binding;
3. require the response to remain `204`, `pass`, `allow|observe`, and `shadow`
   with no rollout authority.

Session issuance happens before the timer starts, but its HTTP request is
included in the request counter. The latency sample begins immediately before
token issuance and ends after validation of the origin response. Percentiles
use the nearest-rank method over successful complete transactions only. Each
worker reuses one HTTP/1.1 connection for its measured operations; this does
not reproduce a particular reverse proxy's connection-pool behavior.

The diagnostic does not enable the encrypted Shadow sink. That keeps this
profile focused on the decision service rather than local disk and encryption
performance, which need a separate operator-owned storage test.

## Run it

Build a local binary and inspect the closed plan first:

```sh
go build -trimpath -o bin/palisade ./cmd/palisade
make load-test-plan
```

Run the bounded defaults—30 seconds, eight workers, and at most 200,000 complete
or failed operations:

```sh
make load-test-local BINARY=./bin/palisade
```

For a short diagnostic:

```sh
python3 scripts/load_test_local.py \
  --binary ./bin/palisade \
  --duration-seconds 5 \
  --concurrency 4 \
  --max-operations 1000
```

The hard limits are 1–300 seconds, 1–64 workers and 1–200,000 operations. Each
HTTP response is capped at 64 KiB and each request times out after five seconds.
The process listens only on `127.0.0.1`; the runner has no external URL option.

## Output and interpretation

Standard output is one compact `palisade.local-load-diagnostic.v1` JSON object.
It contains only:

- configured bounds and the fixed server profile;
- attempted, completed and failed operation counts;
- HTTP request count and successful operations per second;
- p50, p95, p99 and maximum transaction latency;
- counts for seven closed failure classes;
- the stop reason and fixed limitations.

The report never includes ports, session identifiers, cookies, proofs,
challenge bindings, request bodies, response headers, timestamps or per-request
latencies. PALISADE stdout and stderr are discarded. The runner inherits only
`PATH` and optional `TMPDIR`, then supplies newly generated credentials. It
does not read a deployment configuration or any traffic data.

Any failed operation, malformed response or early server exit makes the result
`failed` and the command exits nonzero. An operator may retain the aggregate
JSON outside Git together with machine and toolchain context, but must not
publish it as representative deployment performance without a reviewed test
protocol.

## Deliberate limits

This is a single-process loopback HTTP/1.1 diagnostic without TLS, a reverse
proxy, HTTP/2 or HTTP/3, browser execution, encrypted logging, challenge
rendering, delayed outcomes or multiple replicas. It cannot establish:

- production throughput or tail latency;
- detection efficacy or a false-positive rate;
- accessibility or challenge-abandonment rates;
- proxy, certificate-rotation or distributed-state behavior;
- suitability for a specific host, traffic mix or service-level objective.

The existing in-process p95-below-10-ms test remains the release latency gate.
Deployment capacity must be measured in the operator's architecture with
representative, lawfully handled traffic and linked outcomes. Raw inputs and
private reports stay outside Git and are never required by this diagnostic.
