# Synthetic benchmark protocol

PALISADE ships a closed, local benchmark protocol for reproducible engineering
comparisons between exact source commits. It uses synthetic requests only. It
does not read shadow logs, deployment exports, customer data or private
evaluation reports, and it does not measure detection efficacy.

## Run the protocol

Inspect the fixed command plan without invoking Go:

```sh
make benchmark-plan
```

From a clean checkout, create an owner-only directory outside every Git
worktree and run the complete suite:

```sh
mkdir -m 700 /private/tmp/palisade-benchmark
make benchmark-local OUTPUT=/private/tmp/palisade-benchmark/report.json
```

The runner requires Go 1.27.x, `GOMAXPROCS=1`, a clean 40-character source
commit and a previously nonexistent output file. It sets `GOPROXY=off`,
`GOSUMDB=off`, `GOTOOLCHAIN=local` and `GOFLAGS=-mod=readonly`, so missing
modules fail rather than being downloaded. These Go settings are not an
operating-system network sandbox. Run the command in an OS or container network
sandbox when a hard no-network execution boundary is required.

The JSON report is published create-only with mode `0600`; its parent must be
owned by the invoking user with mode `0700`. The output is rejected inside any
Git worktree. Its closed schema is
[`synthetic-benchmark-report-v1.schema.json`](../schemas/synthetic-benchmark-report-v1.schema.json).

## Fixed measurements

The suite records two different measurement classes and keeps their meaning
separate:

- The production Shadow decision path and signed adaptive Enforcement decision
  path each run 100 warm-up decisions and then time 1,000 individual in-process
  operations. Their p50, p95 and p99 are reported. The existing p95 below
  10 ms pilot budget remains the only timing release gate.
- The production Shadow decision path, signed adaptive Enforcement decision
  path and isolated progression controller each run seven standard Go
  microbenchmark samples at 250 ms with one logical CPU. The report contains
  every aggregate sample and the median/minimum/maximum of ns/op, B/op and
  allocations/op. Those run summaries are not operation-level latency
  percentiles and are intentionally not release thresholds.

The report includes only Go version, GOOS, GOARCH, CGO state and the fixed CPU
count. It deliberately excludes hostname, usernames, local paths, source
records and request identifiers.

## Interpretation and publication boundary

A result supports only a narrow statement: on the reported environment and
source commit, the synthetic in-process code paths produced the recorded
latency and allocation aggregates. It excludes reverse-proxy, network, TLS,
browser and user-perceived latency; concurrent capacity; multiple replicas;
detection quality; false-positive rate; accessibility outcomes; and production
traffic variability. Hardware, operating-system scheduling, power state and Go
toolchain changes can move the numbers.

Do not publish a report as proof of bot-detection effectiveness. A reviewed
public baseline must retain the schema, exact source commit, complete protocol,
environment fields and all limitation statements. Deployment measurements are
a separate aggregate evaluation workflow and must never be copied into this
synthetic report.
