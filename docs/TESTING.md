# Testing strategy

PALISADE treats tests as enforcement boundaries, not only regression examples.
All repository fixtures are synthetic. Raw deployment traffic, encrypted
shadow logs, private analysis reports and customer identifiers must never enter
tests, CI artifacts or public failure output.

## Required local release gates

`make verify` runs the complete gate set on a maintainer-controlled macOS or
Linux host. The repository intentionally has no GitHub Actions workflow and no
hosted CI requirement; local release evidence must be reviewed before a signed
tag is published.

| Layer | Gate | Current target |
|---|---|---|
| Go unit/integration/contract | `go test -race ./...` | all packages pass under the race detector |
| Go coverage | `make coverage-check` | at least 70% overall and 70% in every listed security-critical package |
| Go static analysis | `go vet ./...` | no findings |
| Decision hot path | `TestInProcessDecisionP95MeetsPilotBudget` | p95 below 10 ms over 1000 in-process decisions using the production detector set |
| TypeScript | `pnpm test` and `pnpm typecheck` | sensor, dashboard and website pass |
| Reproducible assets | `pnpm build` | sensor, embedded dashboard and website build from the lockfile |
| Offline evaluation | `python3 -m unittest scripts/test_evaluate_offline.py` | synthetic evaluation cases pass |
| Privacy/licensing | `make privacy-check` and `make license-check` | repository-index attack fixtures and license boundary pass |

The latency test is a regression gate for the in-process decision path, not a
claim about network, reverse-proxy or end-user latency. The benchmark
`BenchmarkProductionDecisionPath` reports allocations and throughput for
diagnosis without turning noisy allocation changes into an automatic release.
The runtime-egress regression test parses Go source and scans production
TypeScript callsites. A new outbound primitive fails until its destination,
activation, data classes and privacy boundary are added to the reviewed
manifest. See the [runtime egress inventory](RUNTIME_EGRESS.md).

## Test pyramid

- Unit tests cover detector evidence, score fusion, policy ordering, bounded
  state, cryptography helpers and closed validation rules.
- Integration tests cover the HTTP API, encrypted shadow pipeline, offline
  importer, generic local evidence importer, verified aggregate sequence
  analyzer, signed rollout workflow, challenge lifecycle and reference origin
  middleware. Origin-coverage tests exercise authenticated cumulative reports,
  idempotent retries, monotonic counters, restart baselines, the 1,024-source
  bound and rejection of free-form endpoint data. Adapter tests additionally
  prove that fail-open, fail-closed and bound challenge-retry completions land
  in exactly one closed disposition without exporting request fields.
- Consumer contract tests ensure the server and Go origin adapter agree on
  pass, delay, throttle, challenge and block responses and reject malformed or
  risky shadow responses. The versioned, language-neutral [origin adapter
  conformance suite](ADAPTER_CONFORMANCE.md) executes the same nine synthetic
  pass, response, outage and malformed-response scenarios against the Go
  reference implementation and includes negative assertions for application
  URLs, queries, bodies, user agents and cookies.
- Challenge accessibility contract tests cover semantic status output, visible
  focus styling, 44-pixel controls, reduced-motion and forced-color CSS, absence
  of focus hijacking, a working no-JavaScript form, closed form parsing, safe
  same-origin redirect selection and identical fallback outcome handling.
- Component tests cover privacy-sensitive sensor behavior and truthful
  aggregate dashboard presentation, including explicit protected-handler scope
  and outcome-ingestion loss states.
- Privacy-guard self-tests stage renamed synthetic attack fixtures in isolated
  temporary Git repositories and require fail-closed rejection.

The generic local import suite additionally rejects unknown and duplicate JSON
fields, ambiguous label provenance, direct-reference leakage, decreasing event
time, incomplete publication and cross-day pseudonym linkage. Owner-only file
mode integration tests run on macOS/Linux; pure contract and pseudonym tests run
on every supported build host.

The local sequence-analysis suite authenticates shard fingerprints, rejects
undeclared files and scan-budget overflow, verifies inactivity and maximum-age
boundaries, enforces one heap entry per active sequence, keeps the three
evidence dimensions separate and searches serialized reports for row-level
identifiers. Its package is part of the 70% security-critical coverage gate.

The holdout suite runs the importer, verified reader, sequence engine, optional
family annotations and aggregate evaluator end to end on synthetic data. It
tests predeclared chronological separation, crossing-window exclusion,
unknown/ambiguous labels, collection artifacts, seen versus unseen families,
duplicate annotation poisoning, hard annotation budgets and absence of
sequence/family identifiers in serialized reports. The public adversarial
scenario contract contains no deployment records.

The encrypted-shadow holdout suite separately verifies that partition
membership follows decision time rather than delayed-outcome arrival, exact
decision/endpoint linkage is preserved, unknown and ambiguous labels stay in
the denominator, endpoint/cohort slices sum to their partition and private
decision IDs never enter the report. File tests require create-only `0600`
output outside Git.

Adaptive-response tests prove that each closed cost factor changes only the
bounded throttle or temporary-block duration, weak/benign evidence cannot
raise cost, signed maxima and rollout expiry remain absolute, and retry history
expires with the bounded session. Engine integration tests cover the first
response and a premature retry without relying on wall-clock sleeps.

The v0.4 progression contract runs the ordered sequence `observe → delay →
throttle → accessible step-up → temporary block` through the rollout boundary
and asserts its closed handling, status, retry and expiry values. Failure cases
prove that an expired rollout and an excluded endpoint return to shadow
`observe`, while a lower signed maximum caps rather than raises the action. A
synthetic concurrency test applies 32,000 mixed progression decisions and
requires deterministic results; a separate 8,000-session stress test keeps the
five-minute response-history store within its configured 256-entry bound under
concurrent eviction. Both run under `go test -race`; the diagnostic
`BenchmarkProgressionController` reports the isolated controller cost.

Challenge-budget tests keep promotion evidence scoped to one exact signed
canary and endpoint. They cover mature-sample insufficiency, missing terminal
outcomes, abandonment and accessible-fallback Wilson bounds, cross-rollout
isolation, aggregate arithmetic poisoning, signed-plan tampering and
non-finite threshold rejection. Fallback usage is tested as a review budget,
not as proof of abuse or a reason to remove the accessible path.

The versioned [public adversarial suite](ADVERSARIAL_FIXTURES.md) links the
roadmap threat categories for replay, poisoning, missing signals, spoofed
headers, accessibility and adapter failures to executable synthetic tests. A
repository contract fails if a required scenario disappears, changes its
closed expected result or points at a missing test function.

## Known gaps

The current baseline does not yet include a real-browser end-to-end suite,
reverse-proxy/TLS deployment tests, multi-replica challenge-state tests or a
sustained end-to-end load environment. The in-process concurrency contract is
not a proxy-capacity or production-throughput claim. Add those environments
with the corresponding product feature; do not simulate unsupported production guarantees. False-positive,
accessibility and challenge-abandonment rates require linked deployment
outcomes and cannot be replaced by synthetic test coverage.
