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
  risky shadow responses.
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

The versioned [public adversarial suite](ADVERSARIAL_FIXTURES.md) links the
roadmap threat categories for replay, poisoning, missing signals, spoofed
headers, accessibility and adapter failures to executable synthetic tests. A
repository contract fails if a required scenario disappears, changes its
closed expected result or points at a missing test function.

## Known gaps

The current baseline does not yet include a real-browser end-to-end suite,
reverse-proxy/TLS deployment tests, multi-replica challenge-state tests or a
sustained load environment. Add those with the corresponding product feature;
do not simulate unsupported production guarantees. False-positive,
accessibility and challenge-abandonment rates require linked deployment
outcomes and cannot be replaced by synthetic test coverage.
