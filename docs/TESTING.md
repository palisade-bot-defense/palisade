# Testing strategy

PALISADE treats tests as enforcement boundaries, not only regression examples.
All repository fixtures are synthetic. Raw deployment traffic, encrypted
shadow logs, private analysis reports and customer identifiers must never enter
tests, CI artifacts or public failure output.

## Required local and CI gates

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
GitHub-hosted enforcement also requires Actions to be enabled for the
repository and the observed CI/Security check names to be required on `main`;
verify those settings after repository or organization transfers.

## Test pyramid

- Unit tests cover detector evidence, score fusion, policy ordering, bounded
  state, cryptography helpers and closed validation rules.
- Integration tests cover the HTTP API, encrypted shadow pipeline, offline
  importer, signed rollout workflow, challenge lifecycle and reference origin
  middleware.
- Consumer contract tests ensure the server and Go origin adapter agree on
  pass, delay, throttle, challenge and block responses and reject malformed or
  risky shadow responses.
- Component tests cover privacy-sensitive sensor behavior and truthful
  aggregate dashboard presentation.
- Privacy-guard self-tests stage renamed synthetic attack fixtures in isolated
  temporary Git repositories and require fail-closed rejection.

## Known gaps

The current baseline does not yet include a real-browser end-to-end suite,
reverse-proxy/TLS deployment tests, multi-replica challenge-state tests or a
sustained load environment. Add those with the corresponding product feature;
do not simulate unsupported production guarantees. False-positive,
accessibility and challenge-abandonment rates require linked deployment
outcomes and cannot be replaced by synthetic test coverage.
