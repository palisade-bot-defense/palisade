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
| Local evidence import and evaluation | `go test -race ./internal/offlineimport ./internal/localsequence` | synthetic contract, privacy-boundary, budget and holdout cases pass |
| Privacy/licensing | `make privacy-check` and `make license-check` | repository-index attack fixtures and license boundary pass |
| Release authenticity | `make release-signing-check` | exact artifact manifest, pinned signer, private-key isolation and tamper rejection pass offline |
| Release reproducibility | `python3 -m unittest scripts/test_compare_release_reproduction.py` | exact two-candidate byte comparison, signed-tag provenance, closed attestation, unsafe archive and publication-race cases pass offline |
| Synthetic red team | `make red-team` | all sixteen scenarios pass across the eight v0.9 attack categories with module downloads disabled |
| Synthetic findings contract | `python3 -m unittest scripts/test_red_team_findings.py` | report closure, suite binding, provenance, create-only output and limitation tamper cases pass |
| Operator Shadow drill | `make operator-shadow-drill` | production secrets, session/proof flow, encrypted records, aggregate analysis, unsigned-enforcement rejection and Shadow restart pass on loopback |
| TLS/proxy deployment boundary | `make deployment-tls-test` | both reference adapters pass real local TCP/TLS/HTTP/2 trust and privacy checks under the race detector |
| Proxy/TLS load diagnostic | `make proxy-tls-load-plan` then `make proxy-tls-load-local` | bounded opt-in HTTP/2/TLS repetition passes both reference adapters with closed aggregate output; no production capacity claim |
| Published synthetic benchmark | `make benchmark-verify REPORT=benchmarks/synthetic-baseline-afc23a3.json` | exact profiles, samples, recomputed summaries, source commit and limitations pass |
| v1 compatibility freeze | `make compatibility-check` | exact public contracts, legacy readers, threat model and runbook hashes pass |
| Artifact lifecycle and migrations | `make migration-check` | every frozen contract has one lifecycle class and every predecessor has one reviewed transition strategy |

## Environment-specific real-browser gate

Run `make browser-e2e` on a maintainer machine with the documented local
Chrome/Chromium, Node and Go versions before publishing a challenge-affecting
release candidate. It completes one-time redemption, fresh evaluation and
fallback without external requests. The system browser is deliberately not
downloaded by `make verify`, so the result must record its exact browser version
separately from the hermetic release checks. `make check` still validates the
dependency-free driver syntax, and `go test ./...` compiles its fixture.

The latency tests are regression gates for the in-process decision paths, not
claims about network, reverse-proxy or end-user latency. They report p50, p95
and p99 for the production Shadow and signed adaptive Enforcement profiles;
only p95 below 10 ms is a hard timing gate. The production, signed Enforcement
and isolated rollout-controller microbenchmarks report allocations and
throughput for diagnosis without turning noisy allocation changes into an
automatic release. The closed [synthetic benchmark protocol](BENCHMARKS.md)
runs seven fixed samples, binds the aggregate report to a clean commit and
records its limitations without using deployment data.
The separate [local HTTP load diagnostic](LOCAL_LOAD_TEST.md) runs bounded
synthetic concurrency through the production-configured session, one-time
proof and origin-check HTTP path. It reports only aggregate error classes,
throughput and nearest-rank p50/p95/p99/max latency. It is deliberately not a
release threshold: local scheduler and hardware variance must not be confused
with a stable performance regression gate, and the runner does not model a
proxy, TLS, multiple replicas or production traffic.
The opt-in [local proxy/TLS load diagnostic](PROXY_TLS_LOAD_TEST.md) complements
that runner with repeated complete protected requests through both Go reference
adapters on ephemeral loopback HTTP/2/TLS hops. Its small contract case runs
under the race gate; the sustained timing run is host-dependent and has no
release threshold.
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
  pass, response, outage and malformed-response scenarios against two
  independently implemented Go reference adapters and includes negative
  assertions for application URLs, queries, bodies, user agents and cookies.
- Normalized-signal contract tests require the public Go validators,
  language-neutral catalog, OpenAPI enums and typed protobuf enums to remain
  identical. Poisoning cases reject unknown and trailing catalog fields,
  free-form request actions, incomplete verified-crawler tuples, unpaired edge
  classifications and duplicate protobuf field or enum numbers. The public
  contract package is included in the per-package 70% coverage gate.
- Signed upstream-envelope tests cover direct-peer spoofing, key and signature
  failure, strict canonical JSON, unknown and duplicate fields, freshness,
  replay, nonce capacity, closed cross-field invariants and conservative merge
  conflicts in both reference adapters. No raw upstream fixture is required.
- Signed local-artifact tests cover domain-separated signatures, key and type
  confusion, expiry, revision rollback, file permissions, symlinks, worktree
  placement, closed threshold ordering and compiled detector selection. Run
  the synthetic package directly with `make artifact-contract`; no deployment
  data or network access is involved.
- Challenge accessibility contract tests cover semantic status output, visible
  focus styling, 44-pixel controls, reduced-motion and forced-color CSS, absence
  of focus hijacking, a working no-JavaScript form, closed form parsing, safe
  same-origin redirect selection and identical fallback outcome handling.
- Component tests cover privacy-sensitive sensor behavior and truthful
  aggregate dashboard presentation, including explicit protected-handler scope
  and outcome-ingestion loss states.
- Privacy-guard self-tests stage renamed synthetic attack fixtures in isolated
  temporary Git repositories and require fail-closed rejection.
- Release-signing self-tests use temporary synthetic keys and artifacts outside
  the repository. They reject permissive or worktree-resident private keys,
  modified artifacts and an unpinned signer without publishing a tag or release.
- Release-reproduction self-tests construct two bounded synthetic candidates,
  require exact artifact and manifest identity, reject unsafe or duplicate tar
  members, validate signed-tag reachability, and keep the create-only
  attestation outside Git. They test the comparison protocol; they do not claim
  that a second maintainer or independent build host participated.

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

The migration-matrix suite requires exact coverage of every frozen API/schema
and every historical schema still present in the repository. It rejects missing
or duplicate lifecycle classifications, unreviewed transition changes and any
attempt to rewrite Shadow v1 outcomes as if their absent decision linkage were
known. Historical analyses and reviews can only be regenerated from current
authenticated sources and never retain rollout authority.

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

The separate versioned [synthetic red-team baseline](RED_TEAM.md) exercises
evasion, poisoning, proof relay, session reset, resource exhaustion and rollout
compromise as one module-download-disabled run. Use an OS network sandbox for
the exercise itself. A clean-commit run can produce a closed, aggregate findings
record only after every named control passes. It is a security-regression suite,
not an independent review or evidence of production detection efficacy.

## Known gaps

The local [real-browser challenge suite](BROWSER_E2E.md) now covers the
single-process reference adapter's rendered challenge, one-time redemption,
fresh evaluation and alternative-method route in Chrome. The separate
[local TLS deployment suite](TLS_DEPLOYMENT_TESTS.md) now covers both reference
adapters on real loopback TCP/TLS/HTTP/2 hops, including the trusted immediate
proxy boundary, direct forwarding-header spoof rejection and raw-request
isolation from PALISADE. The bounded
[local HTTP load diagnostic](LOCAL_LOAD_TEST.md) now covers sustained
single-process loopback HTTP/1.1 session, proof and origin-decision traffic. The
bounded [local proxy/TLS load diagnostic](PROXY_TLS_LOAD_TEST.md) now repeats
the same protected workflow through both Go reference adapters over loopback
HTTP/2/TLS. The opt-in [pinned nginx contract](NGINX_DEPLOYMENT_TEST.md)
adds one concrete external proxy implementation: an exact nginx digest with an
internal Docker topology, real
HTTP/2/TLS termination and direct forwarding-header spoof rejection. It does
not cover other nginx builds, CDNs or cloud proxies. The baseline also does not
include public-PKI and certificate-rotation exercises,
HTTP/3, multi-replica challenge state, assistive-technology automation or a
representative production capacity environment. These local contracts are not
proxy-capacity, production-throughput or human-accessibility claims. Add those
environments with the corresponding product feature; do not simulate
unsupported production guarantees. False-positive, accessibility and
challenge-abandonment rates require linked deployment outcomes and cannot be
replaced by synthetic test coverage.
