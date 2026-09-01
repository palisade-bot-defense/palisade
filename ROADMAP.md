# Product roadmap

PALISADE is building an open-source, EU-first **proof-of-human protocol**: a way
for a relying service to know that a live, continuous and—where a surface
requires it—unique person, or an agent authorized by one, is on the other end of
a call, message or transaction, while showing **where evidence stayed, why a
decision was made and how enforcement was approved**.

The objective is not a mythical challenge that every person can solve and no bot
can solve. Adaptive attackers make that guarantee impossible. The objective is
graded, verifiable human assurance: combine bounded local evidence, verified
assertions, attacker cost and measured outcomes while keeping harm to legitimate
users within an explicit budget.

Bot defense is no longer the product. The detector, decoy and challenge
machinery remains as the evidence substrate of the lowest assurance levels, and
the three-score model remains intact underneath. The success criterion changed:
not "blocked the automated client", but "the relying service could justify how
much human evidence it had, and what obtaining it cost the person." The
assurance ladder and its unimplemented layers are specified in
[Human Trust Protocol](docs/HUMAN_TRUST_PROTOCOL.md); the boundary decision is
[ADR 0004](docs/adr/0004-verify-humans-never-issue-identity.md).

The product strategy and market boundary are documented in
[Differentiation](docs/DIFFERENTIATION.md). The machine-readable privacy contract
starts with the [Sovereignty Report](docs/SOVEREIGNTY.md).

## Product contracts

1. **Sovereignty contract:** no mandatory PALISADE cloud, vendor telemetry
   export or third-party runtime call; the operator chooses processing, storage,
   keys and optional upstream services.
2. **Evidence contract:** every decision exposes separate automation, abuse
   intent and continuity scores, stable reason codes, policy/model versions and
   deterministic replay evidence.
3. **Rollout contract:** risky enforcement begins in shadow mode and can advance
   only through measured, scoped, signed, expiring and reversible artifacts.

These contracts are the durable product boundary. Individual detectors,
challenges and adapters can improve without weakening it.

## North-star scorecard

Every release candidate reports all applicable values, including missing data:

- confirmed abuse reaching protected outcomes, by endpoint class;
- confirmed-human false-positive and abandonment intervals;
- coverage, unknown-label rate and delayed-outcome linkage rate;
- challenge completion, fallback and unresolved rates;
- p50/p95/p99 added decision latency and failure behavior;
- retained data classes, maximum retention and configured external egress;
- rollback time and the fraction of enforcement covered by a signed rollout;
- once any surface is gated on assurance: the confirmed-human false-positive and
  abandonment interval **per assurance level**, by endpoint class, plus the share
  of users who completed the alternative path instead.

No single detection-rate number can replace this scorecard. Results from
synthetic fixtures, one deployment or weak upstream labels are never presented
as general efficacy.

## v0.2 — prove data sovereignty

Status: implementation complete; deterministic candidates and a closed local
two-candidate comparison gate are implemented. The clean macOS/Linux release
verification and first genuinely independent reproduced signed artifact set
remain the exit gate.

Deliverables:

- [x] publish the deterministic `palisade sovereignty-report` command and versioned
  JSON Schema;
- [x] document product invariants separately from unverified operator declarations;
- [x] add a static runtime-egress inventory and regression test for every new
  network client in the reference service;
- [x] inventory collected, derived, persisted and exported fields in a
  machine-readable data map;
- [x] produce a reproducible local release checklist without GitHub Actions or
  mandatory hosted build infrastructure;
- [x] keep private logs, normalized deployment datasets, keys and reports outside
  every Git worktree by construction and documentation.

Exit gate: a clean reference deployment can generate a reviewable sovereignty
report; all runtime egress and persisted data classes are accounted for; local
privacy and license checks pass from a clean checkout.

## v0.3 — prove the local evidence loop

Status: in progress. Generic import and bounded aggregate sequence derivation
are implemented. The local chronological/unseen-family evaluator and its first
synthetic adversarial contract are implemented; representative private
evaluation remains the active evidence gate.

Deliverables:

- [x] complete a generic, local-only import path for operator-authorized exports;
- [x] derive bounded minute-scale sequence features such as burst shape, endpoint
  transitions, decoy interaction and challenge lifecycle without emitting raw
  IP addresses, URLs, form data or exact pointer paths;
- [x] distinguish collection artifacts, automation evidence, harmful intent and
  session continuity in reports;
- [x] implement a one-pass local evaluator with a predeclared chronological
  boundary, fixed diagnostic rules, endpoint slices, Wilson intervals and an
  optional unseen-family partition;
- evaluate by endpoint class on chronological holdouts and unseen attack
  families instead of random row splits;
- [x] link delayed confirmed-human and operator-confirmed-abuse outcomes to the exact
  decision while reporting ambiguous and missing labels;
- [x] publish synthetic adversarial fixtures for replay, poisoning, missing signals,
  spoofed headers, accessibility and adapter failures.

Exit gate: at least one representative private shadow deployment produces
uniquely linked outcomes for both confirmed-human and confirmed-abuse cohorts,
reports confidence intervals and stays below 10 ms p95 added in-process decision
latency. No automatic blocking is enabled.

## v0.4 — make response adaptive and humane

Status: implementation complete, including a loopback-only real-browser
exercise of the reference adapter's challenge, one-time redemption and
alternative-method path. The signed canary, chronological holdout and measured
accessibility/latency/abandonment exit gate remain empirical work for an
operator-controlled deployment.

Deliverables:

- [x] add deployment-owned, server-generated decoy and honeypot contracts whose
  hits are evidence rather than an automatic verdict;
- [x] vary bounded response cost by endpoint value, evidence confidence, recent
  behavior and retry history;
- [x] harden one-time, action-bound challenge redemption against replay and relay;
- [x] provide keyboard, screen-reader, reduced-motion and non-JavaScript fallback
  paths with equal security accounting;
- [x] test the progression `observe → delay → throttle → accessible step-up →
  temporary block` under load and failure;
- [x] make challenge abandonment and fallback first-class rollout budgets.

Exit gate: a signed canary improves a chosen protected outcome on a chronological
holdout without exceeding its confirmed-human, accessibility, latency or
abandonment budget; rollback is exercised and timed.

## v0.5 — build the open deployment ecosystem

Status: implementation complete; the reproduction comparison protocol is now
executable locally. Enrolling independent public release and security
responders, publishing a reviewed release key and independently reproducing the
first signed artifact set remain the operational exit gate.

Deliverables:

- [x] stabilize the normalized HTTP and protobuf adapter contracts;
- [x] publish generic reference integrations for common reverse-proxy patterns,
  starting with the existing Go origin middleware;
- [x] define conformance fixtures so community adapters can be certified without
  production traffic or PALISADE-operated infrastructure;
- [x] support signed, expiring local artifacts for crawler registries, policies,
  detector bundles and rollout plans;
- [x] document compatibility with local upstream signals such as WAF verdicts,
  reputation classes and challenge outcomes without embedding vendor payloads;
- [x] create maintainer, security-response and release-signing processes that do not
  depend on one private deployment.

Exit gate: two independently implemented adapters pass the same privacy,
failure-policy and decision-contract suite; upgrading or rolling back an
artifact does not require data export to the project.

## v0.9 — independent evidence

Status: audit preparation in progress. A closed, module-download-disabled synthetic
red-team baseline, versioned threat model and reproducible synthetic benchmark
protocol are implemented. The first public aggregate benchmark and synthetic
red-team findings record are published with exact source commits and limitations.
The v1 contract, threat-model and operator-runbook freeze is machine checked.
A production-configured synthetic operator drill now covers the documented
Shadow landing state and unsigned-enforcement rollback boundary. A closed local
attestation now fails on any difference between two unsigned candidates from a
signed reachable source tag. Actual second-maintainer reproduction, independent
specialist reviews and an independent new-operator rehearsal remain open.

Deliverables:

- [ ] commission independent application-security, privacy/data-protection and
  accessibility reviews and publish remediations;
- [x] run documented synthetic red-team exercises against evasion, poisoning, proof relay,
  session reset, resource exhaustion and rollout compromise;
- [x] publish reproducible aggregate benchmarks with dataset limitations and no raw
  deployment records;
- [x] freeze v1 schemas, compatibility policy, threat model and operator runbooks;
- [ ] prepare a defensive publication and trademark policy for the open protocols
  and PALISADE name after specialist legal review.

Exit gate: all critical findings are fixed or explicitly accepted, the release
can be reproduced locally from a signed source tag, and a new operator can
complete shadow deployment and rollback using public documentation alone.

## v1.0 — trustworthy self-hosted baseline

The first stable release requires:

- the three product contracts to be implemented and covered by regression
  tests;
- versioned migration paths for every persisted or exchanged artifact;
- a measured reference deployment with published aggregate limitations;
- no unresolved critical security, privacy or accessibility findings;
- a supportable maintainer and vulnerability-disclosure process;
- no dependency on private PALISADE-operated services.

The versioned artifact-lifecycle and migration matrix now covers every frozen
contract and historical schema in the repository. This closes the local
migration-contract implementation item, but it does not close the representative
deployment, independent-review or maintainer-capacity gates above.

Version 1.0 will still not claim universal bot detection, universal legal
compliance, an unsolvable challenge, proof of personhood or a guarantee that a
verified assertion cannot be obtained under coercion or sale.

## Primary arc — human and agent provenance

Status: specified, unimplemented. This is now the product direction, not an
optional extension. It nevertheless does **not** short-circuit the v0.3–v0.9
exit gates: those gates prove that the evidence substrate underneath H1 and H2
is measured and honest, and an assurance ladder built on unmeasured evidence
would be worse than no ladder. The sequencing is deliberate—finish measuring the
substrate, then raise assurance on top of it.

The design, its egress and persistence rules, its legal-assessment items and its
own exit gates are in [Human Trust Protocol](docs/HUMAN_TRUST_PROTOCOL.md); the
boundary decision is
[ADR 0004](docs/adr/0004-verify-humans-never-issue-identity.md).

Deliverables:

- [x] specify a human-assurance assertion format with a JSON Schema, a
  deterministic offline verifier and conformance fixtures;
- [x] express verified interaction evidence as an H1 assertion on a separate
  versioned surface, without adding a persisted class, a request-path callsite
  or any change to the frozen decision contract;
- [x] add an interactive liveness challenge type before any H2 assertion is
  possible; the existing proof-of-work challenge is a cost and outcome signal
  that browser automation may complete routinely, so it cannot reach H2. The
  level it supports is computed and then withheld: raising the ceiling is the
  measurement deliverable below, not a constant change;
- [ ] accept platform device attestation as H3 evidence bound to the existing
  short-lived proof token;
- [x] define the signed, expiring local issuer trust-list and revocation
  artifact so H4 verification stays offline and fails closed on expiry;
- [x] generalize verified-for-a-purpose crawler identity into agent provenance,
  keeping identity separate from authorization;
- [ ] measure a confirmed-human false-positive and abandonment interval per
  assurance level, by endpoint class, before any surface is gated above H1.

The contract-versioning question that blocked every remaining deliverable is
settled by [ADR 0005](docs/adr/0005-assurance-api-surface.md): assurance lives on
its own versioned surface, so `/v1/decision`, its protobuf contract and every
existing adapter stay byte-identical. What remains is missing mechanism rather
than missing contract. H2 needs an interactive liveness challenge; H3 and H4 now
have a surface to arrive on and a trust root to be checked against, but no
verifier.

Exit gate: an independently implemented issuer adapter passes the same privacy,
failure-policy and decision-contract suite as a transport adapter; every gated
surface has a reviewed alternative path; red-team results exist for proof
relay, credential replay, issuer-key compromise and stale revocation. PALISADE
still issues no credential and claims no global proof of personhood.

## Private-data lane

Production exports may contain personal data and attack intelligence. They are
never project inputs and must remain on operator-controlled systems. Development
against private data happens in a separate local directory with operator-held
keys. Only reviewed aggregate metrics, synthetic fixtures or deliberately
anonymized artifacts may be proposed for publication. Pseudonymization alone is
not anonymization.

Community users can bring their own data to their own PALISADE installation.
Participation never requires submitting IP addresses, identifiers, traffic
records or model-training data to the project.

## Explicit non-goals

- a hosted SaaS, managed operations, billing or commercial feature tiers;
- a mandatory central telemetry cloud or cross-site identity graph;
- direct integration with a maintainer's private products or production data;
- treating automation, residential origin or a browser-like fingerprint as
  proof of harmful intent or humanity;
- operating an identity, biometric or personhood registry, issuing a
  PALISADE human credential, or claiming global proof of personhood; PALISADE
  verifies assertions made by operator-selected external issuers;
- opaque auto-learning that can activate blocking without measured review;
- claims of 100% separation, zero false positives or automatic GDPR compliance.
