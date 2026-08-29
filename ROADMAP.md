# Product roadmap

PALISADE is building an open-source, EU-first bot-defense control loop that can
show **where evidence stayed, why a decision was made and how enforcement was
approved**. The objective is not a mythical challenge that every person can
solve and no bot can solve. Adaptive attackers make that guarantee impossible.
The objective is to combine bounded local evidence, attacker cost and measured
outcomes while keeping harm to legitimate users within an explicit budget.

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
- rollback time and the fraction of enforcement covered by a signed rollout.

No single detection-rate number can replace this scorecard. Results from
synthetic fixtures, one deployment or weak upstream labels are never presented
as general efficacy.

## v0.2 — prove data sovereignty

Status: implementation complete; the clean macOS/Linux release verification
and first independently reproduced signed artifact set remain the exit gate.

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
- link delayed confirmed-human and operator-confirmed-abuse outcomes to the exact
  decision while reporting ambiguous and missing labels;
- publish synthetic adversarial fixtures for replay, poisoning, missing signals,
  spoofed headers, accessibility and adapter failures.

Exit gate: at least one representative private shadow deployment produces
uniquely linked outcomes for both confirmed-human and confirmed-abuse cohorts,
reports confidence intervals and stays below 10 ms p95 added in-process decision
latency. No automatic blocking is enabled.

## v0.4 — make response adaptive and humane

Deliverables:

- add deployment-owned, server-generated decoy and honeypot contracts whose
  hits are evidence rather than an automatic verdict;
- vary bounded response cost by endpoint value, evidence confidence, recent
  behavior and retry history;
- harden one-time, action-bound challenge redemption against replay and relay;
- provide keyboard, screen-reader, reduced-motion and non-JavaScript fallback
  paths with equal security accounting;
- test the progression `observe → delay → throttle → accessible step-up →
  temporary block` under load and failure;
- make challenge abandonment and fallback first-class rollout budgets.

Exit gate: a signed canary improves a chosen protected outcome on a chronological
holdout without exceeding its confirmed-human, accessibility, latency or
abandonment budget; rollback is exercised and timed.

## v0.5 — build the open deployment ecosystem

Deliverables:

- stabilize the normalized HTTP and protobuf adapter contracts;
- publish generic reference integrations for common reverse-proxy patterns,
  starting with the existing Go origin middleware;
- define conformance fixtures so community adapters can be certified without
  production traffic or PALISADE-operated infrastructure;
- support signed, expiring local artifacts for crawler registries, policies,
  detector bundles and rollout plans;
- document compatibility with local upstream signals such as WAF verdicts,
  reputation classes and challenge outcomes without embedding vendor payloads;
- create maintainer, security-response and release-signing processes that do not
  depend on one private deployment.

Exit gate: two independently implemented adapters pass the same privacy,
failure-policy and decision-contract suite; upgrading or rolling back an
artifact does not require data export to the project.

## v0.9 — independent evidence

Deliverables:

- commission independent application-security, privacy/data-protection and
  accessibility reviews and publish remediations;
- run documented red-team exercises against evasion, poisoning, proof relay,
  session reset, resource exhaustion and rollout compromise;
- publish reproducible aggregate benchmarks with dataset limitations and no raw
  deployment records;
- freeze v1 schemas, compatibility policy, threat model and operator runbooks;
- prepare a defensive publication and trademark policy for the open protocols
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

Version 1.0 will still not claim universal bot detection, universal legal
compliance or an unsolvable challenge.

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
- opaque auto-learning that can activate blocking without measured review;
- claims of 100% separation, zero false positives or automatic GDPR compliance.
