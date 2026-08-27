# Roadmap

PALISADE advances through measured gates, not a promise of a universally unsolvable puzzle.

## 0. Runnable foundation — complete

- Go decision hot path, explicit fail-safe shadow boundary and replay-safe proofs.
- Typed detectors, three-score fusion, CEL policy and stable reasons.
- Privacy-limited TypeScript sensor and embedded light dashboard.
- Deterministic replay, container build and local security scans.

## 1. Deployment shadow pilot

- Define sanitized adapters for challenge systems, external risk providers and policy-alert sources.
- Import historical samples into a versioned, access-controlled replay dataset.
- Establish endpoint classes, outcome labels and verified-bot allowlists.
- Run parallel shadow decisions without changing live responses.
- Retain only encrypted, bounded local shadow records with explicit rotation, deletion and outcome provenance.
- Run bounded local aggregate analysis and produce operator-facing, non-enforcing recommendations.
- Sign expiring endpoint-scoped canary plans and return bounded origin enforcement results.
- Publish an internal baseline report by endpoint and attacker cohort.

Exit gate: no raw personal data in training/replay artifacts; p95 added decision latency below 10 ms in-process; unknown-label and endpoint outcome shares reported with confidence intervals. A false-positive rate is reported only after outcomes are uniquely linked to decisions and the confirmed-human cohort is representative.

## 2. Detector and calibration layer

- Add protocol/TLS normalization at the trusted proxy boundary.
- Add burst, navigation-graph, token-replay and decoy interaction detectors.
- Calibrate automation, intent and continuity separately by endpoint class.
- Add independently replaceable signed model/policy bundles; rollout plans and aggregate evaluation reports are gated today.
- Test poisoning, missing-signal and forged-sensor scenarios.

Current hardening: the reference adapter normalizes protocol, transport
security and address provenance without transmitting raw addresses; forwarded
metadata is accepted only from explicitly trusted TCP peers. Browser-event
counts are server-authoritative and create benign continuity evidence only when
backed by the bounded event store. Missing sensor data remains neutral, and
forged request counts are covered by regression tests. Navigation state is a
fixed nine-bit endpoint-class graph with capacity eviction; broad sweeps are
low-confidence shadow evidence and decoy interaction is isolated as its own
detector. Broader poisoning and proxy-misconfiguration tests remain open.

Exit gate: improvements hold on a time-separated test set and unseen attack families, not only random train/test splits.

## 3. Progressive response

- Observe → delay → throttle → accessible step-up → temporary block.
- Current hardening: `delay` is an explicit policy/action/directive contract.
  It returns a bounded one-second retry response instead of sleeping in the Go
  hot path, remains `observe` in shadow mode and requires a signed rollout for
  live application.
- Keep canary assignment deterministic, bind full enforcement to the exact measured predecessor canary and preserve one-command rollback.
- Bind challenges to short-lived server state, action, session and nonce. The
  native single-instance lifecycle and one-time redemption are implemented;
  shared multi-replica state and identity-aware families remain future gates.
- Offer WebAuthn/account re-authentication where identity assurance matters.
- Rotate decoy endpoints and challenge families without relying on secrecy alone.
- Measure completion and abandonment by browser/accessibility cohort.

Exit gate: documented rollback, support path and canary results; automatic blocking remains off until approved per endpoint.

## 4. Community hardening

- Maintain the AGPL-3.0-only core and Apache-2.0 sensor/SDK boundary; finalize the separate contributor agreement.
- Publish scrubbed replay fixtures and detector evaluation templates.
- Add reverse-proxy adapters and production shared state where measurements justify it.
- Commission independent privacy, accessibility and adversarial reviews.

## Non-goals

- Claiming 100% detection or a challenge no adversary can ever solve.
- Treating automation as abuse by itself.
- Fingerprinting people across unrelated sites.
- Shipping opaque model decisions without reason codes and replay evidence.
