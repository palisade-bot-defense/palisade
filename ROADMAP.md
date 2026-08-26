# Roadmap

PALISADE advances through measured gates, not a promise of a universally unsolvable puzzle.

## 0. Runnable foundation — complete

- Go decision hot path, bounded sessions and replay-safe proofs.
- Typed detectors, three-score fusion, CEL policy and stable reasons.
- Privacy-limited TypeScript sensor and embedded light dashboard.
- Deterministic replay, container build and local security scans.

## 1. Strain DB shadow pilot

- Define sanitized adapters for Anubis, Cannai Shield and CrowdSec.
- Import historical samples into a versioned, access-controlled replay dataset.
- Establish endpoint classes, outcome labels and verified-bot allowlists.
- Run parallel shadow decisions without changing live responses.
- Publish an internal baseline report by endpoint and attacker cohort.

Exit gate: no raw personal data in training/replay artifacts; p95 added decision latency below 10 ms in-process; false-positive estimates and unknown-label rate reported with confidence intervals.

## 2. Detector and calibration layer

- Add protocol/TLS normalization at the trusted proxy boundary.
- Add burst, navigation-graph, token-replay and decoy interaction detectors.
- Calibrate automation, intent and continuity separately by endpoint class.
- Add signed model/policy bundles and offline evaluation reports.
- Test poisoning, missing-signal and forged-sensor scenarios.

Exit gate: improvements hold on a time-separated test set and unseen attack families, not only random train/test splits.

## 3. Progressive response

- Observe → delay → throttle → accessible step-up → temporary block.
- Bind challenges to short-lived server state, action, session and nonce.
- Offer WebAuthn/account re-authentication where identity assurance matters.
- Rotate decoy endpoints and challenge families without relying on secrecy alone.
- Measure completion and abandonment by browser/accessibility cohort.

Exit gate: documented rollback, support path and canary results; automatic blocking remains off until approved per endpoint.

## 4. Community hardening

- Finalize PolyForm Shield core license, Apache integration SDK license and CLA.
- Publish scrubbed replay fixtures and detector evaluation templates.
- Add reverse-proxy adapters and production shared state where measurements justify it.
- Commission independent privacy, accessibility and adversarial reviews.

## Non-goals

- Claiming 100% detection or a challenge no adversary can ever solve.
- Treating automation as abuse by itself.
- Fingerprinting people across unrelated sites.
- Shipping opaque model decisions without reason codes and replay evidence.
