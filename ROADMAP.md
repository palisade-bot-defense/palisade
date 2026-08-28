# Open-source roadmap

PALISADE advances through measured gates. This roadmap prioritizes a useful,
self-hosted open-source signal-fusion and decision layer—not a promise of a
universally accurate bot detector.

## Now — prove the decision loop

- Make the local quick start reproducible, including a synthetic replay and a
  populated Operator Console without production credentials or private data.
- Run one representative shadow deployment with route-specific endpoint
  classes, measured coverage and uniquely linked delayed outcomes.
- Diagnose and remove collection artifacts before tuning detector thresholds.
- Normalize strong deployment-owned edge evidence, including protocol/TLS
  fingerprints, address provenance and reputation, behind explicit trust
  boundaries; raw vendor payloads stay outside the public decision API.
- Publish aggregate latency, coverage, unknown-label and challenge-outcome
  results together with their limitations.
- Expand poisoning, proxy-misconfiguration, missing-signal, accessibility and
  privacy regression tests.

Exit gate: no raw personal data in repository or CI; p95 added in-process
decision latency below 10 ms; representative confirmed-human and confirmed-abuse
outcomes linked to exact decisions; false-positive and recall estimates reported
with confidence intervals. Until then, automatic blocking remains off.

## Next — calibrate and integrate

- Calibrate automation, abuse intent and continuity separately by endpoint
  class on time-separated data and unseen attack families.
- Publish documented adapters for reverse proxies, reputation providers and
  policy-alert sources using the closed normalized signal contract.
- Publish scrubbed synthetic replay fixtures and detector evaluation templates.
- Make policies and detector bundles independently reviewable, signed and
  replaceable without making policy updates opaque.
- Exercise the full reversible progression: observe → delay → throttle →
  accessible step-up → temporary block.

Exit gate: a reviewed canary improves the chosen endpoint outcome without
exceeding its false-positive or abandonment budget, and rollback is tested.

## Later — harden proven needs

- Add shared challenge/session state only when multi-replica measurements
  justify it.
- Add WebAuthn or account re-authentication where identity assurance matters.
- Add independently maintained crawler-registry update tooling with signed,
  expiring local artifacts and fail-closed verification.
- Commission independent privacy, accessibility and adversarial reviews.
- Grow community integrations under the existing AGPL-3.0-only core and
  Apache-2.0 sensor license boundary.

## Not planned for now

- Hosted SaaS, managed operations, billing, enterprise product tiers or sales
  funnels.
- A central telemetry cloud or cross-site identity graph.
- Claims of 100% detection, a universally unsolvable challenge or a calibrated
  false-positive rate without representative labels.
- Treating automation as abuse by itself.
- Shipping opaque decisions without stable reasons and replay evidence.
