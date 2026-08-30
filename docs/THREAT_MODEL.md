# Threat model

Contract version: `palisade.threat-model.v1`.

Status: frozen v1 compatibility baseline. This document has not received the
independent application-security, privacy or accessibility review required by
the v0.9 roadmap. Freezing prevents silent semantic drift; it does not turn the
project's own threat model into independent assurance.

## Security objective

PALISADE preserves three invariants under adversarial input:

1. untrusted or incomplete evidence cannot silently become trusted identity or
   confirmed-human evidence;
2. risky response requires a measured, scoped, signed and unexpired rollout;
3. every accepted input, state store and offline job remains closed and bounded.

The system raises attacker cost and explains a local decision. It does not prove
humanity, identify every automated browser or replace an origin rate limiter and
DDoS boundary.

## Assets and trust boundaries

| Asset | Trusted boundary | Untrusted or partially trusted input |
|---|---|---|
| Decision integrity | Compiled detector registry, three-score fusion and policy version | browser events, missing sensors, automation claims and weak upstream labels |
| Trusted signal boundary | Allowlisted direct peer plus fresh one-time HMAC envelope | forwarded headers, raw provider payloads and replayed envelopes |
| Challenge capability | server-issued session, action, endpoint, decision, sequence and origin-flow bindings | browser verification and redemption requests |
| Session continuity | signed first-party cookie and bounded process-local store | client-controlled cookie presence, resets and concurrent requests |
| Bounded availability | request limits, fixed stores, parser budgets, retention and explicit adapter failure mode | identifier floods, oversized batches, compressed input and unavailable dependencies |
| Rollout authority | reviewed report hash, Ed25519 plan and fixed expiry/scope/maxima | modified plans, stale canaries, widened endpoints and expired artifacts |
| Release authenticity | signed source tag, exact checksum manifest and pinned release SSH key | mirrored binaries, replaced checksum files and compromised publication accounts |
| Private evidence | operator-controlled owner-only storage outside Git | raw traffic, labels, keys and reports that must never enter project systems |

The host operating system, owner account and configured private keys are trusted.
A host-root compromise, malicious maintainer with authorized signing keys or an
attacker controlling the trusted origin adapter can violate that boundary. The
reference service cannot independently recover truth after such compromise.

## Required attacker capabilities and controls

| Category | Attacker action | Required control | Residual risk |
|---|---|---|---|
| Evasion | use a real browser, residential proxy, solved challenge or verified crawler identity | keep automation separate from intent; never treat challenge completion as humanity | weakly labelled traffic can remain unknown; efficacy needs representative outcomes |
| Poisoning | inject duplicate, unknown, malformed or signed-but-invalid fields | closed schemas, canonical envelopes, compiled rules, conservative merge and hard bounds | compromise of the trusted signing key remains a trusted-boundary failure |
| Proof relay | move a proof or redemption to another request/session/origin | one-time nonce plus session/action/endpoint/decision/sequence/origin-flow binding | process restart invalidates valid pending challenges; multi-replica state is unsupported |
| Session reset | clear or rotate the first-party session reference | isolate the new bounded session; do not inherit benign state or call it human | anonymous continuity is resettable and must never be the sole abuse control |
| Resource exhaustion | flood sessions, nonces, evidence, reports or local imports | fixed capacities, TTL eviction, byte/item budgets and explicit fail policy | upstream volumetric protection is still required before PALISADE |
| Rollout compromise | alter, replay, widen or retain enforcement approval | signed exact report/scope, fixed maxima, expiry, canary evidence and rollback | authorized key theft requires revocation and a new release/rollout identity |

## Logging and privacy abuse cases

- Error output must not contain request URLs, bodies, cookies, tokens, IP
  addresses, raw provider payloads or private decision identifiers.
- Synthetic red-team fixtures may contain reserved example values only. They are
  never derived from an operator log.
- Aggregate reports can still reveal security posture and remain private by
  default even when they contain no row-level identifiers.
- Encrypted append-only files detect modification and internal gaps; they cannot
  prove that an attacker with filesystem authority did not delete, truncate or
  roll back a complete file.

## Explicitly out of scope

- universal bot/human classification or a zero-false-positive claim;
- defense against host-root, malicious authorized signer or origin compromise;
- global volumetric DDoS absorption;
- cross-site fingerprinting or identity graphs;
- automatic legal-compliance certification;
- destructive scanning of public or third-party targets.

The executable baseline and reporting rules are documented in
[RED_TEAM.md](RED_TEAM.md). Deployment-specific risks belong in an
operator-controlled assessment and must not be uploaded with raw evidence.
