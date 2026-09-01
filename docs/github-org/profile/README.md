<p align="center">
  <a href="https://github.com/palisade-human-trust/palisade">
    <img src="https://raw.githubusercontent.com/palisade-human-trust/palisade/main/brand/logo/palisade-horizontal.svg" width="420" alt="PALISADE">
  </a>
</p>

<p align="center">
  <strong>Proof that a human is on the other end—run, inspected and proven by you.</strong><br>
  Verify presence, continuity and provenance. Never issue an identity.
</p>

PALISADE is an open-source proof-of-human protocol for operators that need to
know whether a verified person—or an agent authorized by one—is on the other end
of a call, message or transaction, without routing traffic or identity through a
mandatory vendor cloud. It can run on-premises or in an operator-selected EU
region with no PALISADE account, central telemetry service or cross-site
identity graph.

PALISADE **verifies** assertions and never issues them. It operates no identity,
biometric or personhood registry; credential issuers are external, pluggable and
selected by the operator. Only the two lowest assurance levels exist today.

## Why PALISADE

PALISADE binds three verifiable contracts into one local control loop:
**sovereignty** without mandatory vendor egress, **evidence** with stable reasons
and replay, and **rollout** that is measured, signed and reversible.

- **Self-hosted by design:** processing location, keys, retention and policies
  remain under operator control.
- **No mandatory third-country transfer:** a fully EU-hosted deployment with no
  external providers does not require a PALISADE-operated data transfer.
- **Data-minimized inputs:** raw addresses, protocol fingerprints, URLs, user
  agents and vendor payloads stay at the trusted deployment boundary.
- **Content-free browser sensor:** no form values, keystrokes, DOM text or exact
  pointer coordinates.
- **Local learning loop:** encrypted shadow logs, historical imports,
  evaluation and rollout decisions remain local; production data never belongs
  in the public repository.
- **Auditable decisions:** stable reason codes and versioned policies replace an
  opaque remote bot score or an unexplained trust badge.
- **Verifier, never issuer:** no PALISADE identity, biometric capture or
  personhood registry, and no claim of global proof of personhood.
- **Machine-readable posture:** the [Sovereignty Report](https://github.com/palisade-human-trust/palisade/blob/main/docs/SOVEREIGNTY.md), [egress inventory](https://github.com/palisade-human-trust/palisade/blob/main/manifests/runtime-egress-v1.json) and [data map](https://github.com/palisade-human-trust/palisade/blob/main/manifests/data-map-v6.json) separate product invariants from operator-declared deployment facts.
- **Bring data without giving it away:** the [generic local import](https://github.com/palisade-human-trust/palisade/blob/main/docs/LOCAL_IMPORT.md) accepts an operator-owned closed contract and rotates pseudonyms daily; local [sequence](https://github.com/palisade-human-trust/palisade/blob/main/docs/LOCAL_SEQUENCE_ANALYSIS.md) and [holdout](https://github.com/palisade-human-trust/palisade/blob/main/docs/LOCAL_HOLDOUT_EVALUATION.md) analysis persist only bounded aggregates.
- **Actually open source:** AGPL-3.0-only core and Apache-2.0 browser sensor.

Underneath the assurance ladder, PALISADE separates three evidence questions
that bot controls often collapse into one:

- **Automation risk** — how likely is the client automated?
- **Abuse intent** — how likely is the current action harmful?
- **Account continuity** — how consistent is the session with its established behavior?

Automation alone is not abuse, and absence of automation evidence is never proof
of humanity. Assurance above the behavioral level requires positive, freshly
bound, verified evidence. PALISADE keeps risky actions in shadow mode until
measured, and every surface gated on assurance needs a reviewed alternative
path.

> [!NOTE]
> **GDPR-aware does not mean GDPR-certified.** PALISADE provides technical
> controls, not a compliance certificate.
> Controllers and processors remain responsible for legal basis, transparency,
> data-subject rights, retention, security, provider relationships and any
> required DPIA or terminal-access assessment. Start with the
> [EU privacy deployment checklist](https://github.com/palisade-human-trust/palisade/blob/main/docs/privacy/DEPLOYMENT_CHECKLIST.md).

## What we are building

- A Go decision hot path with fail-safe shadow mode and operator-signed, expiring canary/enforcement plans.
- A privacy-limited browser sensor that excludes content, keystrokes, form values, and exact pointer paths.
- Deterministic replay and offline evaluation with label provenance and confidence.
- Local encrypted shadow logging with bounded queues, rotation, retention, and aggregate verification.
- Closed aggregate analysis, exact-canary promotion gates, origin enforcement directives, and deterministic rollback.
- Progressive, accessible responses guided by false-positive and abandonment measurements.

## Project

| Repository | Status | Purpose |
|---|---|---|
| [`palisade`](https://github.com/palisade-human-trust/palisade) | Early prototype · shadow first | Decision service, sensor, policy engine, replay, local evaluation, and deployment contracts |

Start with the [project overview](https://github.com/palisade-human-trust/palisade#readme), then read the [product differentiation](https://github.com/palisade-human-trust/palisade/blob/main/docs/DIFFERENTIATION.md), [Sovereignty Report](https://github.com/palisade-human-trust/palisade/blob/main/docs/SOVEREIGNTY.md), [roadmap](https://github.com/palisade-human-trust/palisade/blob/main/ROADMAP.md), [evaluation protocol](https://github.com/palisade-human-trust/palisade/blob/main/docs/EVALUATION.md), and [EU deployment checklist](https://github.com/palisade-human-trust/palisade/blob/main/docs/privacy/DEPLOYMENT_CHECKLIST.md).

> [!IMPORTANT]
> PALISADE does not claim proof of personhood, perfect separation of humans from automation, or an unsolvable challenge. Only the mechanisms underneath the lowest assurance levels exist; no assurance assertion is yet produced or consumed, and the only integration surface is HTTP and the web. The current prototype must begin in shadow mode and has no production-supported release.

The PALISADE core is licensed under **GNU AGPL-3.0-only**. The browser sensor is licensed separately under **Apache-2.0**. The repository's licensing map defines the exact scope; software licenses do not grant trademark rights.

## Participate safely

Design discussion, defensive research and narrowly scoped code contributions are welcome through the repository. Contributions use the license covering the affected path. Never attach production traffic, personal data, credentials, or bypass details for real installations to a public issue.

Report vulnerabilities privately through [GitHub Security Advisories](https://github.com/palisade-human-trust/palisade/security/advisories/new). See the full [security policy](https://github.com/palisade-human-trust/palisade/security/policy) and [contribution status](https://github.com/palisade-human-trust/palisade/blob/main/CONTRIBUTING.md).
