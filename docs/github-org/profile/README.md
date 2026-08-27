<p align="center">
  <a href="https://github.com/palisade-bot-defense/palisade">
    <img src="https://raw.githubusercontent.com/palisade-bot-defense/palisade/main/brand/logo/palisade-horizontal.svg" width="420" alt="PALISADE">
  </a>
</p>

<p align="center">
  <strong>Adaptive bot defense, built together.</strong><br>
  Explainable decisions, privacy-limited signals, and measurable rollout gates.
</p>

PALISADE is an early defensive-security project for separating three questions that bot controls often collapse into one:

- **Automation risk** — how likely is the client automated?
- **Abuse intent** — how likely is the current action harmful?
- **Account continuity** — how consistent is the session with its established behavior?

Automation alone is not abuse. PALISADE combines bounded behavioral and server-side evidence with transparent reason codes, keeps risky actions in shadow mode until measured, and treats challenges as outcomes rather than proof of humanity.

## What we are building

- A Go decision hot path with explicit `shadow` and `enforce` boundaries.
- A privacy-limited browser sensor that excludes content, keystrokes, form values, and exact pointer paths.
- Deterministic replay and offline evaluation with label provenance and confidence.
- Local encrypted shadow logging with bounded queues, rotation, retention, and aggregate verification.
- Progressive, accessible responses guided by false-positive and abandonment measurements.

## Project

| Repository | Status | Purpose |
|---|---|---|
| [`palisade`](https://github.com/palisade-bot-defense/palisade) | Early prototype · shadow first | Decision service, sensor, policy engine, replay, local evaluation, and deployment contracts |

Start with the [project overview](https://github.com/palisade-bot-defense/palisade#readme), then read the [roadmap](https://github.com/palisade-bot-defense/palisade/blob/main/ROADMAP.md), [evaluation protocol](https://github.com/palisade-bot-defense/palisade/blob/main/docs/EVALUATION.md), and [privacy boundaries](https://github.com/palisade-bot-defense/palisade/blob/main/docs/privacy/DATA_BOUNDARIES.md).

> [!IMPORTANT]
> PALISADE does not claim perfect bot detection or an unsolvable challenge. The current prototype must begin in shadow mode and has no production-supported release.

The PALISADE core is licensed under **GNU AGPL-3.0-only**. The browser sensor is licensed separately under **Apache-2.0**. The repository's licensing map defines the exact scope; software licenses do not grant trademark rights.

## Participate safely

Design discussion and defensive research are welcome through the repository's issue templates. Substantive external code contributions remain paused until the separate contributor agreement is active. Never attach production traffic, personal data, credentials, or bypass details for real installations to a public issue.

Report vulnerabilities privately through [GitHub Security Advisories](https://github.com/palisade-bot-defense/palisade/security/advisories/new). See the full [security policy](https://github.com/palisade-bot-defense/palisade/security/policy) and [contribution status](https://github.com/palisade-bot-defense/palisade/blob/main/CONTRIBUTING.md).
