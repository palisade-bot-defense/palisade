# Product differentiation

Status: 2026-08-29. This is a product strategy, not a claim that competitors
lack privacy controls or that PALISADE already matches their detection efficacy.
Vendor capabilities and packaging can change; links point to first-party
material used for this review.

## Position in one sentence

**PALISADE is open-source bot defense that can show where evidence stayed, why
it acted and how enforcement was promoted—without requiring traffic telemetry
to be sent to a vendor cloud.**

The differentiation is the combination of three verifiable contracts:

- **sovereignty:** operator-selected infrastructure, keys, retention and
  providers with no mandatory PALISADE control plane or telemetry export;
- **evidence:** closed normalized inputs, three separate risk dimensions, stable
  reasons and deterministic replay;
- **rollout:** local outcome measurement followed by scoped, signed, expiring
  and reversible enforcement.

Self-hosting alone is not unique. Explainable scores alone are not unique.
Behavioral detection, proof of work and honeypots are not unique. The intended
gap is an independently operable and inspectable control loop that binds these
properties together.

## Primary users

PALISADE is for teams that operate sensitive web or API surfaces and cannot
make a US-managed edge or opaque cross-customer learning system their default:

- EU public-sector, research, health, finance and regulated operators;
- hosting providers and SaaS teams offering an EU-only or on-premises path;
- open-source communities protecting content without handing traffic telemetry
  to another platform;
- security teams that already own WAF, proxy, reputation or challenge signals
  and need a local decision and evidence layer rather than another signal silo.

The first adopter is an operator willing to run shadow measurement and own
policy, not a team seeking a turnkey managed service with an efficacy guarantee.

## What established products do especially well

| Product/category | Distinct strength described by its publisher | Boundary relevant to PALISADE |
|---|---|---|
| [Cloudflare Bot Management](https://developers.cloudflare.com/bots/) | Large edge network, managed detection and global threat intelligence integrated with a broad application platform. Its [Data Localization Suite](https://developers.cloudflare.com/data-localization/) adds regional controls, with supported products and regions documented separately. | PALISADE does not try to recreate a global edge. It makes the complete reference decision/evaluation loop independently operable without a PALISADE network or localization add-on. |
| [Akamai Bot Manager](https://www.akamai.com/products/bot-manager) | Edge-scale bot scoring, behavior analysis, fingerprinting, known-bot intelligence and many response options. | PALISADE cannot match Akamai's traffic scale today. Its different asset is inspectable local evidence and operator-controlled promotion rather than proprietary global models. |
| [HUMAN Bot Defender](https://docs.humansecurity.com/applications/bd-detection-overview) | Cloud-based predictive models combine hundreds of browser, mobile and network indicators with cross-customer threat research. | PALISADE intentionally accepts a narrower closed signal vocabulary and does not require a cloud detector or cross-site profile library. |
| [DataDome](https://docs.datadome.co/docs/device-check) | Managed models and device checks collect hundreds of client signals and can choose block or additional challenge dynamically. | PALISADE's browser contract avoids content and exact interaction paths, and its operator can audit every accepted signal class. This trades some managed intelligence for minimization and control. |
| [Kasada](https://www.kasada.io/bot-defense) | Proprietary, rapidly changing invisible client challenges, proof of execution, obfuscation and server-side anomaly detection make retooling expensive. | PALISADE will not claim a permanent secret client challenge in public code. It combines transparent bounded challenges with server evidence, decoys, outcomes and progressive cost. |
| [ALTCHA](https://altcha.org/docs/how-it-works/) | A simple open-source proof-of-work CAPTCHA core; its broader adaptive risk/contextual challenge system is offered through Sentinel/Cloud products. | PALISADE treats proof of work as one outcome and cost lever inside a larger local evidence and rollout loop. |
| Local behavior and reputation engines | Detect locally and may optionally consume collaborative threat intelligence. | PALISADE consumes only closed, operator-authorized signal classes and does not require a central identity or reputation graph. |
| Self-hosted challenge gateways | Put a focused computational or interactive gate in front of selected traffic. | PALISADE fuses multiple evidence dimensions, measures delayed outcomes and governs progressive rollout; an existing gateway can remain an upstream signal source. |

The correct competitive claim is therefore not “only self-hosted product” or
“only privacy-friendly product.” It is: **an open, local, data-minimized
decision-and-rollout protocol whose guarantees can be inspected and replayed.**

## Defensible open-source assets

Open source removes secrecy as a durable moat. PALISADE should build assets that
become more valuable when inspected and adopted:

1. **Sovereignty Report:** a versioned machine-readable product invariant and
   deployment-attestation format.
2. **Normalized signal protocol:** a narrow vocabulary that lets integrations
   use strong edge evidence without forwarding raw IPs, fingerprints, URLs or
   vendor payloads.
3. **Generic local import contract:** a vendor-neutral, owner-only path that
   pseudonymizes direct local references and keeps collection quality,
   automation, harmful intent, continuity, decoy and challenge evidence
   separate without a PALISADE data upload. Its paired sequence contract
   authenticates local shards, bounds active linkage and publishes only fixed,
   reviewable aggregates.
4. **Evidence ledger formats:** stable reasons, policy/model versions, replay
   records and delayed-outcome linkage with explicit uncertainty.
5. **Measured rollout artifacts:** review and rollout schemas that cryptographically
   bind action, endpoint, cohort, expiry, evidence thresholds and rollback.
6. **Humane challenge protocol:** one-time action/session/origin-flow binding, accessibility
   accounting and progressive cost rather than a single visual puzzle.
7. **Evaluation method:** chronological holdouts, unknown-label accounting,
   confidence intervals and poisoning/misconfiguration test fixtures. The
   reference evaluator requires a predeclared time boundary, excludes crossing
   windows and can isolate operator-annotated families never seen in baseline
   without publishing their names.
8. **Adapter conformance:** privacy and failure-policy tests that make PALISADE a
   stable interoperability boundary for proxies and local security tools.
9. **Community trust and brand:** transparent limitations, private vulnerability
   handling and a clear trademark policy around the PALISADE name.

Private operator datasets, keys and tuning remain with each operator. They are
not the community project's moat and must never become a hidden central data
exchange. Specialist counsel should review trademark registration, defensive
publication and contributor/licensing processes before legal claims are made.

## Product principles

- **Behavior changes risk; it does not prove identity.** Minute-scale sequences,
  decoy interaction and challenge history can raise or lower confidence, but a
  person can behave mechanically and a bot can imitate human motion.
- **Automation is not abuse.** Search crawlers, monitoring, accessibility tools
  and user scripts need endpoint-aware policy.
- **Uncertainty is an output.** Missing sensors remain neutral; weak labels and
  incomplete coverage stay visible.
- **Friction is a budget.** Delay, throttle, challenge, fallback and abandonment
  are measured harms, not free security wins.
- **Local learning is operator-owned.** PALISADE ships methods and tools; it does
  not require production records to improve the public project.
- **Security is layered.** A challenge increases attacker cost but cannot provide
  permanent or universal human proof.

## Claims policy

PALISADE may claim capabilities that exist in a tagged release and can be
reproduced, such as no mandatory vendor service, closed API inputs, local
encrypted evaluation, versioned reasons and signed rollout artifacts.

PALISADE must not claim “100% bot detection,” “bots cannot solve this,” “zero
false positives,” “GDPR certified,” “anonymous” for merely pseudonymized data,
or superiority based on an unrepresentative private dataset. Comparative
performance claims require a documented protocol, chronological holdout and
published limitations.

## Immediate product message

Short: **Bot defense you can run, inspect and prove.**

Expanded: **Keep traffic evidence on infrastructure you choose. PALISADE fuses
bounded signals into explainable decisions, measures outcomes locally and lets
risky enforcement advance only through signed, reversible rollout.**
