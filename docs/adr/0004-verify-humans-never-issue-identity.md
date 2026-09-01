# ADR 0004: Verify human assurance, never issue identity

Status: proposed

PALISADE is a proof-of-human protocol. Its purpose is to let a relying service know that a live, continuous and — where a surface requires it — unique human, or an agent authorized by one, is on the other end of a call, message or transaction. It is no longer positioned or developed as a bot-defense product. The detector, decoy, sensor and challenge machinery is retained as the evidence substrate of the lowest assurance levels; blocking automation is a means, never the goal, and "distinguished the six classes of participant" replaces "blocked the bot" as the success criterion.

The decision is that PALISADE is a **verifier**, not an issuer. It never enrols people, captures biometrics, stores templates, operates an identity or personhood registry, or ships a PALISADE-issued human credential. Issuers are external, pluggable and operator-selected; PALISADE ships the verification contract, the signed local trust-list and revocation format, conformance fixtures and the policy surface.

Human assurance (H0–H5) is a fourth derived view over the existing automation, abuse-intent and continuity scores. It does not collapse them; ADR 0003 stands. Absence of automation evidence never raises assurance, and no level above H1 may be reached without positive, freshly bound, verified evidence.

No layer may add an outbound network callsite in the request path. Issuer keys, revocation state and scope parameters arrive as signed, expiring local artifacts verified offline, reusing the signed crawler-registry mechanism. An expired artifact degrades to `unknown`, never to `trusted`.

Consequences: H0–H2 work with no external dependency; H3 requires platform attestation; H4 and H5 require an external issuer and are unimplemented. Global proof-of-personhood is out of scope. Full rationale, layer design, legal-assessment items and exit gates are in [Human Trust Protocol](../HUMAN_TRUST_PROTOCOL.md).
