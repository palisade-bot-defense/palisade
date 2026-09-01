# Human Trust Protocol

Status: 2026-09-01. This document defines what PALISADE is: a protocol for
**proof of human presence, continuity, uniqueness and agent provenance**.
PALISADE is no longer a bot-defense product; its detector, decoy, sensor and
challenge machinery is retained as the evidence substrate of the lowest
assurance levels.

Specification status is separate from implementation status. The assertion
contract itself is implemented and frozen as
[`human-assurance-assertion-v1`](../schemas/human-assurance-assertion-v1.schema.json),
but its **supported ceiling is H1**: the reference verifier refuses to sign or
accept any higher level, because no mechanism in this repository verifies
interactive liveness, device attestation, issuer credentials or uniqueness. A
reader should assume that everything above H1 is design, not capability.

## Position

PALISADE does not decide who you are. It answers narrowly scoped questions for
a relying service:

- **Presence:** is there evidence that a live person is driving this
  interaction right now?
- **Continuity:** is this the same session, device or credential holder that
  was previously trusted here?
- **Uniqueness:** within a declared scope, is this one holder rather than many
  synthetic ones?
- **Provenance:** is this an autonomous agent, an agent authorized by a person,
  or an unattributed automated client?

The relying service receives a short-lived signed proof and a bounded assurance
profile. It does not receive a biometric template, a face, a device identifier,
a PALISADE account or a cross-site identifier.

The one-sentence framing:

**PALISADE is an open verification protocol for human presence, continuity,
uniqueness and agent provenance — verifying proofs issued elsewhere, on
infrastructure the operator controls, without a PALISADE-operated trust
network.**

What that replaces: PALISADE is not a bot filter and does not treat blocking
automation as success. The three-score model survives underneath as evidence,
and the six participant classes below — people, people using AI tools,
authorized agents, organisation agents, unattributed automation, hostile
automation — are what the protocol exists to distinguish.

## Verifier, not issuer

This is the load-bearing architectural decision, and it is what keeps the
proposal inside the existing product contracts.

PALISADE **verifies** assertions. It does not enrol people, does not capture or
store biometrics, does not run an identity registry and does not operate a
credential authority. Issuers are pluggable, operator-selected and external:
an EUDI-wallet-based issuer, a national eID scheme, an enterprise workforce
IdP, a platform's own enrolment service or a device platform's attestation
authority.

PALISADE ships:

- the verification contract (what an acceptable assertion must contain);
- the signed local trust-list format for accepted issuer keys and revocation
  state, reusing the mechanism already proven by the signed crawler registry
  and signed local runtime configuration;
- conformance fixtures so an issuer or adapter can be certified offline, in the
  same way adapters are certified today without production traffic;
- the policy surface that turns an assertion into an enforcement decision.

Consequences that follow directly:

- there is no "PALISADE Trust Network" and no PALISADE-operated issuer; that
  would contradict the sovereignty contract and the v1.0 requirement of no
  dependency on private PALISADE-operated services;
- an operator with no issuer still gets H0–H2, because those levels use only
  signals PALISADE already accepts;
- trusting an issuer is an explicit, reviewable operator decision with a
  documented blast radius, not a PALISADE default.

## Egress and persistence discipline

Every layer below states its delta against
[`RUNTIME_EGRESS.md`](RUNTIME_EGRESS.md) and
[`DATA_MAP.md`](DATA_MAP.md). Those documents are backed by source regression
tests, so a layer that silently needs an issuer call, an online revocation
lookup or a uniqueness registry would break the build rather than the prose.

The rule for this protocol: **no new outbound network callsite in the request
path.** Issuer keys, trust lists, revocation state and scope parameters arrive
as signed, expiring local artifacts distributed by the deployment, exactly as
the crawler registry does. Verification is local, offline and deterministic;
an expired artifact degrades to `unknown`, never to `trusted`.

| Layer | Request-path egress delta | Persisted-class delta |
|---|---|---|
| Behavioural evidence | none | none; reuses bounded event/session windows |
| Native liveness challenge | none | none beyond the existing bounded capability store |
| Device attestation (WebAuthn/platform) | none; assertion arrives in the request | none; verification result is transient evidence |
| Issuer-signed human credential | none; offline-distributed signed trust list | trust-list file only, no subject data |
| Scope-bound pseudonym | none | none in the reference design; see Uniqueness |
| Agent provenance | none; signed local agent registry | registry file only |

Any future layer that cannot meet this rule must be marked verification-only or
offline, or must not ship.

## Assurance levels

Human assurance is a **fourth derived view** over the existing three scores plus
verified assertions. It does not replace automation risk, abuse intent or
account continuity, and it must not collapse them: the evidence contract and
its regression tests depend on those dimensions staying separate and separately
explainable.

| Level | Evidence required | Typical use | Status |
|---|---|---|---|
| H0 | none; unattributed traffic | anonymous reads | available |
| H1 | verified bounded interaction evidence and low automation risk | commenting, low-value writes | implemented: the assertion contract exists and this is its ceiling |
| H2 | H1 plus a completed session/action/endpoint-bound **interactive** challenge | account creation, rate-limited signup | mechanism implemented; the level is computed but withheld until measured |
| H3 | H2 plus a device-attested key bound to the session | marketplace actions, messaging identity | not implemented |
| H4 | H3 plus an issuer assertion of verified liveness at enrolment | high-value transactions, bank-detail changes | not implemented; requires an external issuer |
| H5 | H4 plus an issuer assertion of scope uniqueness | governance, one-person-one-vote surfaces | not implemented; requires an external issuer with a dedupe guarantee |

`internal/liveness` implements the interactive challenge. Several rounds must
be answered, each prompt is revealed only at its own moment, and each response
must arrive inside a narrow window. That cannot be precomputed, batched or
answered ahead of time, and a relay pays the round trip on every round rather
than once. A wrong answer ends the attempt rather than costing one of several
tries, so a client cannot search the option space. The attestation is bound to
one session, action and endpoint class, expires in two minutes, and the attempt
is consumed on completion.

What that does **not** establish is that the client is human: browser
automation can drive a real browser in real time. The mechanism is an
attacker-cost and throughput argument, not a proof, and the response floor is
set generously because excluding a fast assistive-technology user is a worse
failure than admitting a fast script.

The mechanism is reachable: `POST /v1/assurance/liveness` opens an attempt and
`/answer` walks its rounds, both on the assurance contract rather than the
frozen challenge contract. A completed attempt yields an attestation the client
presents to `/v1/assurance`, where it is checked against that request's session,
action and endpoint class. Any failed round reports only that the attempt ended:
distinguishing a wrong answer from one that was too fast or too late would tell
an attacker which constraint to tune.

The level it supports is therefore computed but not granted. `Derive` reaches
H2 and the ceiling clamps it back to H1, adding the reason code
`level_withheld_pending_measurement` and dropping the evidence class the
withheld level would have cited. An assertion must not name evidence for a
level it does not claim. Raising the ceiling is the measurement deliverable's
gate, not a constant change: gating a surface on an unmeasured level would harm
people before anyone knows how often it does.

The H2 distinction is easy to misread and matters. The existing challenge
lifecycle already provides one-time, session/action/endpoint-bound redemption
hardened against replay and relay — that is the *binding* mechanism. What it
does not provide is *liveness*: the current challenge is proof of work, and
browser automation may complete it routinely. H2 therefore needs a new
interactive challenge type, not a new assertion field, and the reference
implementation refuses to sign or accept any level above H1 until one exists.

Two claims deliberately absent from that table:

- **Absence of bot evidence is never human evidence.** A browser-like,
  residential or low-risk class does not raise assurance, and completing a
  proof-of-work challenge is an outcome rather than proof of humanity. This
  restates an existing project invariant; the assurance ladder must not become
  a route around it.
- **No level claims an unsolvable challenge.** Every level is an attacker-cost
  statement with a measurable false-positive budget, not a separation
  guarantee.

## Layers

### 1. Behavioural evidence — H1

The existing detector, event and decoy machinery supplies this layer unchanged:
bucketed interaction timing, navigation shape, burst structure, decoy
interaction and challenge lifecycle, verified by PALISADE against its own
bounded event store rather than trusted from the client.

Framing matters. This layer establishes *credible human presence in this
interaction*. It must not become persistent behavioural identity: no typing
biometric template, no cross-session behavioural fingerprint, no cross-site
correlation. That would create the exact profile store the project exists to
avoid, and it would be special-category processing in several deployments.

### 2. Interactive liveness — H2

The native challenge lifecycle already provides one-time, session-, action- and
endpoint-bound redemption hardened against replay and relay, with keyboard,
screen-reader, reduced-motion and non-JavaScript paths carrying equal security
accounting. The protocol addition is only that a successful redemption can be
expressed as an H2 assertion with an expiry.

Biometric liveness (face dynamics, voice, iris) is explicitly **not** a
PALISADE component. Where a deployment wants it, it belongs to an external
issuer at enrolment time and reaches PALISADE only as an H4 assertion. PALISADE
never receives the sample or the template.

### 3. Device integrity — H3

WebAuthn, passkeys, Secure Enclave, TPM and Android hardware-backed keystores
prove that a proof originated on the hardware it claims and was not copied or
replayed. Hardware alone proves nothing about humanity; combined with live
interaction evidence and a bound proof token it makes remote synthesis
substantially more expensive.

This layer is verification-only: the attestation arrives with the request, and
verification uses locally held roots.

### 4. Issuer-signed credential — H4

An external issuer asserts, for a subject it knows and PALISADE does not:

```text
human_verified   = true
liveness_at      = enrolment timestamp bucket
assurance        = 4
credential_valid = true
```

Selective disclosure or a zero-knowledge proof lets the relying service learn
only the predicate it needs (`assurance >= 3`, `not revoked`) without the name,
contact details, biometric template, device identity or issuer account. The
credential format should follow whatever the operator's issuer ecosystem
standardises on rather than a PALISADE-invented format; for EU-first
deployments the EUDI wallet ecosystem is the obvious candidate and its
selective-disclosure status should be verified against current specifications
before any implementation work.

Revocation is the hard part under the no-egress rule. The reference answer is a
signed, expiring local revocation artifact with a short validity window, so a
stale artifact fails closed to a lower assurance level instead of silently
accepting revoked credentials.

That artifact is implemented as
[`issuer-trust-list-v1`](../schemas/issuer-trust-list-v1.schema.json), verified
by `internal/issuertrust`. One signed document names which issuers a deployment
accepts, the assurance ceiling and uniqueness scope each is granted, the purpose
each was assessed for, and which credential commitments are revoked. It is
distributed as a file and verified offline: no issuer lookup, no revocation
fetch and no network call happens while a request is handled.

Four properties are worth stating because they are enforced rather than
intended. The list expires within a day at most, and an expired list degrades
every issuer to untrusted rather than staying in force. A list whose revision
does not increase is refused as a rollback, and a refused update leaves the
previous list installed. An issuer granted a ceiling above what this build can
verify is clamped down to it, so a trust list may be written for a future
release without silently granting assurance nothing checks. And an issuer
permitted to assert uniqueness must also be granted a level that can carry it,
so the two statements cannot contradict each other.

The list holds no subject data: a revoked credential appears only as an opaque
per-issuer commitment, which is not reversible to a person and is meaningless
outside that issuer.

### 5. Uniqueness — H5

Uniqueness is three different problems and the doc must not blur them:

| Tier | Mechanism | What it actually buys | Feasibility |
|---|---|---|---|
| Device-scoped | attested key per device | cheap Sybil resistance; one person can hold many devices | implementable |
| Issuer-scoped | issuer dedupes at enrolment and asserts one credential per person | real uniqueness *within that issuer's population*, conditional on trusting it | feasible with an external issuer |
| Global personhood | one credential per living person worldwide | not solvable by this project, and the claims policy forbids implying it | out of scope |

Scope-specific pseudonyms — deriving an unlinkable per-relying-party identifier
so the same person is `0x8F92…` at one site and `0x31DA…` at another — are a
genuine privacy improvement, but they are a property of the issuer's derivation,
not a source of uniqueness. They prevent cross-site linkage *given* a unique
credential; they do not create one.

Worth stating plainly for operators evaluating this: scope-bound response cost
plus session continuity, both shipping today, already remove a large share of
practical Sybil pressure with no new trust root and no new personal data. H5 is
for surfaces where that is genuinely insufficient.

### 6. Agent provenance

The internet PALISADE has to serve contains people, people using AI tools,
authorized autonomous agents, organisation-controlled agents, unattributed
automation and hostile automation. Blocking everything non-human is the wrong
target and would break the accessibility, indexing and integration cases the
three-score design was built to protect.

The existing crawler-identity model already does the right thing for one class
of agents: verified for a narrow declared purpose, or unknown, with identity
separated from authorization and a signed local registry instead of a vendor
lookup. Agent provenance generalises it, so that an agent can present
`authorized by an H3 holder for purpose P, scope S, expiring at T` and be
policed on purpose and behaviour rather than on being non-human.

The same guardrail carries over: a declared agent identity that trips intent,
decoy or policy signals is still challenged or blocked. Identity is not
authorization.

## Policy surface

Assurance enters CEL policy as an additional input alongside the three scores
and closed contextual fields, so operators keep the ordered, deterministic,
versioned rule model:

```text
human_assurance          in {0,1,2,3,4,5}
human_assurance_source   in {behavioural, challenge, device, issuer}
human_unique_scope       in {none, device, issuer}
agent_provenance         in {none, declared, authorized, verified_purpose}
```

A relying service asks for a minimum, and PALISADE returns a decision with the
usual stable reason codes, policy and model versions and expiry. Insufficient
assurance is an ordinary progressive action — observe, delay, challenge — not
an automatic block, and the response must say which level was missing.

## Amendments to the stated non-goals

The roadmap currently lists as non-goals a mandatory central telemetry cloud or
cross-site identity graph, and treating a browser-like fingerprint as proof of
humanity. This proposal keeps both, with one clarification each.

1. **No cross-site identity graph — unchanged.** PALISADE never builds one, and
   the scope-pseudonym design exists precisely so that an issuer cannot become
   one either. A deployment that accepts a cross-site-linkable credential has
   made that choice at the issuer, and the sovereignty report should say so.
2. **A fingerprint is still never proof of humanity — unchanged.** Assurance
   above H1 requires positive, verified, freshly bound evidence. No passive
   class ever raises it.
3. **Verification is added; issuance is not.** The non-goal list gains an
   explicit entry: PALISADE does not operate an identity, biometric or
   personhood registry, and does not ship a PALISADE-issued human credential.

## Legal and ethical assessment items

These are deployment-assessment items for the operator's existing register, not
legal conclusions, and none of them is discharged by self-hosting:

- biometric processing for the purpose of uniquely identifying a person is
  special-category processing under GDPR Article 9 and needs its own legal
  basis; an Article 35 DPIA is the expected starting point;
- whether EU AI Act provisions on biometric identification or emotion
  inference apply to a chosen issuer's liveness method must be assessed for
  that method, not assumed from PALISADE's own architecture;
- eIDAS 2.0 and EUDI wallet selective-disclosure capabilities should be
  verified against current published specifications before being relied on;
- exclusion risk is a first-class budget: any surface gated above H2 must have
  a documented alternative path, and abandonment at each level belongs in the
  north-star scorecard next to the confirmed-human false-positive interval;
- a uniqueness requirement is a censorship and deanonymisation surface. Gating
  ordinary speech on H5 should be treated as a serious operator decision with
  its own review, not as a stronger default.

## Mapping to existing components

| Protocol element | Existing component |
|---|---|
| short-lived, replay-protected proof | `internal/token` |
| continuity across sessions | `internal/sessioncookie` |
| one-time, action-bound liveness redemption | `internal/challenge` |
| behavioural and decoy evidence | `internal/detector`, `internal/events`, `internal/decoy` |
| issuer keys, trust lists, revocation, scope parameters | `internal/issuertrust`, on the `internal/localartifact` signed-expiring pattern |
| assurance-aware enforcement | `internal/policy` CEL |
| verified-for-a-purpose agent identity | signed crawler registry pattern, `pkg/palisadehttp` |
| deployment claims about issuers and scopes | `internal/sovereignty` |

The signed-local-artifact mechanism is the strongest bridge: it already
delivers keys, expiry, revocation-by-rotation and offline verification without
a control plane, which is precisely what a credential ecosystem normally uses a
cloud for.

## What would have to be proven

Consistent with the project's exit-gate discipline, this proposal is not
credible until at least the following exist, and none of them do today:

- an assurance assertion format with a JSON Schema, conformance fixtures and a
  deterministic offline verifier;
- a measured false-positive and abandonment interval per assurance level on a
  confirmed-human cohort, by endpoint class;
- a red-team result for proof relay, credential replay, issuer-key compromise
  and stale-revocation windows at each level;
- at least one independently implemented issuer adapter passing the same
  privacy, failure-policy and decision-contract suite required of transport
  adapters;
- an accessibility review of every path gated above H1, including the
  alternative path.

Until then the honest claim is narrow: PALISADE has the evidence, challenge,
proof-token, signed-artifact and policy primitives that such a protocol needs,
and a documented boundary describing what it will and will not become.
