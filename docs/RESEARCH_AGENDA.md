# Research agenda: proof of human presence

Status: 2026-09-02. A working document of theses, research questions and
proposed concepts for the human trust protocol. Everything here is either
grounded in a cited source, grounded in a tension this repository actually hit
while implementing the assurance ladder, or explicitly marked as a proposal. It
is not a survey and makes no claim to completeness.

## 0. The central research question

The goal of the software is to rebuild a trust layer for the internet: to know
that a verified human is on the other end of a call, a message or a transaction.
As a research question that sentence is too loose to answer, because "verified
human on the other end" bundles three different claims and names three surfaces.
Made precise:

> **Under what conditions can a relying party obtain verifiable evidence that a
> live, present person is on the other end of a call, a message or a
> transaction — at a stated and measured level of confidence — without learning
> who that person is, without excluding people who interact differently, and
> without any party acquiring the power to decide who counts as a person?**

Every clause is load-bearing.

- **Verifiable evidence, not a verdict.** The answer is an assertion a relying
  party can check, with reason codes, not a boolean somebody else decided.
- **Live and present** is one claim (liveness, H2). **The same one as before**
  is a second (continuity). **One, not many** is a third (uniqueness, H5). They
  are answered by different mechanisms, fail differently, and must be measured
  separately. Collapsing them is how "verified human" becomes a badge.
- **A stated and measured level.** A level without a confirmed-human
  false-positive and abandonment interval is a promise. This repository
  computes H2 and H3 and withholds them until that interval exists.
- **Without learning who.** No subject identity, no biometric material, no
  device identifier, no cross-site identifier; commitments derived per
  audience.
- **Without excluding.** A control that excludes people does not remove them;
  it routes them through the relay paths it was meant to close.
- **Without concentrating power.** The verifier never issues. Whoever can say
  who counts as a person can also say who does not.
- **Call, message, transaction — all three.** The goal is all three surfaces,
  and they are not three adapters for one problem. They differ in who the
  relying party is, when verification happens relative to the interaction, what
  the assertion binds to, and what freshness means. Section 0.1 sets that out.
  The transaction and message surfaces exist; the call surface does not yet.

The theses, questions and concepts below are decompositions of this question.
Every one of them should be traceable back to a clause of it.

### 0.1 Three surfaces, three problems

| | Transaction | Message | Call |
|---|---|---|---|
| **Relying party** | a service | a recipient — usually a person's client | the other participant — a person's client |
| **When verified** | before the action, one shot | at send; verified at read, possibly hours later | continuously, for the duration |
| **What the assertion binds to** | session, action, endpoint class, audience | a content commitment and the recipient scope | a channel identifier and a time window, re-attested |
| **Freshness** | a minute | validity and freshness diverge: verifiable for days, freshness is evidence age *at send* | continuous; presence must be re-established, not assumed |
| **Primary threat** | scripted automation, relay | spam at scale, impersonation, forwarded assertions | voice and video cloning, relay of a real person |
| **What PALISADE verifies** | interaction evidence, liveness, device | the same, minted at send, bound to content | device-bound continuity plus periodic liveness — never the media |
| **Status** | HTTP surface exists | content surface exists; client verifier checks the commitment | no adapter |

Three consequences follow.

First, for messages and calls the relying party is a *person's client*, not a
server. The verifier has to run there. `pkg/palisadeassurance` is Go; a
verifier for the client side is a deliverable, not an afterthought.

Second, messaging is increasingly end-to-end encrypted, so the verifier cannot
see content. The sender must commit to the content and the assertion is minted
over that commitment; PALISADE never sees plaintext. A forwarded assertion then
fails, because the binding is to the message that was sent, not to the person
who sent it — which is the point.

Third, on a call, the threat is the media, and PALISADE verifies no media
(T10). "Verified human on a call" therefore means "a present person holding a
registered device stayed attached to this channel and re-attested throughout".
It does not mean "this voice is real". That is a narrower claim than the slogan
suggests and it must be stated as such, because a system that implies it can
detect a cloned voice will be trusted for exactly the thing it cannot do.

## 1. What the sources establish

- **Personhood credentials** (Adler et al., 2024, arXiv:2408.07892) propose
  credentials that let a person prove they are real "without disclosing any
  personal information", built on unlinkable pseudonymity. The paper names
  issuer power, equitable access, coercion and centralization as open problems
  rather than solved ones.
- **Privacy Pass** (IETF; RFC 9576 architecture) separates the party that
  observes a property (attester), the party that issues a token (issuer) and
  the party that consumes it (origin), with the guarantee that an issuer cannot
  link a redeemed token to its issuance better than chance. The working group
  itself flags issuer centralization as unresolved.
- **WebAuthn Level 3** states that an assertion proves the user "controls the
  credential private key", scopes credentials per relying party so that relying
  parties "are not able to detect any properties, or even the existence, of
  credentials scoped to other Relying Parties", and makes attestation optional
  with an explicit `none` format.
- **EU AI Act Article 5** prohibits real-time remote biometric *identification*
  in public spaces for law enforcement and emotion inference in workplaces and
  education. Verifying liveness or presence without identifying anyone is not
  what the article targets, but any biometric method used at enrolment still
  falls under GDPR Article 9 as special-category processing.
- **The EUDI wallet** Architecture and Reference Framework reached v3.0.0 on
  21 July 2026 under Regulation (EU) 910/2014. It is the obvious external issuer
  for an EU-first deployment; its concrete unlinkability guarantees under
  repeated presentation must be verified against that version before any H4
  design relies on them.
- **World ID** documents uniqueness via Orb verification with zero-knowledge
  proofs and nullifiers that are "unlinkable across apps". Its documentation
  contains no discussion of the regulatory actions and critiques that exist
  elsewhere; a research agenda must treat vendor claims and independent
  evaluation as separate inputs.
- **The W3C note on the inaccessibility of CAPTCHA** is being revised as a
  working draft, which is itself evidence: the accessibility problem of
  human-verification is not settled and the standard answers are being
  re-examined.

## 2. Theses

Each thesis states what would falsify it.

**T1 — Every mechanism is a cost function, never a separator.** No challenge,
credential or behavioural model separates people from automation; each raises
the cost of one forgery and lowers the throughput of many. Assurance must
therefore be *reported as measured cost*, not as truth. Falsified by: a
mechanism with a demonstrated zero false-negative rate against an adaptive
attacker on a representative cohort.

**T2 — Absence of automation evidence is never human evidence.** A system that
treats "nothing looked like a bot" as presence is calibrated on its own
false negatives. This repository enforces the rule in code and tests. Falsified
by: showing that a detector's false-negative rate is bounded tightly enough that
its silence carries information — which would require exactly the measurement
that does not exist.

**T3 — The verifier must never be the issuer.** Issuing identity concentrates
power; verifying does not. The personhood-credentials paper names issuer power
as an open problem, and Privacy Pass names issuer centralization as one. A
sovereignty-preserving protocol can only ever verify. Falsified by: a credible
issuer design whose power is bounded by construction rather than by policy.

**T4 — Uniqueness is issuer-scoped or it does not exist.** "One credential per
living person worldwide" is an issuer with global reach, which is a single point
of control. Uniqueness within one issuer's population is real; global
personhood is a governance claim wearing a cryptographic costume. Falsified by:
a global-uniqueness scheme with no party able to deny or duplicate enrolment.

**T5 — Cross-service unlinkability is necessary and insufficient.** Deriving a
commitment per audience (as this repository does) stops two relying services
from linking a visitor. It does nothing about the operator, who sees both mint
and redemption. Falsified by: showing that operator-side linkage is either
impossible in practice or harmless in every threat model that matters.

**T6 — Accessibility exclusion is a security failure, not a usability cost.**
People a control excludes do not vanish; they route around it, through shared
accounts, relatives, or paid intermediaries, which are precisely the relay
paths the control was meant to close. Falsified by: evidence that excluded users
abandon the goal rather than the control.

**T7 — For agents, the valuable proof is delegation, not personhood.** An
autonomous agent cannot and should not prove it is human. It can prove "a
verified person authorized me for this purpose until this time". The interesting
object is the authorization chain, not the endpoint. Falsified by: a deployment
in which "is this a human" turns out to be the operative question for agents
rather than "who is accountable for this agent".

**T8 — A level granted before its false-positive interval exists is a
liability transfer to end users.** This repository computes H2 and H3 and
withholds them for exactly this reason. Falsified by: an argument that an
unmeasured level harms nobody, which would need the measurement to make.

**T9 — Liveness is attachment, not humanity.** A multi-round, unpredictable,
time-bounded challenge proves that something stayed attached and reacted in
real time. Its value is cost-per-attempt and a throughput bound. Falsified by: a
liveness design whose completion is not achievable by driving a real browser in
real time.

**T10 — Biometrics belong at enrolment in an external issuer, never in the
verifier.** Architecturally, because the verifier must hold no template; legally,
because Article 9 GDPR makes biometric identification special-category
processing wherever it happens. Falsified by: a verifier-side biometric method
that provably retains nothing and is legally assessed as such.

**T11 — Data maps drift unless they are tested against code.** This repository
shipped a liveness endpoint without its data-map flow and found the gap only by
re-checking. A privacy contract that is prose is a promise; one that fails a
build is a property. Falsified by: a long-lived deployment whose prose map has
never drifted from its code.

## 3. Research questions

### Foundations

- **RQ1.** Can the assurance derivation be formalized as a constraint system in
  which each evidence class either *supports* or *contradicts* a level and never
  both, so that the result is the maximum level with no unresolved
  contradiction? What monotonicity properties follow, and can they be proved
  rather than tested?
- **RQ2.** Is a discrete ladder (H0–H5) the right projection of a continuous
  (attacker cost, abandonment, exclusion) surface, or does the ladder hide the
  trade-offs a relying service actually needs to make?
- **RQ3.** What is the correct semantics of *freshness*? Evidence has a
  half-life; a liveness completed ninety seconds ago is not the same as one
  from twenty minutes ago. Should assertions carry evidence age, and should
  relying services set freshness budgets per action class?

### Measurement

- **RQ4.** What is the smallest consented, diverse human panel — including
  assistive-technology users — that yields a usable abandonment and exclusion
  interval per mechanism *before* any production deployment? Which part of the
  interval can such a panel supply, and which part can only come from
  production?
- **RQ5.** How should withheld levels be counted? Recording "earned but
  withheld" separately from "not earned" (as `shadow-record-v4` does) is
  necessary for the measurement that decides whether to raise the ceiling. Is it
  also sufficient, or does the decision need the *reason* a level was earned?
- **RQ6.** Do confirmed-human and confirmed-abuse labels linked to exact
  decisions have enough coverage to bound a per-level false-positive rate, or
  does per-level slicing dilute the cohorts below usefulness at realistic
  volumes?

### Adversary

- **RQ7.** What is the formal model of *relay* attacks — human farms,
  AI-driven relays, remote-controlled real browsers — and which bindings
  (session, action, endpoint, origin, device) defeat which relay topologies?
  The central adversary is not "a bot" but "a real human whose presence is
  attributed to someone else's action".
- **RQ8.** For a multi-round liveness challenge, how does attacker cost scale
  with rounds, option count and window width, and where does the human
  abandonment curve cross it? The mechanism's parameters were chosen for
  accessibility; the crossing point has not been measured.
- **RQ9.** What does the automation-contradiction threshold (currently 0.60
  confidence) do to the ladder under adversarial evidence injection? Can an
  attacker *lower* a legitimate user's assurance cheaply, and is that a denial
  of service worth modelling?

### Privacy

- **RQ10.** Does splitting attester from issuer *inside one operator's
  infrastructure* (the Privacy Pass split model) buy anything against a
  compromised operator, or only against a curious one? What would a
  blind-minted assurance token look like, and what does it cost in latency?
- **RQ11.** Under the EUDI ARF v3.0.0, what unlinkability actually survives
  repeated presentation of the same credential to the same relying party, and
  to different ones? This must be read from the specification, not assumed.
- **RQ12.** Selective disclosure reveals a predicate; a predicate over time
  reveals a profile. Which predicates, presented how often, become identifying,
  and can a relying service be prevented from asking a sequence that adds up to
  identity?

### Accessibility

- **RQ13.** Can a non-interactive alternative path ever reach the same attacker
  cost as an interactive one, and if not, what is the honest way to grant it the
  same level? An alternative path with weaker security accounting is a
  documented bypass.
- **RQ14.** What reaction floor excludes whom? The current 120 ms floor is a
  guess made in the direction of inclusion. Which assistive technologies and
  which practised users are faster, and is any floor defensible at all?

### Agents

- **RQ15.** What is the minimal delegation credential that lets an agent prove
  "authorized by a verified person for purpose P in scope S until T" without
  revealing the person, and how is revocation delivered offline in the same
  signed-artifact shape as the issuer trust list?
- **RQ16.** When an agent acts, who is accountable — and is that the same
  question as who authorized it? Does the protocol need an accountability chain
  distinct from the authorization chain?

### Surfaces

- **RQ19 (message).** How does an assertion travel with an end-to-end encrypted
  message when the verifier cannot see content? The sender computes a content
  commitment; the assertion is minted over that commitment and the recipient
  scope; the recipient verifies. What commitment scheme keeps the assertion
  unforgeable without leaking anything about the content to PALISADE?
- **RQ20 (message).** What does freshness mean when verification happens hours
  after minting? The assertion needs two clocks — validity, and evidence age at
  the moment of sending — and a recipient needs to see both.
- **RQ21 (call).** What is *continuous* presence? An initial liveness challenge
  plus periodic re-attestation gives a cadence; what cadence is enough, and can
  re-attestation be passive (device signature over channel and interval) so a
  call is not interrupted every thirty seconds?
- **RQ22 (call).** If the voice can be cloned but the device and liveness check
  out, what has actually been verified? Precisely: that a present person holding
  a registered device is attached to the channel. Is that claim useful to the
  other participant, and how must the client phrase it so it is not read as
  "this voice is real"?
- **RQ23 (all three).** Is one assertion contract with three binding profiles
  enough, or do the surfaces need three contracts? The `binding` object already
  exists; the question is whether request-bound, content-bound and
  channel-bound bindings are variants or different things.

### Governance

- **RQ17.** Trusting an issuer is a bounded-blast-radius decision only if the
  blast radius is actually bounded. What does a trust list need to express so
  that revoking one issuer, or one purpose, is a local operation with no
  collateral loss of assurance?
- **RQ18.** A uniqueness requirement is a censorship and deanonymisation
  surface. Which surfaces, if any, justify it, and can the protocol make gating
  ordinary speech on H5 structurally awkward rather than merely discouraged?

## 4. Proposed concepts

These are proposals, not findings. Each names the tension it responds to.

**C1 — Cost curves instead of levels.** Publish, per mechanism and endpoint
class, the measured triple (attacker cost per successful forgery, human
abandonment rate, exclusion rate). Treat the H0–H5 ladder as a projection of
that surface for convenience, and let a relying service choose a point on the
curve rather than a rung. Responds to T1 and RQ2.

**C2 — Freshness as a first-class dimension.** Give every evidence class a
half-life and carry `evidence_age` in the assertion. A relying service sets a
freshness budget per action: a comment tolerates stale evidence, a bank-detail
change does not. Today TTLs are binary; this makes decay continuous and
inspectable. Responds to RQ3.

**C3 — Provenance chains for agents.** An agent presents a chain whose root is
a person's assurance assertion and whose links are signed delegations, each
narrowing purpose, scope and expiry. PALISADE verifies the chain and never
learns the person. No new cryptography: nested signed assertions and the
existing offline revocation artifact. The `authorized` provenance value,
currently unreachable, becomes reachable through exactly this. Responds to T7,
RQ15 and RQ16.

**C4 — Contradiction-first derivation.** Formalize the derivation so that each
evidence class may only support or only contradict, never both; the result is
the highest level with no unresolved contradiction. The current implementation
already behaves this way; making it a stated model allows monotonicity to be
proved and lets an operator reason about what a new evidence class *cannot* do.
Responds to RQ1 and RQ9.

**C5 — Withheld state as signal.** Emitting `level_withheld_pending_measurement`
turns a safety gate into information: a relying service learns that evidence,
not policy, is the binding constraint. Proposal: study whether exposing withheld
state changes relying-service adoption or attacker targeting, and whether the
signal should be coarser. Responds to T8 and RQ5.

**C6 — Equal-accounting alternative paths.** Every mechanism ships with an
alternative path that grants the same level under its own measured cost. If the
alternative cannot reach the same cost, the level is granted anyway and the gap
is published as an exclusion budget the deployment accepted, rather than hidden
as a bypass. Responds to T6 and RQ13.

**C7 — Rate-limited nullifiers for abuse without identity.** For the surfaces
where uniqueness is genuinely needed, prefer "at most k actions per epoch per
holder" over "one person one vote". Rate-limiting nullifiers give a Sybil bound
without ever naming the holder and without a global registry, and they fit the
issuer-scoped uniqueness the trust list already expresses. Responds to T4 and
RQ18.

**C8 — Consented calibration panels.** Unblock the abandonment and exclusion
half of the per-level interval before production by running a small, consented,
diverse panel through each mechanism. State plainly which half of the interval
this supplies and which half still requires a deployment. Responds to RQ4.

**C9 — Blind-minted assertions.** Restructure minting so that the process that
observes behaviour and the process that signs the assertion cannot link the two
even inside one operator, using the Privacy Pass split. This is the only
proposal that changes the trust boundary of PALISADE itself, and it is listed
because T5 says the current boundary is insufficient. Responds to T5 and RQ10.

**C10 — Relay as the primary adversary.** Reframe the threat model around
attribution rather than automation: the question is not "is this a bot" but
"is the present human the one this action belongs to". Session, action,
endpoint, origin and device bindings are the defences; each should be mapped to
the relay topology it defeats. Responds to RQ7.

**C11 — Surface profiles of one assertion.** One contract, three binding
profiles: request-bound (session, action, endpoint, audience — exists),
content-bound (content commitment, recipient scope) and channel-bound (channel
identifier, interval). The assertion, its verifier and its freeze stay single;
the profile says what the signature covers. Responds to RQ23.
*Status:* implemented as `human-assurance-assertion-v2`. Both verifiers accept
the three profiles with per-profile validity bounds — five minutes for a
request, seven days for content, two minutes for a channel — and refuse a
binding that carries another profile's field. Only the request profile has a
transport; C12 and C13 are the message and call transports on top of it.

**C12 — Sender-committed assertions for encrypted messaging.** The sender
hashes the message, requests an assertion over the hash and the recipient
scope, and attaches it. PALISADE never sees plaintext. A recipient verifies
locally with a client-side verifier. Forwarding breaks the binding by design.
Responds to RQ19 and RQ20.
*Status:* implemented. `POST /v1/assurance/content` takes the same normalized
request plus the sender's commitment, evaluates evidence exactly as the request
surface does, and returns a content-profile assertion valid for a day by
default. Both verifiers expose a `matchesContent` check the recipient runs
against the message it received. The commitment is a plain SHA-256; a salted
or hiding commitment is still open if content must stay unguessable from the
commitment alone (RQ19).

**C13 — Continuous presence for calls.** Open the call with the interactive
liveness challenge, then re-attest with a low-cost device signature over the
channel identifier and the current interval, on a cadence the other
participant's client displays as "present · verified *n* seconds ago". No media
is analysed, and the client copy says exactly what was verified and what was
not. Responds to RQ21 and RQ22.

**C14 — A client-side verifier.** Messages and calls make a person's client the
relying party. A verifier that runs in a browser or a phone, with the same
conformance fixtures as the Go one, is what turns the message and call surfaces
from design into capability. Responds to the first consequence in 0.1.

## 5. What this repository can already test

- T2, T8 and C4 are enforced by tests in `internal/assurance`.
- C5's signal exists: `level_withheld_pending_measurement` is emitted.
- RQ5's precondition exists: `shadow-record-v4` records withheld state and
  `shadow-analysis-report-v5` slices by level.
- RQ7's bindings all exist: session, action, endpoint class, origin (in device
  attestation) and device.
- RQ8's parameters are constants in `internal/liveness` and can be varied
  without contract changes.
- C3 has its vocabulary reserved (`authorized`) and its revocation shape
  (`internal/issuertrust`); what is missing is the delegation credential.
- Nothing here can supply RQ4, RQ6 or the production half of any interval.
  Those need people and a deployment.
- C14 exists: `verifier/` is a client-side verifier held to the same
  conformance suite as the Go implementation plus a set of documents Go
  actually signed, so the two cannot drift by a byte. C11 to C13 — the message
  and call surfaces themselves — are not started; C14 was their prerequisite.
