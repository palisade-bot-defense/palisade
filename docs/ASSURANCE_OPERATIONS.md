# Assurance operations

How to run the assurance surface: what to configure, what to hand a relying
party, what each level currently means, and what to read before granting one.

The design is in [Human Trust Protocol](HUMAN_TRUST_PROTOCOL.md); the boundary
decision in [ADR 0004](adr/0004-verify-humans-never-issue-identity.md); the
transport decision in [ADR 0005](adr/0005-assurance-api-surface.md). This
document is the operator's side.

## What you are turning on

An assurance assertion answers one narrow question for one relying party: how
much verified human evidence backed this interaction. It is not an identity, not
a session token and not an authorization. It carries no subject identity, no
biometric material, no device identifier and no cross-site identifier.

The surface is **off by default** and stays off unless a signing key, a binding
secret and a non-empty audience allow list are all present. An incomplete
configuration fails closed rather than minting unusable assertions.

## See it work first

```sh
go run ./scripts/human-liveness-demo   # http://localhost:8099
```

Loopback only, synthetic keys, nothing persisted. It walks an assertion without
liveness, the interactive challenge, the same assertion with liveness, a real
WebAuthn ceremony against a platform authenticator, and one assertion per
surface side by side. The console prints the shape of each attempt and nothing
about who made it.

It is a functional check, not a measurement: one person is not a cohort, and no
false-positive interval comes out of it. What it does show is a withheld level
in the concrete — the evidence recorded, the level unchanged — which is easier
to argue with than a paragraph.

## Configure

Four things, all operator-held, none of which leave the process except the
public signing key.

| Item | Purpose | Constraint |
|---|---|---|
| Ed25519 signing key | Signs assertions | The private half never leaves the deployment |
| Binding secret | Derives the per-audience session and channel commitments | At least 32 bytes; **not** the proof-token secret |
| Audience allow list | Which relying parties may be minted for | Non-empty; an unlisted audience is refused, not minted |
| Content validity | How long a message assertion stays verifiable | A day by default, a week at most |

The binding secret is what makes two relying parties unable to link the same
visitor. Reusing another subsystem's secret would let one construction's output
be replayed into the other, so keep it separate and rotate it on its own
schedule. Rotating it changes every commitment, which is a visible change to a
relying party rather than a silent one.

A content validity above the contract's week **disables the surface** rather
than being clamped. A deployment that asked for more than the contract allows
should find that out at start-up.

### Liveness and device evidence

Both are optional and independent. Enable liveness to make H2 evidence
reachable and device attestation to make H3 evidence reachable. Each has its own
secret; do not share one between them.

Decide what "device" means to you before you enable it. Most people present a
synced passkey, which lives on every device signed into their account: the
ceremony then shows possession of that account's credential, not of one machine.
The verifier reports the backup-eligible flag and `RequireDeviceBound` refuses
such credentials, but turning it on excludes almost everyone, so it is a
deliberate trade rather than a hardening default.

The same credential type also keeps no signature counter — a counter cannot stay
consistent across copies, so the authenticators that sync report zero every time.
That is allowed and it verifies, but it means clone detection never runs. Read
the two together: for the credential most people present, device evidence is
neither bound to a device nor checked for cloning. It is evidence that someone
holds the account's registered credential, which is worth something, and it is
less than the phrase "device attestation" suggests.

Device attestation additionally needs a registry. PALISADE registers nothing:
your own registration ceremony writes credentials, and PALISADE reads them
through an interface you implement. Whatever attestation-statement policy you
want — which vendor made the authenticator — is applied there, at registration,
not here. Persist the signature counter the verifier hands back: without that,
clone detection cannot run for the authenticators that do keep one. The verifier
reports whether a counter was in play at all, so a deployment can tell a check
that passed from a check that never executed.

## Hand to a relying party

Three things:

1. the **public** signing key;
2. the audience string you minted for;
3. a verifier — [`pkg/palisadeassurance`](../pkg/palisadeassurance) for a Go
   service, [`verifier/`](../verifier) for a browser, phone or desktop client.

Nothing else. A relying party that has the public key and its own audience can
check an assertion offline, with no call back to you.

Both verifiers are held to the same
[conformance suite](../examples/conformance/human-assurance-assertion-v2.json)
plus a set of documents the Go implementation actually signed, so a divergence
in rules or in bytes fails a test rather than a deployment.

## Which surface to call

| You are protecting | Call | The assertion binds to |
|---|---|---|
| An action on your service | `POST /v1/assurance` | session, action, endpoint class |
| A message you are sending | `POST /v1/assurance/content` | a commitment you computed over the message |
| A call in progress | `POST /v1/assurance/channel` | a channel commitment and the current interval |

On the message surface you compute a SHA-256 over the message and send only
that. PALISADE never receives the message. The recipient checks the commitment
against what it received, so a forwarded assertion fails on the forwarded
message and an altered message fails on the original assertion.

On the call surface you request one assertion per interval for as long as the
call lasts. The deployment derives the interval from its own clock; you cannot
name one. The other participant's client checks that each assertion continues
the channel the call started on — same opaque channel, interval advanced.

## What a level means today

| Level | Granted? | Meaning |
|---|---|---|
| H0 | yes | No human evidence. A legitimate answer, not an error. |
| H1 | yes | PALISADE verified bounded interaction evidence against its own event store. |
| H2 | **computed and withheld** | A completed interactive liveness challenge: several rounds, each revealed at its own moment and answered in order inside a narrow window. It evidences live attachment, not humanity — a script that reads the prompt answers as well as a person. |
| H3 | **computed and withheld** | Plus a registered credential the person holds. A synced passkey satisfies this by default and is *not* bound to one device; require `RequireDeviceBound` if you need that literally, at the cost of excluding most people. |
| H4, H5 | no | No verifier exists. |

A withheld level arrives as H1 carrying
`level_withheld_pending_measurement` alongside the evidence reason codes. That
is deliberate and it is the honest state: the mechanisms work, but no
confirmed-human false-positive and abandonment interval exists per level yet.
Granting a level you have not measured harms people before anyone knows how
often it does.

Do not read a withheld level as a failure. It says the evidence was there and
the build declined to state it.

## Before you gate anything on a level

Read the per-level interval on a chronological holdout, not on the population
your thresholds came from:

```sh
go run ./cmd/palisade evaluate-shadow-holdout --dir <shadow-dir> --key-file <key> --holdout-start <RFC3339>
```

`assurance_slices` in both partitions carries the linked outcome evaluation per
endpoint class and assurance level, with the same Wilson intervals the endpoint
slices use. `analyze-shadow-log` reports the same slicing over the whole log.

Read three things before granting a level:

- the **confirmed-human false-positive interval** at that level, on the holdout
  partition, for the endpoint class you intend to gate;
- the **abandonment rate**, including how many people completed the alternative
  path instead — a control that excludes people does not remove them, it routes
  them around itself;
- the **`unknown` bucket**. Decisions never evaluated for assurance are counted
  there, never folded into H0. A large unknown bucket means your sample says
  less than its size suggests.

Every surface you gate above H1 needs a reviewed alternative path. That is not
a usability nicety: people a control excludes route around it, through shared
accounts, relatives or paid intermediaries — precisely the relay paths the
control was meant to close.

## What this does not tell you

- **Not identity.** An assertion says how much evidence there was, never who.
- **Not a separator.** No challenge, credential or behavioural model separates
  people from automation. Each raises the cost of one forgery and lowers the
  throughput of many.
- **Not media verification.** On a call, no audio or video is analysed. A
  verified channel means a present person holding a registered device stayed
  attached and re-attested. It does not mean the voice is real, and a client
  must not phrase it as if it did.
- **Not proof of personhood.** Uniqueness is issuer-scoped where it exists at
  all, and no issuer is implemented.

## Legal assessment

Enabling assurance does not change the deployment's obligations, and
self-hosting does not discharge them. The
[EU privacy deployment checklist](privacy/DEPLOYMENT_CHECKLIST.md) applies
unchanged. If you later add an external issuer whose enrolment uses biometrics,
that is special-category processing under GDPR Article 9 with its own legal
basis and an expected Article 35 DPIA — assessed for that issuer's method, not
inferred from PALISADE's architecture.
