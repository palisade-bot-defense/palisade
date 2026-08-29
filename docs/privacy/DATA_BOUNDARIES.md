# Data boundaries

PALISADE should decide from behavior without reconstructing a person's content.

## Allowed on the hot path

- Quantized event timing and counts.
- Quantized movement magnitude and scroll depth.
- Visibility and navigation lifecycle transitions.
- Sequence gaps and bounded session aggregates.
- Saturating counts of recent enforced responses and retries before an active
  Retry-After boundary; both expire with the five-minute session and are never
  persisted as a client history.
- Server-side protocol consistency signals.
- Closed transport protocol/security and client-address provenance classes;
  never the peer, proxy or client address itself.
- Closed edge-fingerprint method/class and network reputation/type classes
  computed by a trusted deployment adapter. Raw JA4/JA3 hashes, HTTP/2
  fingerprints, IP addresses, ASNs, reverse-DNS names, provider scores and
  vendor labels never enter PALISADE.
- Closed crawler purpose and proof-method classes derived at the trusted origin.
  The reference adapter may compare an address and user-agent transiently with
  an operator-supplied local registry, but sends and retains only the closed
  verification result.
- Random, server-issued session identifiers authenticated by an HttpOnly cookie; they are continuity handles, not identity claims.
- Reason codes and normalized verdicts from challenge systems, external risk providers and policy-alert sources.
- Opaque server-generated decoy capabilities plus the closed `link|form|api`
  surface and `touched|submitted` interaction classes. Capabilities are bound
  to an opaque session and closed endpoint class; no trap URL or form content
  enters PALISADE.
- One closed, deployment-supplied evaluation cohort (`standard`, `reduced_motion`, `keyboard_only`, `fallback_path`, `sensor_missing`, `unknown`) used only for aggregate safety measurement.

## Prohibited

- Keystrokes, clipboard contents or form values.
- DOM text, screenshots or canvas captures.
- Exact pointer coordinates or full pointer trails.
- Full URLs containing queries, fragments or embedded identifiers.
- Raw client, proxy or peer IP addresses in decision observations or shadow
  records.
- User-agent strings, reverse-DNS names or vendor-specific crawler labels in
  decision observations, shadow records or the operator summary.
- Secret tokens in logs or replay fixtures.
- Raw customer traffic in public issues, CI artifacts or the repository.

## Local import exception

The generic [`import-local-events`](../LOCAL_IMPORT.md) CLI is outside the hot
path. In an owner-only, operator-authorized input file it accepts a bounded
`subject_ref` and optional `session_ref` solely to derive daily rotating,
dataset-and-pilot-separated pseudonyms. These references may contain personal
data, including an address if the operator chooses that local mapping. They are
never written to normalized shards, manifests, stdout or error messages and
never sent over a network. All other raw classes above remain prohibited. The
input and pseudonymized output stay outside Git and remain subject to the
operator's legal basis, access controls, retention and deletion duties.

The follow-on [`analyze-local-events`](../LOCAL_SEQUENCE_ANALYSIS.md) command
may use daily subject/session pseudonyms transiently as bounded sequence-map
keys. It verifies every shard locally and persists only aggregate counts,
closed feature definitions, collection-quality totals and a source time range.
Pseudonyms and row-level events never enter the report. The report is still a
private, owner-only artifact because its aggregate timing and volume may be
sensitive; the repository privacy guard rejects it by schema marker even after
renaming.

[`evaluate-local-holdout`](../LOCAL_HOLDOUT_EVALUATION.md) may additionally
read an owner-only mapping from a normalized daily sequence pseudonym to an
operator attack/tool family reference. Both fields are transient and reduced
to domain-separated fixed-size digests in memory. The report persists only
aggregate partition/slice counts, Wilson intervals, an annotation-file
fingerprint and closed readiness reasons. It contains no sequence or family
identifier. Annotation inputs and holdout reports are blocked from Git by both
filename/content guards and remain subject to operator access, retention and
deletion controls.

Default event/session retention is five minutes in memory. Optional shadow persistence records only the bounded decision fields and normalized outcomes documented in [SHADOW_LOG.md](../SHADOW_LOG.md). It is disabled unless both a local directory and key file are configured. Records are individually authenticated and encrypted, session IDs are replaced with keyed pilot-local link keys, timestamps are quantized to seconds, retention is configurable, and paths must be owner-only and outside Git worktrees. This is not permission to persist browser events, request bodies, cookies, tokens, IP addresses, user agents or raw traffic.

The response-cost controller reuses that five-minute session entry for two
saturating counters and an in-memory Retry-After deadline. These values may
only increase bounded response duration up to a signed plan maximum; they are
not detector labels, are not exported, and reset on TTL expiry or restart.

When event-triggered shadow evaluation is enabled, accepted browser events stay
in that same bounded memory store; only the resulting closed decision is sent
to the encrypted recorder. The browser receives only a `recorded|dropped`
status header. The event proof and internally minted decision proof are cleared
before the recorder is called and are never persisted.

Retention deletes whole PALISADE-managed files after their age threshold. Operators must choose the shortest useful window, restrict host access, protect and separately back up the key only when policy requires recoverability, and securely retire both key and expired backups. Key rotation uses a new empty directory; mixed-key directories fail closed.

The `__Host-palisade_session` cookie contains only a random identifier plus issue/expiry times and an authenticated signature. It is Secure, HttpOnly, SameSite=Lax, has no Domain attribute and expires after 24 hours. The signing key is domain-separated from proof-token signatures. Cookie validity may increase only the continuity dimension; it must never be interpreted as human, account or device verification.

Native challenge state is memory-only and contains a random challenge ID, the
closed session/decision/action/endpoint/rollout bindings, attempt/state fields,
expiries, a hash of the server-only origin-flow capability and only a hash of
the one-time redemption capability. It never stores
the original URL, query, request body, IP address, user agent, cookie or sensor
events. Only closed challenge outcomes may enter the encrypted shadow sink.

Native decoy state is also memory-only and bounded. Issuance retains only a
SHA-256 digest of the random capability, a domain-separated digest of the
opaque session handle, one closed endpoint/surface class and an expiry. A
successful backend-authenticated hit consumes the capability exactly once and
queues at most 100 normalized hits for five minutes. The next matching
decision consumes that evidence at most once. A decoy hit is suspicious intent
evidence, not an identity label and not a standalone block condition.

The reference Go origin adapter additionally holds bounded, expiring sequence,
pending-challenge and one-time retry maps. It binds the retry to method, escaped
path, raw query and decision sequence with a process-random HMAC. The pending
entry also retains one opaque 32-byte origin-flow capability until redemption.
Only digests and that capability are retained; the
application URL, query, body, user-agent value and PALISADE tokens are never
stored in this map or sent as observations.

Scores are decision support, not identity claims. Operators need an appeal/fallback path for challenged people and must measure false positives by endpoint and client cohort.

The [Sovereignty Report](../SOVEREIGNTY.md) inventories PALISADE product
invariants separately from closed operator declarations. It does not inspect
network flows or turn self-hosting into a legal-compliance claim.
The versioned [data map](../DATA_MAP.md) and [runtime egress
inventory](../RUNTIME_EGRESS.md) make accepted flows and reviewed outbound
calls machine-readable; surrounding operator infrastructure remains outside
that source-level inventory.

The evaluation cohort is not detector evidence. It must not contain free text,
account or device identifiers, browser fingerprints, medical diagnoses or
demographic inference. Empty input becomes `unknown`; unknown values fail
validation. Analysis emits only endpoint/cohort aggregates and never the
decision-ID digests used for the bounded local join.
