# Data boundaries

PALISADE should decide from behavior without reconstructing a person's content.

## Allowed on the hot path

- Quantized event timing and counts.
- Quantized movement magnitude and scroll depth.
- Visibility and navigation lifecycle transitions.
- Sequence gaps and bounded session aggregates.
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

Default event/session retention is five minutes in memory. Optional shadow persistence records only the bounded decision fields and normalized outcomes documented in [SHADOW_LOG.md](../SHADOW_LOG.md). It is disabled unless both a local directory and key file are configured. Records are individually authenticated and encrypted, session IDs are replaced with keyed pilot-local link keys, timestamps are quantized to seconds, retention is configurable, and paths must be owner-only and outside Git worktrees. This is not permission to persist browser events, request bodies, cookies, tokens, IP addresses, user agents or raw traffic.

When event-triggered shadow evaluation is enabled, accepted browser events stay
in that same bounded memory store; only the resulting closed decision is sent
to the encrypted recorder. The browser receives only a `recorded|dropped`
status header. The event proof and internally minted decision proof are cleared
before the recorder is called and are never persisted.

Retention deletes whole PALISADE-managed files after their age threshold. Operators must choose the shortest useful window, restrict host access, protect and separately back up the key only when policy requires recoverability, and securely retire both key and expired backups. Key rotation uses a new empty directory; mixed-key directories fail closed.

The `__Host-palisade_session` cookie contains only a random identifier plus issue/expiry times and an authenticated signature. It is Secure, HttpOnly, SameSite=Lax, has no Domain attribute and expires after 24 hours. The signing key is domain-separated from proof-token signatures. Cookie validity may increase only the continuity dimension; it must never be interpreted as human, account or device verification.

Native challenge state is memory-only and contains a random challenge ID, the
closed session/decision/action/endpoint/rollout bindings, attempt/state fields,
expiries and only a hash of the one-time redemption capability. It never stores
the original URL, query, request body, IP address, user agent, cookie or sensor
events. Only closed challenge outcomes may enter the encrypted shadow sink.

The reference Go origin adapter additionally holds bounded, expiring sequence,
pending-challenge and one-time retry maps. It binds the retry to method, escaped
path and raw query with a process-random HMAC. Only the digest is retained; the
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
