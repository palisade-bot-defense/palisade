# Native decoy capabilities

PALISADE can turn a deployment-owned trap into normalized, server-verified
evidence without receiving the trap URL, HTML, form fields, request content,
client address or user-agent value. The deployment remains responsible for
where and how a decoy is rendered.

## Backend flow

1. The trusted origin calls `POST /v1/decoy/issue` with its PALISADE bearer
   credential, an opaque session handle, one canonical endpoint class and one
   closed surface class: `link`, `form` or `api`.
2. PALISADE returns a 43-character random capability with a default five-minute
   expiry. The origin embeds that opaque value in its own deployment-specific
   trap.
3. If the trap is touched, the trusted origin calls `POST /v1/decoy/hit` with
   the capability and `touched`; a `form` capability may instead report
   `submitted`. This is a server-to-server call;
   the PALISADE API key must never be exposed in browser markup.
4. The capability is consumed exactly once. The next decision for the bound
   session and endpoint class consumes the pending hit at most once and emits
   `DECOY_CAPABILITY_REDEEMED`.

Issue request:

```json
{
  "session_id": "opaque-session-handle",
  "endpoint_class": "login",
  "surface": "form",
  "ttl_seconds": 300
}
```

Hit request:

```json
{
  "capability": "opaque-random-capability-from-issue",
  "interaction": "submitted"
}
```

## Security semantics

- Issuance and hit ingestion both require the backend bearer credential.
- Capabilities contain 256 random bits. PALISADE retains only their SHA-256
  digests, plus a domain-separated digest of the session handle.
- State is process-local, bounded to 100,000 combined issued/pending entries,
  and expires after at most 15 minutes. Pending evidence expires after five
  minutes and is consumed by one matching decision.
- A capability cannot be rebound to a different session or endpoint class.
- An expired or replayed capability creates no evidence.
- A native decoy hit is intent evidence, not proof of automation or identity.
  The default policy may request a step-up from this signal alone, but blocks
  only when independent policy-alert evidence is also present.
- Restarting a single instance discards outstanding capabilities and pending
  hits. Multi-instance deployments need sticky routing until a future shared
  state contract is explicitly designed and measured.

The older `honeypot_hits` observation remains a normalized signal supplied by
a trusted adapter for compatibility. It is reported as
`HONEYPOT_INTERACTION`. Native capabilities have the stronger, distinct reason
code `DECOY_CAPABILITY_REDEEMED`; neither contract accepts raw trap data.

Go `net/http` deployments can use `Middleware.IssueDecoy` and
`Middleware.RecordDecoyHit`. These helpers validate the closed enums locally,
forward the signed PALISADE session cookie only for issuance, attach the
backend API key server-side and reject malformed service responses.
