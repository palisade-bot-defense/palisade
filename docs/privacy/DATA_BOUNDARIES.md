# Data boundaries

PALISADE should decide from behavior without reconstructing a person's content.

## Allowed on the hot path

- Quantized event timing and counts.
- Quantized movement magnitude and scroll depth.
- Visibility and navigation lifecycle transitions.
- Sequence gaps and bounded session aggregates.
- Server-side protocol consistency signals.
- Random, server-issued session identifiers authenticated by an HttpOnly cookie; they are continuity handles, not identity claims.
- Reason codes and normalized verdicts from challenge systems, external risk providers and policy-alert sources.

## Prohibited

- Keystrokes, clipboard contents or form values.
- DOM text, screenshots or canvas captures.
- Exact pointer coordinates or full pointer trails.
- Full URLs containing queries, fragments or embedded identifiers.
- Secret tokens in logs or replay fixtures.
- Raw customer traffic in public issues, CI artifacts or the repository.

Default event/session retention is five minutes in memory. Optional shadow persistence records only the bounded decision fields and normalized outcomes documented in [SHADOW_LOG.md](../SHADOW_LOG.md). It is disabled unless both a local directory and key file are configured. Records are individually authenticated and encrypted, session IDs are replaced with keyed pilot-local link keys, timestamps are quantized to seconds, retention is configurable, and paths must be owner-only and outside Git worktrees. This is not permission to persist browser events, request bodies, cookies, tokens, IP addresses, user agents or raw traffic.

Retention deletes whole PALISADE-managed files after their age threshold. Operators must choose the shortest useful window, restrict host access, protect and separately back up the key only when policy requires recoverability, and securely retire both key and expired backups. Key rotation uses a new empty directory; mixed-key directories fail closed.

The `__Host-palisade_session` cookie contains only a random identifier plus issue/expiry times and an authenticated signature. It is Secure, HttpOnly, SameSite=Lax, has no Domain attribute and expires after 24 hours. The signing key is domain-separated from proof-token signatures. Cookie validity may increase only the continuity dimension; it must never be interpreted as human, account or device verification.

Scores are decision support, not identity claims. Operators need an appeal/fallback path for challenged people and must measure false positives by endpoint and client cohort.
