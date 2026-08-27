# Native challenge lifecycle

PALISADE includes a bounded native challenge capability for an origin adapter.
It is a short-lived anti-replay step-up, not a CAPTCHA and not evidence that a
person is present. Browser automation can complete it. The purpose is to add a
measurable, progressively deployable cost and to authorize exactly one bound
origin flow after completion.

## Preconditions

A challenge is created only when all of these conditions hold:

- `/v1/origin-check` produced an applied `challenge` action;
- the action came from a valid signed `canary` or `enforce` rollout;
- the decision contains a bounded, unexpired challenge directive;
- the request session matches a valid `__Host-palisade_session` cookie.

Shadow decisions and direct `/v1/decision` calls never allocate challenge
state. If challenge state cannot be created, the origin check fails with `503`
instead of returning an unusable `403`.

## Origin integration

For `X-Palisade-Handling: challenge`, read both headers returned with `403`:

```text
X-Palisade-Challenge-ID: <32-character identifier>
Location: /v1/challenge/<identifier>
```

The included Go [`palisadehttp`](../pkg/palisadehttp) middleware implements this
same-origin sequence while forwarding the PALISADE session cookie:

1. `GET /v1/challenge/{id}` returns closed metadata, `ready_at`, `expires_at`,
   remaining attempts and a signed verification token.
2. After `ready_at`, `POST /v1/challenge/verify` exchanges that token for a
   short-lived redemption token. A request before `ready_at` returns `425` and
   `Retry-After` without consuming an attempt.
3. Before the redemption expiry, the adapter calls
   `POST /v1/challenge/redeem` with the original closed `action` and
   `endpoint_class`.
4. A `204` plus `X-Palisade-Challenge: redeemed` authorizes exactly one retry
   matching the original method, escaped path, raw query, action and endpoint
   class. The reference adapter binds this locally with a process-random HMAC;
   it never stores or sends the raw request target. A mismatched request neither
   passes nor consumes the grant.

Do not put an original URL, query string, request body, cookie or upstream token
in any challenge request. PALISADE intentionally does not store a return URL.
Custom origins own this same bounded mapping. The reference adapter limits
pending challenges and retry grants, expires both, and loses them on restart.

Example verification bodies:

```json
{"challenge_id":"...","verification_token":"..."}
```

```json
{"challenge_id":"...","redemption_token":"...","action":"read","endpoint_class":"public_content"}
```

## Accessibility and fallback

The protocol family is `timed_confirmation_v1`. Its contract is nonvisual,
keyboard-operable and does not collect pointer paths, typing patterns or
content. The origin adapter is responsible for rendering clear accessible UI,
announcing the remaining wait without focus traps, and preserving a documented
support route.

`POST /v1/challenge/fallback` closes the active challenge and records only the
closed `fallback_used` outcome. The deployment may then offer account
reauthentication, WebAuthn or human support as appropriate for that endpoint.
PALISADE does not accept a fallback/return URL in this API.

## State, limits and failure semantics

The baseline stores at most 100,000 challenges in process memory. Each challenge
is bound to the session, decision, action, endpoint class, rollout, random ID,
ready time and expiry. The default confirmation delay is two seconds, there are
at most five invalid verification attempts, and redemption expires after at
most 60 seconds or at the challenge expiry, whichever comes first. Challenge
directives cannot exceed 15 minutes.

Expired entries are swept every minute and while new challenges are issued.
Expiry, failed attempts, fallback and successful redemption produce only these
normalized local outcomes:

- `challenge_passed`
- `challenge_failed`
- `challenge_abandoned`
- `fallback_used`

They use `server_observed` / `confirmed` provenance in the encrypted shadow
sink. A completed challenge is never converted to `human_confirmed`. If the
bounded shadow queue is unavailable, the user-facing completion remains final
and PALISADE counts/logs the measurement loss rather than replaying the action.

Process restart invalidates every outstanding challenge. This is an explicit
single-instance baseline. Multi-instance deployment requires a shared,
atomic, TTL-aware state implementation with the same one-time semantics before
traffic is spread across replicas; adding a general database or cache is not a
baseline requirement.

The reference UI is served below `/__palisade`, uses a restrictive CSP, is
keyboard-operable and nonvisual, and reloads the current browser location only
after successful redemption. Only challenged `GET` requests receive this page;
unsafe methods are never buffered or replayed. See [ORIGIN_ADAPTER.md](ORIGIN_ADAPTER.md).

## Stable HTTP errors

| Status | Error | Meaning |
|---|---|---|
| `400` | `challenge_invalid` | Invalid token, binding or closed request shape |
| `401` | `invalid_session` | Missing, expired or invalid signed session cookie |
| `404` | `challenge_not_found` | Unknown challenge or session mismatch |
| `409` | `challenge_invalid_state` | Already verified, redeemed, failed or closed |
| `410` | `challenge_expired` | Challenge or redemption expired |
| `425` | `challenge_not_ready` | Wait until `Retry-After` |
| `429` | `challenge_attempts_exceeded` | Invalid verification attempt limit reached |
| `503` | `challenge_service_unavailable`, `challenge_issue_failed`, or `challenge_unavailable` | Bounded state, issuance or internal service unavailable |

The full wire schema is in [OpenAPI](../api/openapi.yaml). Rollout preparation,
measurement and rollback remain governed by [ROLLOUT.md](ROLLOUT.md).
