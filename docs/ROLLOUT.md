# Signed rollout and origin enforcement

PALISADE never converts an analysis report directly into live blocking. The
local analyzer may nominate a reversible canary, but an operator must review
that aggregate report and sign an expiring rollout plan. The server accepts
canary or enforcement behavior only from such a plan; `serve --mode enforce`
is rejected.

This separates four authorities:

1. the encrypted shadow log records bounded decisions and outcomes locally;
2. the analyzer produces a closed aggregate report without individual rows;
3. an operator approval key signs endpoint scope, cohort size, maximum action
   and expiry;
4. the origin applies the bounded result returned by `/v1/origin-check`.

The running shadow deployment and its raw traffic do not need to be copied or
uploaded. Run every command below on the deployment host. Use a canonical,
owner-only directory outside every Git worktree (on macOS use `/private/...`,
not a symlinked `/tmp` or `/var` spelling).

## 1. Produce a protected aggregate report

```sh
install -d -m 0700 /private/local/palisade-rollout

palisade analyze-shadow-log \
  --dir /private/local/palisade-shadow/logs \
  --key-file /private/local/palisade-shadow/shadow.key \
  --output /private/local/palisade-rollout/analysis-20260827.json
```

The output is created once with mode `0600`; existing files are never
overwritten. Continue only when `readiness.state` is
`operator_review_candidate`, the endpoint-specific evidence has been reviewed,
and rollback/support ownership is explicit. The report's
`automatic_enforcement` field is always `false`. Rollout preparation also
requires a self-consistent aggregate covering at least 24 hours; it recomputes
all readiness gates instead of trusting the JSON readiness label.

## 2. Create the operator approval key once

```sh
palisade rollout-keygen \
  --private-key /private/local/palisade-rollout/approval.private \
  --public-key /private/local/palisade-rollout/approval.public
```

Both files are `0600`. Keep `approval.private` off the serving host when
operational separation permits it. Deploy only the public key and signed plan.
Never commit either key, a report or a signed plan.

## 3. Sign a small reversible canary

```sh
palisade prepare-rollout \
  --analysis /private/local/palisade-rollout/analysis-20260827.json \
  --private-key /private/local/palisade-rollout/approval.private \
  --output /private/local/palisade-rollout/canary-20260827.json \
  --rollout-id canary-20260827 \
  --approval-id change-1234 \
  --stage canary \
  --endpoints public_content \
  --max-action throttle \
  --canary-basis-points 100 \
  --expires-in 24h

palisade verify-rollout \
  --plan /private/local/palisade-rollout/canary-20260827.json \
  --public-key /private/local/palisade-rollout/approval.public
```

One hundred basis points is 1%. Canary plans are capped at 10%, seven days and
`throttle` or `challenge`; they cannot block. Session assignment is a stable
HMAC cohort derived from the production secret and rollout ID. Endpoint classes
are allowlisted and account/login/checkout classes cannot currently be placed
in a rollout.

Start the server with its normal production secrets and the verified plan:

```sh
palisade serve --mode shadow \
  --rollout-plan /private/local/palisade-rollout/canary-20260827.json \
  --rollout-public-key /private/local/palisade-rollout/approval.public \
  --require-session-cookie \
  --shadow-log-dir /private/local/palisade-shadow/logs \
  --shadow-log-key-file /private/local/palisade-shadow/shadow.key
```

Rollout plans cannot run with `--dev`: its ephemeral cohort key would change
membership after a restart. A signature, runtime policy/model mismatch,
unsupported endpoint/action, expired plan or excluded cohort fails back to
shadow `observe`.

The server also refuses a rollout without the encrypted shadow sink or signed
session-cookie requirement. The origin must issue and forward the PALISADE
cookie before entering canary; otherwise clients could rotate untrusted session
IDs to change cohort membership and the rollout could not produce promotion or
rollback evidence.

## 4. Apply the origin result

An origin or reverse-proxy adapter sends the same closed `DecisionRequest` to
`POST /v1/origin-check` instead of `/v1/decision`. Do not call both routes for
one request because the production proof is one-time.

| Status | Header result | Required origin behavior |
|---|---|---|
| `204` | `X-Palisade-Handling: pass` | Continue the original request |
| `429` | `throttle` plus `Retry-After` | Return/rate-limit for that bounded duration |
| `403` | `challenge` | Route to the deployment's accessible challenge handler |
| `403` | `block` plus `Retry-After` | Apply the temporary block |
| `503` | stable JSON error | Treat as an adapter failure under the site's documented availability policy |

The response also provides decision, action, mode and rollout IDs in bounded
headers. It never reflects scores, evidence, raw signals or reason codes to the
client. Validate and consume only these documented values. The challenge result
must return later as a normalized outcome; challenge completion is not human
confirmation.

## 5. Measure and promote the exact canary

Keep writing encrypted decision/outcome records, then create a new aggregate
report. It attributes enforced canary decisions to their exact rollout ID.
Enforcement preparation requires at least 1000 decisions from the named
predecessor canary, not merely from any historical canary:

```sh
palisade prepare-rollout \
  --analysis /private/local/palisade-rollout/analysis-after-canary.json \
  --private-key /private/local/palisade-rollout/approval.private \
  --output /private/local/palisade-rollout/enforce-20260828.json \
  --rollout-id enforce-20260828 \
  --approval-id change-1251 \
  --predecessor-rollout-id canary-20260827 \
  --stage enforce \
  --endpoints public_content \
  --max-action challenge \
  --expires-in 12h
```

Enforcement plans always cover 100% of their explicitly listed endpoint
classes, expire within 24 hours and may cap at throttle, challenge or temporary
block. Their directives can never outlive the signed plan.

## Rollback and limitations

Rollback is deterministic: remove the two rollout flags and restart the
service, or let the signed plan expire. Plans are loaded only at startup; there
is no mutable remote control channel or automatic promotion. Keep the previous
known-good command/config ready before starting a canary.

The signature is the operator's attestation over the report hash and rollout
scope. It does not make a report trustworthy if the host or approval process is
already compromised. PALISADE currently returns a challenge directive but does
not render a vendor-specific challenge page; that remains the responsibility
of an authenticated deployment adapter. A native accessible challenge
lifecycle is tracked separately from the safe throttle/block controller.
