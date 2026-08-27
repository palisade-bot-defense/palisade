# Signed rollout and origin enforcement

PALISADE never converts an analysis report directly into live blocking. The
local analyzer may nominate a reversible canary, but an operator must review
that aggregate report and sign an expiring rollout plan. The server accepts
canary or enforcement behavior only from such a plan; `serve --mode enforce`
is rejected.

This separates five authorities:

1. the encrypted shadow log records bounded decisions and outcomes locally;
2. the analyzer produces a closed aggregate report without individual rows;
3. `prepare-review` deterministically binds the exact report hash to a narrow,
   non-executable recommended scope and lists the remaining operator checks;
4. an operator approval key signs exactly that reviewed scope and its expiry;
5. the origin applies the bounded result returned by `/v1/origin-check`.

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

## 2. Produce the deterministic review proposal

```sh
palisade prepare-review \
  --analysis /private/local/palisade-rollout/analysis-20260827.json \
  --output /private/local/palisade-rollout/review-20260827.json \
  --stage canary
```

The closed `palisade.rollout-review.v1` artifact is deterministic: the same
validated report bytes and requested stage produce the same proposal. It
contains the exact report SHA-256, source window, dominant policy/model,
machine-checkable gates, and a fixed operator checklist. It is not signed,
cannot be loaded by `serve`, and always carries `automatic_activation: false`.

A proposal can be produced while evidence is incomplete. In that case its
state is `hold`, its failed gates explain what is missing and
`recommended_scope` is `null`. A candidate selects exactly one allowlisted
public endpoint with observed risky shadow actions. The selection minimizes
the observed risky-action ratio, then prefers the larger sample; account,
login and checkout endpoints are excluded. A canary proposal is fixed at 1%,
24 hours and at most `throttle`.

Before signing, an operator must independently confirm the endpoint confidence
intervals, accessible fallback/support path, origin-adapter fail-safe behavior,
and the rollback owner/command listed in `operator_checklist`. These facts are
not inferred from aggregate counts.

## 3. Create the operator approval key once

```sh
palisade rollout-keygen \
  --private-key /private/local/palisade-rollout/approval.private \
  --public-key /private/local/palisade-rollout/approval.public
```

Both files are `0600`. Keep `approval.private` off the serving host when
operational separation permits it. Deploy only the public key and signed plan.
Never commit either key, an analysis report, a review proposal or a signed
plan. The repository privacy guard rejects these artifacts even when renamed.

## 4. Sign the reviewed canary

```sh
palisade prepare-rollout \
  --analysis /private/local/palisade-rollout/analysis-20260827.json \
  --review /private/local/palisade-rollout/review-20260827.json \
  --private-key /private/local/palisade-rollout/approval.private \
  --output /private/local/palisade-rollout/canary-20260827.json \
  --rollout-id canary-20260827 \
  --approval-id change-1234

palisade verify-rollout \
  --plan /private/local/palisade-rollout/canary-20260827.json \
  --public-key /private/local/palisade-rollout/approval.public
```

`prepare-rollout` reconstructs the proposal from the exact analysis bytes and
rejects a changed hash, gate, endpoint, action, cohort size, duration, policy or
model. The private-key signature is therefore the operator's approval of that
exact deterministic scope; there is no CLI override for a broader action.

One hundred basis points is 1%. The proposal path fixes canaries at 1%, 24
hours and `throttle`; signed plan validation additionally caps any canary at
10%, seven days and `throttle` or `challenge`, and canaries cannot block.
Session assignment is a stable
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

## 5. Apply the origin result

An origin or reverse-proxy adapter sends the same closed `DecisionRequest` to
`POST /v1/origin-check` instead of `/v1/decision`. Do not call both routes for
one request because the production proof is one-time.

For Go `net/http` origins, use the included reference middleware and follow its
[deployment guide](ORIGIN_ADAPTER.md). It validates the complete bounded header
contract before applying a result; risky status codes in shadow mode or without
a rollout ID fail as invalid service responses.

| Status | Header result | Required origin behavior |
|---|---|---|
| `204` | `X-Palisade-Handling: pass` | Continue the original request |
| `429` | `throttle` plus `Retry-After` | Return/rate-limit for that bounded duration |
| `403` | `challenge` plus challenge ID and `Location` | Run the native bound lifecycle described in `CHALLENGE.md` |
| `403` | `block` plus `Retry-After` | Apply the temporary block |
| `503` | stable JSON error | Treat as an adapter failure under the site's documented availability policy |

The response also provides decision, action, mode and rollout IDs in bounded
headers. It never reflects scores, evidence, raw signals or reason codes to the
client. Validate and consume only these documented values. The challenge result
must return later as a normalized outcome; challenge completion is not human
confirmation.

## 6. Measure and review the exact canary

Keep writing encrypted decision/outcome records, then create a new aggregate
report. It attributes enforced canary decisions to their exact rollout ID.
Enforcement preparation requires at least 1000 decisions from the named
predecessor canary, not merely from any historical canary:

```sh
palisade prepare-review \
  --analysis /private/local/palisade-rollout/analysis-after-canary.json \
  --output /private/local/palisade-rollout/review-enforce-20260828.json \
  --stage enforce \
  --predecessor-rollout-id canary-20260827

palisade prepare-rollout \
  --analysis /private/local/palisade-rollout/analysis-after-canary.json \
  --review /private/local/palisade-rollout/review-enforce-20260828.json \
  --private-key /private/local/palisade-rollout/approval.private \
  --output /private/local/palisade-rollout/enforce-20260828.json \
  --rollout-id enforce-20260828 \
  --approval-id change-1251
```

The deterministic enforcement proposal requires at least 1000 decisions from
the exact named predecessor, recommends one public endpoint, covers 100% for
12 hours and caps at `challenge`; it never recommends a block. Signed plan
validation still supports bounded temporary block plans for a future explicit
review contract, but this CLI workflow cannot create one. Directives can never
outlive the signed plan.

## Rollback and limitations

Rollback is deterministic: remove the two rollout flags and restart the
service, or let the signed plan expire. Plans are loaded only at startup; there
is no mutable remote control channel or automatic promotion. Keep the previous
known-good command/config ready before starting a canary.

The signature is the operator's attestation over the report hash and the exact
reproducible review scope. It does not make a report trustworthy if the host or approval process is
already compromised. PALISADE now issues a native in-memory, signed-session-
bound challenge capability for applied challenge directives. The deployment
adapter still owns accessible rendering and the mapping to one pending origin
request; the included Go adapter is the reference implementation. Follow
[the challenge protocol](CHALLENGE.md). Process restart
invalidates outstanding challenges, and this baseline is not a multi-replica
shared-state implementation.
