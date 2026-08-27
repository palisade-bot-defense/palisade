# Local Operator Console

PALISADE serves its integration API and its administrative surface on separate
listeners. The public `--listen` address never serves the dashboard or
administrative summary. The `--admin-listen` address accepts only a literal
loopback IP (`127.0.0.1` or `::1`) and defaults to `127.0.0.1:8081`.

Outside development mode set three independent secrets:

```sh
export PALISADE_HMAC_KEY='base64url-secret-without-padding'
export PALISADE_API_KEY='backend-integration-secret'
export PALISADE_ADMIN_KEY='distinct-operator-secret-at-least-32-bytes'
```

Open `http://127.0.0.1:8081`. The console asks for the admin key and holds it
only in React process memory. It does not use cookies, local storage or session
storage. Locking or closing the tab discards the value. The summary endpoint
uses a constant-time bearer comparison and sends `Cache-Control: no-store`.

## What the console shows

- process uptime and configured runtime, policy, model and rollout identifiers;
- accepted event batches and bounded event counts;
- computed and enforced action counters;
- bounded aggregate reason-code counts explaining why decisions were reached;
- successful encrypted decision/outcome writes and explicit drop counters;
- whether the encrypted sink and event-triggered shadow evaluation are active;
- an optional aggregate v3 analysis report with linked endpoint/cohort Wilson
  95% intervals and same-endpoint shadow/canary comparisons reloaded from an
  atomic local feed.

The endpoint does not return session or decision identifiers, individual reason
trails, request fields, proofs, keys, file paths or decrypted records. Counters
are process-local and reset on restart; they are operational telemetry, not an
audit log. The Console labels false-positive rate, recall, precision and
challenge completion only from uniquely linked decision/outcome evidence. Empty
denominators display as `no sample`; ambiguous, unresolved and mismatched
evidence stays visible rather than being treated as success. Canary differences
remain descriptive, not causal.

The control center exposes only real tab-local controls: manual refresh,
bounded polling intervals, pause/resume and lock. It also shows the effective
runtime mode, rollout ID and activation authority. It cannot edit detector
weights, sign a plan or activate enforcement. Aggregate reason-code counts are
deduplicated per decision, limited to 64 stable codes and sorted by frequency;
they explain system behavior without disclosing an individual request trail.

## Loading analysis

Create the report locally, outside every Git worktree, then start PALISADE with
the owner-only file:

```sh
palisade analyze-shadow-log \
  --dir /private/local/palisade-shadow/logs \
  --key-file /private/local/palisade-shadow/shadow.key \
  --output /private/local/palisade-shadow/analysis.json \
  --watch-interval 5m

palisade serve \
  --admin-analysis-report /private/local/palisade-shadow/analysis.json
```

PALISADE reads the report at startup and polls it every 30 seconds by default;
`--admin-analysis-refresh` changes that bounded interval. The server uses the
same canonical-path, owner-only, outside-Git and size checks used for rollout
inputs. It rejects unknown JSON fields and validates all aggregate arithmetic
and default recommendations. A rejected replacement leaves the last valid
report visible with an `invalid_update` warning. Reports shorter than the
rollout observation window may be displayed honestly as collection state, but
they remain ineligible for signing a rollout.

When the report shows `operator_review_candidate`, generate the private,
non-executable proposal with `palisade prepare-review`; the console deliberately
has no button or API that writes, signs or activates a rollout. The proposal
binds the exact report hash to a narrow scope and lists the remaining operator
checks. Follow the [signed review and rollout guide](ROLLOUT.md).

The baseline listener is intentionally local. Remote or multi-user access,
reverse-proxy publication, browser sessions and role-based access control are
not part of this release and must not be simulated by binding the admin surface
to a public interface. The baseline Compose deployment therefore supplies the
required admin secret but publishes only the decision API port; use the native
process on an operator-controlled host to access this local console.
