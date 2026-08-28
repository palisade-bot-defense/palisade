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
- the internal event-shadow collection funnel from route-classified proofs to
  accepted batches and recorded decisions, including pre-ingest rejections,
  post-ingest drops and bounded counts for the nine closed endpoint classes;
- authenticated protected-handler coverage from reference origin adapters,
  including evaluated requests, bound challenge retries, availability bypasses
  and adapter rejections per closed endpoint class;
- authenticated crawler-registry health from reference origin adapters,
  including signed expiry, revision range, replica drift and closed
  current/expired/empty/static source counts;
- accepted, rejected and dropped outcome-event ingestion counts, without
  presenting event volume as ground-truth label coverage;
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

The collection funnel is deliberately narrower than website traffic coverage.
It can report what happened inside this PALISADE process after a trusted origin
requested a classified event proof: proofs issued, event batches accepted and
shadow decisions recorded. It has no authenticated count of all requests that
reached the protected site, so `traffic_denominator` is always
`external_total_unavailable`. The Console therefore never turns these counters
into a site-wide evaluation percentage or a `healthy` state. `collecting` starts
only after an event batch was accepted; proofs without an accepted batch remain
`no_samples`. Any rejected proof/context or post-ingest recording drop changes
the process-local state to `degraded` until restart. A real coverage ratio needs
the separate authenticated origin-denominator contract described below; event
collection counters alone never provide it.

When the Go reference adapter explicitly enables `CoverageReporting`, it sends
cumulative completed-request counters to `POST /v1/origin-coverage` with the
backend API key. The Console then shows `authenticated_origin_reports` as the
denominator and `protected_handler_requests` as the immutable scope. Fresh
evaluations plus bound challenge retries count as covered handling; availability
bypasses and adapter rejections make the state `degraded`. The report source is
a random per-process epoch, reports are monotonic and idempotent, and the server
keeps at most 1,024 epochs in memory. This still says nothing about requests
that never traversed the configured middleware, so the UI continues to state
that total website traffic is unavailable.

Registry health is similarly explicit rather than inferred from decision
traffic. An adapter with `CrawlerRegistryReporting` enabled calls
`ReportCrawlerRegistryStatus` after initial load and on every bounded watcher
poll. PALISADE accepts only a random process epoch, monotonic sequence, closed
heartbeat deadline, state, revision, validity timestamps, digest and aggregate
counts. Reports disappear after their bounded heartbeat deadline. The Console marks
the registry `current` only when every reporting source has the same unexpired
signed revision and digest. Missing reports are `unavailable`; expiry, static or
empty sources and replica drift are `attention`.

The outcome funnel counts only authorized ingestion attempts after the API-key
boundary. Invalid payload/session/provenance combinations are `rejected`;
validated events that cannot reach the encrypted sink are `dropped`. Successful
writes are `accepted`, but are not described as human or abuse labels. Linked
label coverage remains exclusively in the validated local analysis report.

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
