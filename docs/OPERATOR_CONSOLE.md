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
- successful encrypted decision/outcome writes and explicit drop counters;
- whether the encrypted sink and event-triggered shadow evaluation are active;
- an optional aggregate analysis report reloaded from an atomic local feed.

The endpoint does not return session or decision identifiers, individual reason
trails, request fields, proofs, keys, file paths or decrypted records. Counters
are process-local and reset on restart; they are operational telemetry, not an
audit log.

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

The baseline listener is intentionally local. Remote or multi-user access,
reverse-proxy publication, browser sessions and role-based access control are
not part of this release and must not be simulated by binding the admin surface
to a public interface. The baseline Compose deployment therefore supplies the
required admin secret but publishes only the decision API port; use the native
process on an operator-controlled host to access this local console.
