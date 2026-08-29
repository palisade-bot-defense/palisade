# Automated local shadow analysis

## Objective and boundary

The automation turns the encrypted append-only shadow stream into a current,
validated aggregate report without granting the serving process access to the
log encryption key. It does not upload data, make enforcement changes or create
row-level operator views.

```text
encrypted *.plog + key
          │ local bounded scan
          v
analyze-shadow-log --watch-interval
          │ validate + fsync + atomic same-directory rename
          v
owner-only palisade.shadow-analysis.v4 report
          │ bounded read + closed JSON decode + aggregate validation
          v
serve --admin-analysis-report
          │ counters + recommendations only
          v
loopback Operator Console
```

When the report becomes an operator-review candidate, the next boundary is an
explicit local command, not an automatic worker:

```text
validated analysis.json
          │ prepare-review (deterministic; no key)
          v
owner-only review.json (non-executable; automatic_activation=false)
          │ operator checks + offline Ed25519 approval
          v
short-lived signed rollout plan
```

See [signed review and rollout](ROLLOUT.md). The periodic analyzer never creates
a review proposal, touches the approval key, signs a plan or restarts PALISADE.

Run exactly one writer for a report path:

```sh
palisade analyze-shadow-log \
  --dir /private/local/palisade-shadow/logs \
  --key-file /private/local/palisade-shadow/shadow.key \
  --output /private/local/palisade-shadow/analysis.json \
  --watch-interval 5m
```

The first analysis must succeed or the process exits. Later transient failures
emit only a stable error message and leave the last valid report untouched. The
interval must be between 10 seconds and 24 hours. Existing file-count, record
count and encrypted-byte scan budgets apply to every run.

Start the serving process separately:

```sh
palisade serve \
  --admin-analysis-report /private/local/palisade-shadow/analysis.json \
  --admin-analysis-refresh 30s
```

The v4 report contains only aggregate endpoint totals, linked endpoint/cohort
Wilson 95% intervals, rollout/endpoint canary comparisons and exact
rollout/endpoint challenge budgets. A bounded local
join uses decision-ID digests but emits no IDs or digests. False-positive rate,
recall and precision require unique confirmed decision labels. Challenge rates
use only mature challenged decisions and keep unresolved or ambiguous outcomes
explicit. The shadow/canary difference is not a causal A/B estimate.

The report directory must be canonical, owner-only and outside every Git
worktree. Each publication validates the closed aggregate schema, writes a new
0600 temporary file, syncs it, confirms that the target did not change, renames
it atomically and syncs the parent directory. The reader never follows a
symlink. If a replacement is malformed or fails validation, the Console keeps
the prior report and exposes `analysis_status.state = invalid_update`.

## Availability and failure behavior

- A scan can overlap the currently appended file. If it observes an incomplete
  frame, that run fails safely and the next interval retries; the previous
  report remains available.
- A report update never changes runtime policy, rollout stage or enforcement.
- A review candidate needs risky shadow actions plus at least 100 uniquely
  linked confirmed-human and 100 confirmed-abuse decisions on the exact
  proposed public endpoint.
- Enforcement review additionally needs at least 1,000 decisions and 100 mature,
  uniquely linked challenge outcomes from the exact predecessor canary on that
  same endpoint. Conservative Wilson bounds require at least 90% terminal-outcome
  coverage and at most 10% abandonment and 10% fallback usage.
- A review proposal is generated only on explicit operator invocation and
  cannot be loaded by the serving process.
- Process counters continue independently when analysis is unavailable.
- The source `last_at` timestamp is shown so an operator can judge data
  freshness; PALISADE does not claim that an unchanged report is current.
- Shutdown through SIGINT or SIGTERM stops after the current bounded scan; no
  new update is started.

## Assumptions and trade-offs

The baseline rescans the retained encrypted window on every interval. This is
simple, deterministic and avoids a sensitive index, at the cost of repeated
local I/O. Keep retention and scan budgets bounded. If measured deployments
outgrow this design, revisit an authenticated incremental checkpoint only after
defining crash recovery, rotation and deletion semantics. A database, broker or
cloud analytics service is deliberately not introduced by this feature.

Atomic replacement relies on an owner-controlled parent directory. Portable Go
does not provide a cross-platform directory capability that eliminates every
concurrent-creator race; do not share the report directory with untrusted users
or processes.
