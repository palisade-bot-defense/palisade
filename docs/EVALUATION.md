# Evaluation protocol

## Minimum viable validation campaign

The current detector is not validated by repository size, feature count or an
unlabeled traffic sample. Before making a detection-efficacy claim, run one
falsifiable four-week shadow campaign on representative traffic:

1. Week 1 verifies integration coverage, route classes, collection loss and
   outcome linkage. Detector thresholds do not change while instrumentation is
   suspect.
2. Weeks 2–3 collect complete traffic cycles with authenticated or
   operator-reviewed human outcomes, operator-confirmed abuse and explicit
   unknowns. Challenge completion remains an outcome, not a human label.
3. Week 4 freezes thresholds and evaluates a time-separated holdout plus unseen
   attack families. Compare the fused decision against the deployment's edge
   and reputation baseline; report incremental lift rather than crediting
   PALISADE for upstream signals.
4. Publish aggregate coverage, label provenance, confidence intervals,
   latency, false-positive rate, recall, challenge abandonment and every
   material cohort gap. A count threshold alone is not representativeness.

The campaign fails—and enforcement stays off—if confirmed humans do not cover
the protected endpoint classes and relevant browser/accessibility cohorts, if
the external traffic denominator is missing, if collection artifacts remain,
or if the time-separated comparison does not improve the declared security
metric within the false-positive and abandonment budgets.

## Unit of evaluation

Evaluate a session/action decision, not an isolated request. Preserve event order and time while replacing direct identifiers with pilot-scoped pseudonyms. Keep raw source data outside the repository.

Each replay record requires an RFC 3339 `observed_at` timestamp, endpoint class, observation window, source verdicts, final outcome label, label provenance and confidence. Records in every versioned shard must be globally chronological; equal timestamps are allowed. `observed_at` drives session TTLs and output expiry, and sanitized importer output must always provide the normalized real observation time. Separate `unknown` from human or bot; uncertain traffic must not be silently treated as benign.

The deployment shadow sink may collect only its closed outcome vocabulary. New outcomes must carry the exact decision ID. `human_confirmed` requires an authenticated account or operator review; `operator_confirmed_abuse` requires operator review; challenge and successful-action outcomes must be server-observed. Each outcome carries `provenance` and `confidence`, and challenge completion must never be promoted to a human label. Record queue drops, unavailable outcome writes, duplicate IDs, endpoint mismatches and missing linkage are reported as measurement loss, not silently excluded from denominators.

`palisade analyze-shadow-log` produces the closed aggregate `palisade.shadow-analysis.v4` readiness report from authenticated local records. It keeps only SHA-256 digests of decision IDs under `--max-decision-links` (default one million, hard maximum five million) and never emits those digests. False-positive rate, abuse recall and precision are computed only for unique decisions carrying one unambiguous confirmed ground-truth label. Challenge rates use challenged decisions at least 15 minutes old; absent, duplicate and conflicting terminal outcomes remain explicit. Results are sliced by endpoint and a closed coarse cohort (`standard`, `reduced_motion`, `keyboard_only`, `fallback_path`, `sensor_missing`, `unknown`). Cohorts are trusted operational tags, not inferred attributes and never detector evidence. Canary comparisons remain descriptive rather than causal. Challenge promotion budgets are additionally grouped by the exact signed rollout ID and endpoint so unrelated historical traffic cannot mask a harmful canary. `operator_review_candidate` permits only review of a reversible endpoint canary; the report never enables enforcement.

`palisade evaluate-shadow-holdout` applies a predeclared UTC boundary to that
same authenticated decision/outcome stream. Partition membership follows the
decision record time, so a delayed label cannot move a baseline decision into
holdout. It reports only aggregate linked confusion and challenge metrics by
endpoint/cohort, keeps unknown and ambiguous decisions explicit and always sets
automatic enforcement to false. It does not implement unseen-family grouping;
that remains the separate normalized local-evidence workflow.

The evaluated 2026-08-26 offline export contains 16 `human_confirmed` admin clients,
17,841 weak `campaign_signature` clients and 169,050 `unlabeled` clients.
Neither rendered subresources/internal referers nor timing regularity define a
human cohort: the browser campaign loads and renders assets, and its median
`gap_cv` is 4.36 versus 2.45 for the selected unlabeled comparison. Challenge
completion is also only an outcome; the campaign commonly solved proof-of-work.
These fields may be reported diagnostically but must not be converted into
benign labels or used to claim a false-positive rate.

## Splits

Use time-based holdouts and group related campaigns, networks and tooling into one split. A random request split leaks repeated attacker behavior and produces unrealistically strong results. Maintain an unseen-family red-team set.

For generic normalized local evidence, `palisade evaluate-local-holdout`
implements this boundary in one verified streaming pass. The operator must
predeclare an absolute UTC `--holdout-start`; windows crossing it are excluded
and counted. Optional owner-only family annotations identify a holdout family
as unseen only when that family did not occur in an annotated baseline window.
The closed report contains only aggregate confusion counts, Wilson intervals,
endpoint membership slices and readiness reasons. See
[local holdout evaluation](LOCAL_HOLDOUT_EVALUATION.md). Running the command on
private data is still required before this roadmap item can be considered
empirically complete.

## Required metrics

- False-positive rate and challenge rate for confirmed human sessions.
- Recall and precision for confirmed abusive automation.
- Coverage and error rates for unknown traffic.
- Calibration error for all three scores.
- p50/p95/p99 decision latency and allocation rate.
- Challenge completion, abandonment and fallback usage by client cohort.
- Decision changes when sensor or external sources are unavailable.

Report confusion matrices by endpoint class. A global average can hide unacceptable harm on login, checkout or accessibility cohorts.

## Promotion gates

1. **Replay:** deterministic output, versioned inputs and no regression beyond approved tolerances. Assert enforced `expected_action` separately from policy `expected_computed_action`.
2. **Shadow:** no risky response changes; `action` remains `allow` or `observe` while `computed_action` is compared with downstream outcomes for at least one full traffic cycle.
3. **Canary:** progressive response on a small, reversible endpoint cohort.
4. **Enforcement:** automatic blocks only for narrow, high-confidence policies with rollback and operator review. Promotion from a challenge-capable canary requires at least 100 mature uniquely linked challenges on the exact rollout and endpoint, a Wilson 95% lower bound of at least 90% for terminal-outcome coverage, and Wilson upper bounds no greater than 10% for abandonment and fallback usage. A fallback is a safety path, not a failure or human label; exceeding its rollout budget means review the primary challenge and accessibility experience, never remove the fallback.

Every release report records data window, hashes, policy/model versions, thresholds and known limitations. Never optimize on the enforcement holdout after looking at its labels.
