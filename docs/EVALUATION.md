# Evaluation protocol

## Unit of evaluation

Evaluate a session/action decision, not an isolated request. Preserve event order and time while replacing direct identifiers with pilot-scoped pseudonyms. Keep raw source data outside the repository.

Each replay record needs an endpoint class, observation window, source verdicts, final outcome label, label provenance and confidence. Separate `unknown` from human or bot; uncertain traffic must not be silently treated as benign.

## Splits

Use time-based holdouts and group related campaigns, networks and tooling into one split. A random request split leaks repeated attacker behavior and produces unrealistically strong results. Maintain an unseen-family red-team set.

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

1. **Replay:** deterministic output, versioned inputs and no regression beyond approved tolerances.
2. **Shadow:** no response changes; compare decisions with downstream outcomes for at least one full traffic cycle.
3. **Canary:** progressive response on a small, reversible endpoint cohort.
4. **Enforcement:** automatic blocks only for narrow, high-confidence policies with rollback and operator review.

Every release report records data window, hashes, policy/model versions, thresholds and known limitations. Never optimize on the enforcement holdout after looking at its labels.
