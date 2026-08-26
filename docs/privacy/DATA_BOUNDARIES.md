# Data boundaries

PALISADE should decide from behavior without reconstructing a person's content.

## Allowed on the hot path

- Quantized event timing and counts.
- Quantized movement magnitude and scroll depth.
- Visibility and navigation lifecycle transitions.
- Sequence gaps and bounded session aggregates.
- Server-side protocol consistency signals.
- Reason codes and normalized external verdicts from Anubis, Cannai Shield and CrowdSec.

## Prohibited

- Keystrokes, clipboard contents or form values.
- DOM text, screenshots or canvas captures.
- Exact pointer coordinates or full pointer trails.
- Full URLs containing queries, fragments or embedded identifiers.
- Secret tokens in logs or replay fixtures.
- Raw customer traffic in public issues, CI artifacts or the repository.

Default event/session retention is five minutes in memory. Production persistence is not implemented. Any future retention must be purpose-limited, configurable, encrypted, access-controlled and documented before release.

Scores are decision support, not identity claims. Operators need an appeal/fallback path for challenged people and must measure false positives by endpoint and client cohort.
