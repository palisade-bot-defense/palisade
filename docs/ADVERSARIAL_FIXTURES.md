# Public adversarial conformance fixtures

PALISADE publishes a versioned, synthetic-only adversarial suite at
[`examples/adversarial/suite-v1.json`](../examples/adversarial/suite-v1.json).
It turns the v0.3 threat list into a machine-readable contract across six
categories:

- deterministic replay and one-time capability consumption;
- state, annotation and detector-evidence poisoning;
- missing or unverified signals that must remain neutral or unknown;
- forwarding, crawler-identity and raw edge-intelligence spoofing;
- accessibility cohort, fallback and challenge-label safety; and
- explicit adapter failures, risky shadow responses and unsafe-method replay.

Every scenario names at least one executable Go test containing only synthetic
inputs. The repository contract verifies that scenario IDs and expected
outcomes are closed, all six categories remain represented and every referenced
test function still exists. This prevents a documentation-only scenario from
silently surviving after its executable coverage is removed or renamed.

The suite schema is
[`schemas/adversarial-suite-v1.schema.json`](../schemas/adversarial-suite-v1.schema.json).
The narrower
[`adversarial holdout suite`](../examples/holdout/adversarial-scenarios-v1.json)
continues to define chronological evaluation and unseen-family attacks in more
detail.

Run the executable contract locally:

```sh
go test ./internal/sovereignty ./internal/localsequence ./internal/detector \
  ./internal/httpapi ./internal/token ./pkg/palisadehttp ./cmd/palisade
```

These fixtures verify failure behavior and product invariants. They are not a
traffic dataset, a false-positive-rate estimate or evidence of detection
efficacy. Real efficacy and accessibility rates still require independently
confirmed, delayed outcomes from a representative private shadow deployment.

The broader [synthetic red-team baseline](RED_TEAM.md) is a separate v0.9 audit
preparation contract. It executes evasion, poisoning, proof relay, session reset,
resource exhaustion and rollout-compromise controls as one local exercise without
changing this frozen v0.3 conformance suite.
