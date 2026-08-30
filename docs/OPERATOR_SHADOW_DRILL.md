# Operator shadow drill

Runbook contract: `palisade.runbook.operator-shadow-drill.v1`.

This local drill proves that a freshly built PALISADE binary can complete the
minimum production-configured Shadow loop without deployment traffic. It uses
random ephemeral keys, two loopback listeners and three synthetic encrypted
records in an owner-only temporary directory. The directory is deleted at the
end of the run and nothing is uploaded.

Run it from a clean checkout with Go 1.27.x and Python 3:

```sh
make operator-shadow-drill
```

The drill:

1. starts the production server with distinct API/admin credentials, a stable
   HMAC secret, required server-issued session cookies and the encrypted sink;
2. confirms the admin route is absent from the public listener;
3. issues a backend session and one-time proof;
4. submits a closed synthetic multi-source-risk decision and requires enforced
   `observe`, computed `block`, mode `shadow` and
   `SHADOW_ACTION_OVERRIDDEN`;
5. records one normalized operator-confirmed-abuse outcome and checks the
   aggregate admin counters without reading row-level records;
6. shuts down cleanly and authenticates the append-only encrypted chain;
7. proves unsigned `--mode enforce` is rejected;
8. restarts in Shadow, records a second risky decision and verifies the
   complete two-decision/one-outcome chain;
9. runs local aggregate analysis and requires zero risky Shadow enforcements,
   `automatic_enforcement=false` and `remain_shadow`.

The only output is a small machine-readable pass summary. Server output, random
credentials, session cookies, proof tokens, decision IDs, file paths and
decrypted records are not printed or retained.

## What this does not prove

This is a synthetic single-process loopback rehearsal. It is not evidence of a
real operator completing the documentation independently, a proxy/TLS test, a
signed canary exercise, multi-replica availability, detection efficacy or a
false-positive rate. A real rollback from canary/enforcement still requires the
signed-plan expiry/removal procedure, origin-adapter validation and deployment
evidence in [`ROLLOUT.md`](ROLLOUT.md). The drill proves the safe Shadow landing
state and fail-closed unsigned-enforcement boundary only.
