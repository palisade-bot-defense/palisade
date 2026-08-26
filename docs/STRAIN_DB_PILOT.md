# Strain DB shadow pilot

## Inputs

The pilot will consume normalized fields rather than raw logs:

- Request/session sequence, coarse timing and endpoint class.
- Anubis verdict and challenge outcome.
- Cannai Shield normalized risk score and reason category.
- CrowdSec scenario/alert boolean at decision time.
- PALISADE decoy interactions and proof-token outcomes.
- Delayed outcome label such as successful account action, scraper-confirmed, operator-reviewed or unknown.

The exact Anubis/Cannai export supplied later must first be mapped and audited. Do not copy the 413 GB source corpus into Git, CI or developer laptops by default.

## Pipeline

1. Read locally from the authorized export using an append-only importer.
2. Remove request bodies, cookies, authorization, query strings and direct account/network identifiers.
3. Pseudonymize session linkage with a pilot-specific rotating key.
4. Emit versioned JSONL/Parquet shards plus a manifest containing schema, counts, time range and hashes.
5. Replay shadow decisions and aggregate metrics; never print row-level production data in normal logs.

## First hypotheses

- Anubis bot plus CrowdSec alert should strongly increase automation and intent respectively.
- Decoy interaction plus an external abuse verdict may support a narrow block policy.
- Consistent browser events should improve continuity, but must never override strong intent evidence.
- Missing browser telemetry is unknown, not automatically malicious.
- Verified beneficial bots require identity verification and an allow policy independent of browser behavior.

## Safety controls

Start with `allow`/`observe` output only. Run the importer read-only, cap memory and shard sizes, record deletion/retention rules and make every threshold change replayable. Canary enforcement requires an explicit operator approval outside PALISADE.
