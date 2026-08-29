# Sovereignty Report

`palisade sovereignty-report` emits a deterministic JSON inventory that keeps
two different kinds of statement separate:

- **product invariants** describe the reviewed PALISADE reference service;
- **deployment declarations** are closed operator attestations that PALISADE
  cannot verify from inside its own process.

This separation prevents a product property such as “no mandatory PALISADE
telemetry” from being misrepresented as proof that a particular hosting,
monitoring or adapter setup is EU-only.

## Generate an incomplete baseline

```sh
go run ./cmd/palisade sovereignty-report
```

Undeclared fields produce `deployment_posture: insufficient_declaration`. This
is the safe default.

## Add a closed operator attestation

```sh
go run ./cmd/palisade sovereignty-report \
  --processing-location eu_region \
  --storage-location eu_only \
  --external-runtime-services none \
  --operator-held-keys yes
```

When every field supports the bounded posture, the report says
`operator_attested_eu_bound`. It does not say compliant, certified or legally
transfer-free. Values are intentionally closed enums; the report accepts no
customer name, domain, IP address, provider name, path or other free-form
deployment metadata.

The schema is
[`schemas/sovereignty-report-v1.schema.json`](../schemas/sovereignty-report-v1.schema.json).
Identical declarations and PALISADE versions produce identical JSON because the
report includes no timestamp, host name or process environment.

## Product invariants in v1

- no mandatory PALISADE vendor control plane;
- no mandatory telemetry export;
- no mandatory external runtime call from the reference decision service;
- closed normalized inputs at the public decision API;
- no raw network identifier field in that API;
- bounded browser counts without content or exact coordinates;
- optional local encrypted evaluation;
- stable decision reasons and versions;
- signed, scoped and expiring enforcement promotion.

These are architectural inventory statements, not proof derived from packet
capture. A future code change that introduces a mandatory service must update
the report, schema, documentation and regression tests in the same change.

## What still needs separate evidence

- the physical or contractual location of compute, backups and support access;
- reverse-proxy, reputation, monitoring, DNS, CDN and identity-provider flows;
- key custody and administrator access in the real deployment;
- retention jobs and deletion behavior outside PALISADE;
- legal basis, transparency, data-subject rights, processor contracts, DPIA and
  any ePrivacy/TDDDG terminal-access analysis.

Use the [EU privacy deployment checklist](privacy/DEPLOYMENT_CHECKLIST.md) for
the operator assessment. A network-flow capture, infrastructure inventory and
contract review remain necessary when the deployment needs stronger evidence.

## Threat boundary

The report is not signed in v1 and does not authenticate the operator. Anyone
can generate a declaration. It is useful as a reproducible inventory attached
to a reviewed deployment record, not as remote attestation. Signed build
provenance and operator attestations are roadmap work and must remain optional
for fully local operation.
