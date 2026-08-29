# Normalized signal contract

`palisade.normalized-signal-contract.v1` is the closed semantic boundary shared
by the HTTP decision API, protobuf messages, PALISADE runtime and origin
adapters. Its language-neutral catalog is
[`api/contracts/normalized-signal-v1.json`](../api/contracts/normalized-signal-v1.json),
with a closed schema at
[`schemas/normalized-signal-contract-v1.schema.json`](../schemas/normalized-signal-contract-v1.schema.json).
Go integrations may use [`pkg/palisadecontract`](../pkg/palisadecontract).

The catalog is the portable value vocabulary. Repository tests require its
sets to match the Go validators, every OpenAPI enum and every typed protobuf
enum. A drift in any one representation fails `go test ./...`.

## Boundary

The contract accepts only deployment-independent classes. It never accepts a
URL, query, request body, User-Agent, address, ASN, raw TLS or HTTP/2
fingerprint, vendor label or provider score. A trusted local adapter must map
its source into the closed classes before calling PALISADE and reject values it
cannot map. Hashing a forbidden raw value does not make it a normalized class.

`events` is a special proof action for browser-event ingestion. It is not a
valid `DecisionRequest.action`. Normal decision actions describe the protected
operation, while endpoint classes describe its deployment-independent value
and exposure. Both are derived from trusted route configuration, never client
parameters.

Optional normalized classes may be omitted at the JSON boundary and then mean
`unknown`; an explicit empty string is not a published enum value. Protobuf
zero values map to `unknown` for optional observations and cohorts. Required
protobuf request action and endpoint values use `UNSPECIFIED = 0`, which a
server must reject. Protobuf symbols use the enum name as an uppercase prefix;
for example, catalog value `trusted_proxy_tls` maps to
`TRANSPORT_SECURITY_TRUSTED_PROXY_TLS`. This is a semantic mapping, not a claim
that protobuf JSON uses the lowercase HTTP spelling.

Cross-field invariants are part of v1:

- a positive verified-crawler claim requires a non-unknown crawler class and
  non-unknown verification method;
- a known edge-fingerprint class and method must appear together;
- client-claimed browser-event counts remain neutral until replaced by the
  bounded server-side event store;
- a passed challenge is an outcome, not proof of a person;
- low-risk, residential or browser-consistent context never creates human or
  benign-intent evidence by itself.

## Compatibility policy

The current protobuf files described future typed transport and had no public
gRPC server or generated client release. v1 therefore replaces their draft
string fields with typed enums before the first compatibility promise. From
this contract onward, removing, renaming or reinterpreting a value requires a
new contract version. Adding a value also requires a new version because older
fail-closed adapters must reject an unknown value rather than silently map it.
Field numbers and meanings remain fixed within a version.

Run the complete local drift gate with:

```sh
make normalized-contract
```

The gate validates only contract consistency and closed semantics. It does not
establish detector accuracy, source authenticity or deployment readiness.
