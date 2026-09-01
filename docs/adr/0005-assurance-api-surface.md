# ADR 0005: Carry assurance on a separate versioned surface

Status: accepted

Every remaining proof-of-human roadmap item needs the same thing: a way for an assurance assertion, an interactive liveness challenge or a device attestation to cross the HTTP boundary. All of them are blocked by one rule and one fact.

The rule is [`docs/COMPATIBILITY.md`](../COMPATIBILITY.md): adding an enum value, a required or optional field, an endpoint or a protobuf field to a frozen contract requires a new contract version "unless the specific contract already defines an extension mechanism." The fact is that `api/openapi.yaml` defines none — all forty of its objects are closed with `additionalProperties: false`, and the six protobuf files are frozen with hash-pinned entries in the compatibility freeze.

Adding an extension mechanism to v1 does not escape this: the mechanism itself is an added field.

## Options

**A. New version of the whole HTTP surface.** Move to `/v2/decision` and a v2 protobuf package. Correct, and disproportionate: it forces every adapter to migrate for one optional field, and the decision contract itself is not changing.

**B. Separate versioned surface for assurance.** Add `api/openapi-assurance-v1.yaml` with its own endpoints and its own frozen identifier. `/v1/decision` is untouched, so existing adapters are unaffected and need no migration. An adapter that wants an assertion asks for one, naming its audience.

**C. Out-of-band carriage.** Response headers or a side channel on the existing endpoints. Rejected: a declared response header is part of the same frozen contract, so this is option A with less clarity.

## Decision

Option B. It is what the compatibility policy already prescribes for a semantic addition — "a new schema/contract identifier and file rather than in-place replacement" — applied to the transport rather than to a schema. It also matches the protocol boundary: assurance is a separate concern from the risk decision, and a deployment may run one without the other.

Consequences:

- assurance is opt-in per deployment and per relying service, so a deployment that wants none carries no new data class;
- the audience is supplied by the caller, which is required anyway: the session commitment is derived per audience so two relying services cannot link the same visitor;
- the new surface needs its own conformance fixtures, and the same privacy and failure-policy suite required of transport adapters;
- the data map gains a flow and the runtime egress inventory gains a data class **in the same change that adds the emission**, never before it, so the map never records a flow that does not exist;
- `/v1/decision`, its protobuf contract and every existing adapter remain byte-identical.

## Implemented

`POST /v1/assurance` is live behind `api/openapi-assurance-v1.yaml`. It evaluates the same normalized request the risk surface would and returns only the assertion; scores, evidence, enforcement actions and the decision identifier are not reflected. The surface is disabled unless a signing key, a binding secret and at least one allowed audience are all configured, and an unlisted audience is refused rather than minted.

Data map v7 records the flow and the runtime egress inventory records the class, in the same change that added the emission.

## What is still blocked, and on what

Not on this decision. The interactive liveness challenge that H2 requires is a missing mechanism, not a missing contract: the existing challenge is proof of work. Device attestation for H3 and issuer credentials for H4 now have a surface to arrive on and a trust root to be checked against, but no verifier. The per-level false-positive and abandonment measurement needs deployments emitting assertions first.
