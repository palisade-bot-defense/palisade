# ADR 0005: Carry assurance on a separate versioned surface

Status: proposed

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

This ADR does not authorize the work. It records that the blocker is a contract-versioning decision rather than an implementation detail, and which option this repository's own policy points to.

## What stays blocked until this is decided

The H1 assertion in the decision path, the interactive liveness challenge type that H2 requires, device attestation for H3, and the per-level false-positive and abandonment measurement that gates any surface above H1. The offline work each of them depends on — the assertion contract, the derivation, the issuer trust list and agent provenance — is implemented and needs no contract change.
