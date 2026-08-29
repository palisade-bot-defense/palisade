# Origin adapter conformance

`palisade.origin-adapter.v1` is the portable contract for an HTTP origin
middleware that consumes PALISADE decisions. The canonical synthetic suite is
[`examples/conformance/origin-adapter-v1.json`](../examples/conformance/origin-adapter-v1.json),
and its closed schema is
[`schemas/origin-adapter-conformance-v1.schema.json`](../schemas/origin-adapter-conformance-v1.schema.json).
The OpenAPI document remains authoritative for the PALISADE HTTP wire format;
the protobuf decision messages carry the same normalized request and decision
semantics for non-HTTP integrations.

The suite is intentionally independent of production traffic, private
infrastructure and a PALISADE-operated service. Every value is synthetic. An
adapter implementation can run it against an in-process fake service and may
publish the resulting local test output without publishing deployment data.

## Harness protocol

For every scenario, a harness must:

1. Configure the adapter with the scenario's explicit `failure_mode` and closed
   classification.
2. Expose a synthetic PALISADE service that issues one valid Secure,
   HttpOnly `__Host-palisade_session` cookie, returns one bounded proof token,
   and then returns the exact `service_response` from `/v1/origin-check`.
3. Send the declared method to a synthetic protected route. The request should
   contain unique sentinel values in its path, query, body, User-Agent and an
   application cookie.
4. Compare status, downstream invocation count and every declared response
   header with `expected`. When `error_code` is non-empty, decode only the
   adapter's closed JSON error object and compare its `error` field.
5. Assert that none of the application sentinels occur in a service request
   body or forwarded header. PALISADE continuity cookies, the closed action,
   endpoint class, cohort and normalized observations are expected service
   inputs and are not application-cookie forwarding.

The exact nine scenario IDs are part of v1. A harness must reject unknown
fields, duplicate IDs, missing IDs, non-empty service bodies and values outside
the schema. Passing only a subset is not conformance.

## Covered behavior

The suite covers shadow pass-through, signed delay and throttle, non-GET
challenge metadata without request replay, a bounded temporary block, explicit
outage behavior in both failure modes and malformed risky-shadow behavior in
both failure modes. Local classifier and signal-provider failures are also
required to fail closed by the normative adapter guide, but are implementation
unit tests rather than portable service-response fixtures.

A pass certifies only the v1 middleware contract. It does not certify a
deployment, detector accuracy, challenge accessibility in a specific frontend,
proxy trust configuration or production availability. Certification must name
the adapter implementation and commit, suite schema version, runtime and test
date. Do not attach request captures or production logs.

## Reference implementations

Both independent Go adapters execute the canonical file directly:

- `pkg/palisadehttp/conformance_test.go` covers the in-process origin
  middleware with the accessible challenge lifecycle;
- `pkg/palisadeproxy/conformance_test.go` covers the standalone handler-based
  reverse-proxy adapter without calling the middleware implementation.

Run both:

```sh
make adapter-conformance
```

Community adapters should consume the JSON file directly rather than copying
its cases into a private format. Proposed v1 changes must remain additive or
be released as a new contract and suite version.
