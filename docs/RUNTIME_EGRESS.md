# Runtime egress inventory

PALISADE keeps a machine-readable inventory of every reviewed outbound runtime
network path in the reference repository:

- [`manifests/runtime-egress-v1.json`](../manifests/runtime-egress-v1.json)
- [`schemas/runtime-egress-v1.schema.json`](../schemas/runtime-egress-v1.schema.json)

The default posture is `no_mandatory_vendor_egress`. This means no reference
component requires a PALISADE-operated account, control plane, telemetry
collector or external intelligence service. It does not mean the host operating
system or operator-selected surrounding infrastructure has no network traffic.

## Reviewed paths

| Initiator | Destination | Activation | Boundary |
|---|---|---|---|
| Reference Go origin adapter | Operator-configured PALISADE base URL | Operator enables the adapter | Non-loopback plain HTTP is rejected; remote endpoints require HTTPS. The adapter sends closed requests, required backend credentials and opaque capabilities only, including the server-only origin-flow binding required for challenge redemption. |
| Browser sensor | Relative operator same-origin event path | Operator embeds the sensor | Absolute, protocol-relative, query-bearing and fragment-bearing endpoints are rejected. Custom browser code remains outside the reference boundary. |
| Native challenge page | Relative same-origin challenge path | A measured policy returns `challenge` | Embedded browser code retrieves closed metadata and exchanges one-time verification/redemption capabilities. It has no configurable external destination. |
| Operator Console | Same-origin loopback admin listener | Local operator opens the console | The server refuses a public admin listener outside the explicit synthetic container demo exception. Only aggregate summaries are returned. |

The Go decision service itself has no outbound runtime client. Crawler registry
updates, policies, analysis reports and rollout artifacts are loaded from local
operator-controlled files; request handling performs no vendor or reverse-DNS
lookup.

## Regression gate

`TestRuntimeEgressManifestMatchesReviewedSourceCallsites` parses all non-test Go
source and scans production TypeScript source for outbound network primitives.
The test contains a narrow reviewed allowlist and compares its files with the
manifest's `source_paths`. Adding a new HTTP client, `fetch`, beacon, WebSocket,
event source or XHR call fails the test until all of the following are reviewed
together:

1. destination and transport security;
2. activation and failure behavior;
3. exact data and credential classes;
4. raw-identifier and content exclusions;
5. the runtime manifest, data map, documentation and relevant tests.

This is a source-level tripwire, not a formal proof that arbitrary dependencies
or operator code cannot open a socket. Deployment verification should combine
the inventory with firewall policy, DNS and flow logs, packet capture where
appropriate, and a review of hosting and processor relationships.
