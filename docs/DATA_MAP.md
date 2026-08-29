# Machine-readable data map

The versioned [PALISADE data map](../manifests/data-map-v1.json) records the
reference product's accepted data classes, destinations, network scopes and
persistence modes. Its JSON Schema is
[`schemas/data-map-v1.schema.json`](../schemas/data-map-v1.schema.json).

The v1 map covers nine flows:

1. bounded browser-event ingestion;
2. trusted normalized decision requests;
3. the signed first-party continuity cookie;
4. the same-origin native challenge lifecycle;
5. optional encrypted shadow decisions;
6. delayed closed outcome labels;
7. local aggregate analysis;
8. the loopback Operator Console summary;
9. the non-identifying Sovereignty Report.

Every mapped flow has `external_export: false`. That field means PALISADE does
not export the flow to a PALISADE-operated external service. It does not override
the operator's surrounding monitoring, backup, proxy or hosting configuration.

The map separately lists prohibited raw classes including IP addresses, ASNs,
URLs, request bodies, user-agent strings, TLS fingerprints, vendor payloads,
form content, DOM text, keystrokes and exact pointer paths. Closed classes
derived transiently at a trusted adapter may enter the decision contract; their
raw source values may not.

`TestDataMapIsClosedAndContainsNoRawAcceptedClass` rejects duplicate flows,
external-export flags, missing boundaries and any raw excluded class that is
also declared as accepted. Changes to collection, persistence, retention or
export must update the map, schema, privacy documentation and tests in the same
commit.

The data map is technical documentation, not a record of processing activities,
DPIA or legal-basis assessment. Operators must add their real infrastructure,
processors, recipients, retention decisions and data-subject procedures to
their own compliance records.
