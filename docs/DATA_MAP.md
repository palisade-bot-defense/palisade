# Machine-readable data map

The current versioned [PALISADE data map](../manifests/data-map-v2.json) records the
reference product's accepted data classes, destinations, network scopes and
persistence modes. Its JSON Schema is
[`schemas/data-map-v2.schema.json`](../schemas/data-map-v2.schema.json). The
original [v1 map](../manifests/data-map-v1.json) remains available as an
immutable record of the pre-generic-import boundary.

The v2 map covers ten flows:

1. bounded browser-event ingestion;
2. trusted normalized decision requests;
3. the signed first-party continuity cookie;
4. the same-origin native challenge lifecycle;
5. optional encrypted shadow decisions;
6. delayed closed outcome labels;
7. local aggregate analysis;
8. the loopback Operator Console summary;
9. the generic local evidence import; and
10. the non-identifying Sovereignty Report.

Every mapped flow has `external_export: false`. That field means PALISADE does
not export the flow to a PALISADE-operated external service. It does not override
the operator's surrounding monitoring, backup, proxy or hosting configuration.

The map separately lists prohibited runtime and persisted raw classes including IP addresses, ASNs,
URLs, request bodies, user-agent strings, TLS fingerprints, vendor payloads,
form content, DOM text, keystrokes and exact pointer paths. Closed classes
derived transiently at a trusted adapter may enter the decision contract; their
raw source values may not.

Data Map v2 adds one explicit exception at a different boundary: the local
evidence importer may read an operator subject and session reference from an
owner-only input file solely to derive daily rotating pseudonyms. Those two
transient classes are listed separately on the flow and at the document root.
They never enter the runtime decision service or persisted normalized output.
The input file remains operator-controlled personal data; pseudonymized output
is still potentially personal data and is not publication-ready.

`TestDataMapIsClosedAndContainsNoRawAcceptedClass` rejects duplicate flows,
external-export flags, missing boundaries and any raw excluded class that is
also declared as accepted. Changes to collection, persistence, retention or
export must update the map, schema, privacy documentation and tests in the same
commit.

The data map is technical documentation, not a record of processing activities,
DPIA or legal-basis assessment. Operators must add their real infrastructure,
processors, recipients, retention decisions and data-subject procedures to
their own compliance records.
