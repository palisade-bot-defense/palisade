# Machine-readable data map

The current versioned [PALISADE data map](../manifests/data-map-v5.json) records the
reference product's accepted data classes, destinations, network scopes and
persistence modes. Its JSON Schema is
[`schemas/data-map-v5.schema.json`](../schemas/data-map-v5.schema.json). The
[v1](../manifests/data-map-v1.json), [v2](../manifests/data-map-v2.json) and
[v3](../manifests/data-map-v3.json) and [v4](../manifests/data-map-v4.json) maps remain immutable records of earlier
boundaries.

The v5 map covers thirteen flows:

1. bounded browser-event ingestion;
2. trusted normalized decision requests;
3. the signed first-party continuity cookie;
4. the same-origin native challenge lifecycle;
5. the backend-authenticated native decoy-capability lifecycle;
6. optional encrypted shadow decisions;
7. delayed closed outcome labels;
8. local aggregate analysis;
9. the generic local evidence import;
10. bounded local aggregate sequence analysis;
11. local chronological and optional unseen-family holdout evaluation;
12. the loopback Operator Console summary; and
13. the non-identifying Sovereignty Report.

Every mapped flow has `external_export: false`. That field means PALISADE does
not export the flow to a PALISADE-operated external service. It does not override
the operator's surrounding monitoring, backup, proxy or hosting configuration.

The map separately lists prohibited runtime and persisted raw classes including IP addresses, ASNs,
URLs, request bodies, user-agent strings, TLS fingerprints, vendor payloads,
form content, DOM text, keystrokes and exact pointer paths. Closed classes
derived transiently at a trusted adapter may enter the decision contract; their
raw source values may not.

Data Map v2 added one explicit exception at a different boundary: the local
evidence importer may read an operator subject and session reference from an
owner-only input file solely to derive daily rotating pseudonyms. Those two
transient classes are listed separately on the flow and at the document root.
They never enter the runtime decision service or persisted normalized output.
The input file remains operator-controlled personal data; pseudonymized output
is still potentially personal data and is not publication-ready.

Data Map v3 adds the follow-on sequence-analysis flow. Daily pseudonyms are
used transiently to associate events inside fixed five-minute/15-minute windows,
but only aggregate feature and evidence-lane counts are persisted in the
sequence report. No subject/session pseudonym or row-level event is a report
data class. The report remains owner-only because aggregate activity volume and
time ranges may still reveal operational information.

Data Map v4 adds local holdout evaluation. An optional owner-only annotation
file supplies normalized daily sequence pseudonyms and an operator attack/tool
family reference. Both are transient; the evaluator retains domain-separated
digests for equality within one run and persists only family counts plus the
annotation-file fingerprint. No sequence pseudonym or family reference appears
in the report. The annotation input and aggregate report remain private
operator artifacts.

Data Map v5 adds the native decoy lifecycle. A trusted origin handler requests
an opaque, short-lived capability bound to a session handle, closed endpoint
class and closed surface class. PALISADE stores only the capability digest and
a digest of the session handle. A consumed capability creates one bounded
`touched|submitted` evidence event for the next matching decision. URLs, form
fields, content, client addresses and user-agent values are outside the
contract.

The `aggregate_analysis` flow also covers chronological evaluation of the
encrypted shadow stream. That evaluator reuses the already mapped encrypted
decision/outcome records and persists only aggregate confidence intervals,
endpoint/cohort slices and closed readiness. It introduces no new accepted,
transient or exported data class; decision IDs remain in-memory digest keys and
never enter the report.

The runtime decision flow also derives saturating recent-enforcement and
premature-retry counts inside the existing five-minute session entry. They are
closed response-control state, never raw request data or identity evidence,
and are neither persisted nor exported.

`TestDataMapIsClosedAndContainsNoRawAcceptedClass` rejects duplicate flows,
external-export flags, missing boundaries and any raw excluded class that is
also declared as accepted. Changes to collection, persistence, retention or
export must update the map, schema, privacy documentation and tests in the same
commit.

The data map is technical documentation, not a record of processing activities,
DPIA or legal-basis assessment. Operators must add their real infrastructure,
processors, recipients, retention decisions and data-subject procedures to
their own compliance records.
