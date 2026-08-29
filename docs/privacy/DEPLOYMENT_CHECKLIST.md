# EU privacy deployment checklist

This checklist helps a deployment operator review PALISADE. It is not legal
advice, a certification or a statement that a particular deployment is lawful.
The operator remains responsible for its purposes, configuration, notices,
retention and legal basis and should obtain qualified review where needed.

## 1. Describe the processing before enabling it

- Name the controller, protected service, security purpose and affected user
  groups.
- Inventory every enabled source: origin request classes, first-party session
  cookie, browser event counts, edge fingerprint class, network reputation,
  challenge outcomes and application outcomes.
- Record which system sees raw IP, ASN, JA4/JA3, HTTP/2 fingerprint or vendor
  reputation data. PALISADE itself should receive only the closed normalized
  classes in the public API contract.
- Document recipients, processors, locations, retention, access roles,
  deletion procedure and incident contact in the operator's processing record.

## 2. Choose and document a GDPR legal basis

Do not state that security processing is automatically covered by legitimate
interests. If relying on Article 6(1)(f) GDPR, document before deployment:

1. the lawful, specific, real and present security interest;
2. why each enabled field is necessary and why a less intrusive alternative is
   not equally effective; and
3. the balancing of user impact, reasonable expectations, children or other
   vulnerable users, safeguards and the right to object.

The operator must also provide the required transparency information, handle
applicable data-subject rights and reassess the balance when sources, purposes
or enforcement actions change. The EDPB describes these as cumulative
conditions, not a blanket fraud-prevention exemption.

Primary sources:

- [GDPR Article 6(1)(f)](https://eur-lex.europa.eu/eli/reg/2016/679/art_6/par_1/pnt_f/oj)
- [EDPB Guidelines 1/2024 on legitimate interests](https://www.edpb.europa.eu/public-consultations/guidelines-12024-on-processing-of-personal-data-based-on-article-61f-gdpr_en)

## 3. Assess the browser sensor and first-party cookie separately under TDDDG

Section 25 TDDDG starts from consent for storing information in, or accessing
information already stored in, terminal equipment. Its exceptions are narrow:
message transmission, or storage/access strictly necessary to provide a digital
service expressly requested by the user.

Before enabling the browser sensor or `__Host-palisade_session`, record for each
browser API and storage operation:

- what is stored or accessed on the terminal;
- whether it is strictly necessary for the requested service or instead needs
  consent;
- whether the same security purpose can be met server-side with less terminal
  access;
- how the site behaves before consent, after refusal and after withdrawal; and
- whether sensor absence remains neutral and the service stays accessible.

PALISADE deliberately does not encode an answer to this legal assessment. The
first-party, Secure, HttpOnly session cookie and the content-free sensor design
reduce risk, but they do not by themselves prove that an exception applies.

Primary source: [§ 25 TDDDG](https://www.gesetze-im-internet.de/ttdsg/__25.html).

## 4. Apply privacy by design in configuration

- Keep Shadow mode and local encrypted logging as the default.
- Do not send raw IPs, ASNs, user agents, DNS names, fingerprints, paths,
  queries, bodies, cookies or vendor payloads to PALISADE runtime APIs. The
  generic local importer has the narrow, filesystem-only reference exception
  documented below and in its contract.
- Use the shortest justified in-memory, shadow-log and backup retention.
- Keep keys and logs owner-only, outside Git worktrees and separate from shared
  exports.
- Treat every `import-local-events` input and normalized shard as potentially
  personal data. Document the adapter mapping, key custody, daily pseudonym
  rotation, approved linkage window and deletion of inputs, outputs and
  backups. Pseudonymization is not anonymization.
- Treat local sequence reports as private operational data even though they
  contain no row-level event or pseudonym. Restrict report access, choose a
  deletion period and never publish a report without a separate disclosure
  review of its aggregate time ranges, volumes and labels.
- Limit operator-console and report access; never expose the demo container
  admin listener beyond host loopback.
- Keep `sensor_missing` neutral. Do not disadvantage consent refusal merely by
  mapping absence to suspicion.
- Provide an accessible fallback, appeal or support path before challenge or
  blocking can be enabled.

## 5. Complete the release review

- Perform a DPIA screening, especially where the deployment could amount to
  systematic monitoring, affect access to important services or combine
  multiple high-risk signals. Escalate a likely high-risk deployment for a
  formal DPIA and qualified review.
- Test access, objection, deletion and retention workflows against the actual
  systems holding session links, outcomes and raw edge data.
- Verify processor agreements and international-transfer safeguards for every
  external reputation, hosting, monitoring or support provider.
- Publish a deployment-specific notice that describes actual processing rather
  than copying this generic checklist.
- Record the approval, policy/model versions, enabled sources, thresholds,
  evaluation window, known limitations and rollback owner.

Any change to browser collection, identity linkage, raw-data boundaries,
retention, external providers or enforcement scope requires a new privacy and
security review.
