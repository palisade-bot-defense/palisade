# PALISADE business product specification

Status: first sellable product definition, 27 August 2026.

This document separates what the open-source product can do now from the
services and managed operations PALISADE can offer to design partners. It is a
product contract, not a claim that every planned commercial capability is
already generally available.

## 1. Problem

Security and platform teams need to reduce scraping, abusive automation and
high-cost scripted actions without locking legitimate people or useful bots out.
Request-level browser traits are no longer a dependable human/bot separator,
while opaque managed products can make enforcement difficult to explain,
measure or reverse.

PALISADE addresses the operational gap between receiving imperfect signals and
making a defensible live response. It keeps automation, abuse intent and session
continuity separate, measures in shadow first and requires explicit operator
approval before risky actions reach traffic.

## 2. Product promise

> Move from private shadow evidence to explainable, reversible bot protection.

The promise is deliberately narrower than “detect every bot.” PALISADE gives a
team a controlled decision loop:

```text
bounded signals -> shadow decisions -> encrypted outcomes -> aggregate analysis
       -> operator review -> signed canary -> measured enforcement or rollback
```

## 3. Buyers and users

### Economic buyer

- Head of Security, Platform or Infrastructure at an online business with a
  measurable automation problem.
- CTO at a smaller content, marketplace, SaaS or API business that needs
  protection without adopting a raw-traffic surveillance platform.

### Daily users

- Platform engineer integrating the origin adapter and operating the service.
- Security engineer reviewing evidence, policy and rollout scope.
- Product or support owner monitoring abandonment and customer impact.
- Privacy or compliance reviewer confirming collection and retention boundaries.

### Initial fit

- Public content scraping with identifiable business cost.
- API and expensive-compute abuse.
- Sign-up or trial abuse where delayed outcomes exist.
- High-value actions that can support a progressive response and fallback.

Account, login, payment and checkout enforcement remain excluded until identity,
support and false-positive evidence satisfy stricter gates.

## 4. Commercial product line

### Palisade Core — available now

Self-hosted open-source control plane for teams that own integration and
operations.

- AGPL-3.0-only server, dashboard, policies and tooling.
- Apache-2.0 browser sensor.
- Decision API, Go origin middleware and accessible bound challenge lifecycle.
- Encrypted append-only shadow measurement, aggregate analysis and signed
  rollout controls.
- Community documentation and security reporting process.

Core is the acquisition and trust layer: prospects can inspect the complete
decision path before buying services.

### Palisade Pilot — design-partner offer

A scoped professional-services engagement for one protected workflow and a
bounded traffic cohort.

Deliverables:

1. threat, endpoint and trusted-proxy boundary workshop;
2. same-origin sensor or origin-adapter integration;
3. shadow deployment and retention/runbook review;
4. aggregate baseline report including coverage, unknown labels and limitations;
5. detector/policy recommendation with an explicit hold option;
6. if gates pass, a small signed canary, rollback command and review report.

The pilot does not promise that enforcement will be recommended. “Collect more
evidence” is a valid result.

### Palisade Managed — early access

A dedicated single-tenant deployment operated for a customer. The initial
managed offer is intentionally not a multi-tenant telemetry cloud.

- Isolated runtime and customer-specific encryption/signing keys.
- Deployment-local encrypted decision and outcome storage.
- Managed upgrades, health monitoring, retention and backup policy.
- Scheduled aggregate policy review and canary/rollback support.
- Customer-controlled integration and outcome provenance.

Before general availability this offer still requires production automation,
support coverage, recovery objectives, a DPA/data-processing model, regional
hosting choices, audit logs, SSO/RBAC and a published SLA.

### Commercial licensing and enterprise support

Alternative licensing, integration engineering and support may be contracted
separately. They do not revoke or narrow the AGPL-3.0-only and Apache-2.0 rights
already granted for published code. Contract language must match `LICENSING.md`.

## 5. User stories

1. As a security engineer, I want to observe computed actions without changing
   live traffic so that I can evaluate risk before enforcement.
2. As a platform engineer, I want a closed origin response contract so that the
   application can apply pass, throttle, challenge or temporary block safely.
3. As a privacy reviewer, I want raw values excluded and local retention bounded
   so that bot defense does not become an uncontrolled identity dataset.
4. As an operator, I want recommendations separated from activation so that no
   analysis job can silently start blocking customers.
5. As a support owner, I want an accessible fallback and rollback path so that
   legitimate users are not trapped by a step-up.
6. As a self-hosting customer, I want the same core used by the managed offer so
   that I can change operating models without replacing the decision system.
7. As a managed customer, I want a dedicated deployment and customer-specific
   keys so that another tenant cannot become part of my data boundary.

## 6. Requirements

### P0 — sellable pilot

- The public website describes Core, Pilot and Managed with explicit availability
  labels and no unverified detection, SLA or compliance claims.
- A private contact/scheduling URL can be supplied at build time without placing
  credentials or customer information in the repository.
- The pilot uses the current shadow log, analyzer, signed rollout and origin
  adapter as one documented operating loop.
- Every engagement starts with an endpoint and signal-boundary review.
- Customer raw logs and identifiers remain on the authorized host; reports shared
  for review are aggregate and purpose-limited.
- Canary activation always requires human review, expiry, endpoint scope and a
  tested rollback.
- The service proposal records current exclusions, ownership, retention,
  availability behavior and support responsibility.

Acceptance criteria:

- Given no private contact URL is configured, the website does not invent an
  email address or claim a private channel exists.
- Given a prospect reads the deployment section, Core is marked available,
  Pilot design-partner and Managed early access.
- Given a risky shadow recommendation, the live action remains allow/observe.
- Given a pilot cannot establish outcome quality, no enforcement plan is issued.

### P1 — repeatable managed beta

- Versioned deployment bundle with single-tenant infrastructure templates.
- Exportable health, aggregate decision and drop metrics without raw records.
- Operator authentication, RBAC and immutable administrative audit events.
- Backup/restore procedure for configuration and key metadata without exporting
  customer telemetry by default.
- Customer-visible service status, incident process and defined recovery targets.
- Contracted support channel and onboarding/offboarding runbook.

### P2 — scalable platform

- Atomic shared challenge/session state for multi-replica deployments.
- Tenant control plane separated from tenant data planes.
- Regional placement, SSO/SCIM, billing and entitlement management.
- Signed independently deployable detector and policy bundles.
- Privacy-preserving fleet health that does not centralize raw traffic evidence.

## 7. Non-goals

- Universal or perfect bot detection.
- A cross-customer fingerprinting or reputation identity graph.
- Uploading customer raw logs into a central PALISADE account.
- Fully automatic promotion from analysis to blocking.
- Multi-tenant hosting before isolation, keys, RBAC, audit and recovery are proven.
- Blocking account/login/checkout traffic in the initial design-partner pilot.

## 8. Success metrics

### Product safety

- 100% of risky live rollouts reference a valid, unexpired signed plan.
- 100% of pilots document rollback and availability behavior before canary.
- Zero raw customer records in Git, public issues, central product analytics or
  sales artifacts.
- p95 in-process decision overhead remains below the documented 10 ms pilot gate.

### Customer value

- Time from integration start to first shadow decision: target under one day for
  the reference Go adapter; stretch under two hours.
- Time from retained evidence to aggregate report: target under 30 minutes of
  operator work.
- At least 80% of pilot decisions carry usable stable reason codes; unknown
  outcome coverage is always reported rather than hidden.
- Every canary report includes completion/abandonment or an explicit statement
  that the endpoint cannot yet measure it.

### Business learning

- Three qualified design partners complete the boundary workshop.
- Two reach a 24-hour shadow baseline.
- At least one chooses a paid pilot or managed beta after reviewing measured
  results.
- Record why prospects choose self-hosted, service or managed operation; do not
  infer demand for multi-tenancy from general interest.

These are launch hypotheses, not current achievements.

## 9. Operating architecture

```text
customer traffic
      |
trusted origin adapter ---- browser sensor
      |                           |
      +------ dedicated PALISADE data plane
                    | decision + challenge
                    | encrypted local shadow records
                    v
             aggregate analyzer
                    |
              operator review
                    |
           signed canary / rollback

optional managed control: deploy, update, health and reviewed configuration
prohibited managed flow: raw request/event/session records leaving tenant boundary
```

Core and Managed share the same data plane. A future management plane may
coordinate versions and aggregate health, but it must not silently become a raw
telemetry collector.

## 10. Open questions

### Blocking before public commercial launch

- **Founder/legal:** Which legal entity contracts Pilot and Managed work?
- **Founder:** What private email or scheduling URL should the website publish?
- **Legal:** Which name/trademark checks are complete for commercial use?
- **Operations/legal:** Which hosting regions, subprocessors, DPA and retention
  options can be promised?
- **Operations:** What support hours, availability target and recovery objective
  are actually staffed?
- **Commercial:** Is the first pilot fixed-scope, time-and-materials or credited
  toward a managed subscription?

### Non-blocking during design-partner work

- Which endpoint class produces the clearest measurable customer value?
- Which origin integrations should follow the Go reference adapter?
- Which aggregate metrics are useful across customers without creating a shared
  identity or raw-data layer?

## 11. Phased delivery

1. **Now:** publish the honest product site, configure a private contact channel
   and sell a single-workflow design-partner pilot.
2. **Pilot repeatability:** package deployment, metrics, runbooks and engagement
   templates; complete two shadow baselines.
3. **Managed beta:** operate dedicated single-tenant deployments with contracted
   support, recovery and data-processing terms.
4. **General availability:** only after RBAC, audit, SSO, infrastructure
   automation, incident response and SLA evidence exist.
