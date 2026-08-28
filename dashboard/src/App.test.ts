import { describe, expect, it } from "vitest";

import { collectionRateLabel, collectionStateCopy, countComparableCanaries, explainReason, formatInterval, originCoverageCopy, outcomeFlowCopy, scoreEvidenceState } from "./App";

describe("aggregate endpoint evidence", () => {
  it("does not invent an interval for an absent sample", () => {
    expect(formatInterval({ count: 0, total: 0, rate: 0, lower_95: 0, upper_95: 0 })).toBe("no sample");
  });

  it("labels a populated interval and counts only comparable canaries", () => {
    expect(formatInterval({ count: 10, total: 100, rate: 0.1, lower_95: 0.055, upper_95: 0.174 })).toContain("95%");
    expect(countComparableCanaries([{ comparable: true }, { comparable: false }, { comparable: true }])).toBe(2);
  });

  it("explains known and future stable reason codes without exposing rows", () => {
    expect(explainReason("NAVIGATION_SURFACE_SWEEP")).toContain("endpoint classes");
    expect(explainReason("FUTURE_REASON_CODE")).toContain("versioned rule");
  });

  it("does not present the neutral prior as measured intent risk", () => {
    expect(scoreEvidenceState({ minimum: 0.5, maximum: 0.5, mean: 0.5 })).toContain("No evidence observed");
    expect(scoreEvidenceState({ minimum: 0.2, maximum: 0.8, mean: 0.55 })).toContain("Observed range");
  });

  it("does not turn an internal collection funnel into site traffic coverage", () => {
    const collection = {
      state: "collecting" as const, traffic_denominator: "external_total_unavailable" as const,
      context_proofs_issued: 12, accepted_event_batches: 10, recorded_shadow_decisions: 9,
      rejected_before_ingest: 1, dropped_after_ingest: 1, batch_recording_rate: 0.9,
      endpoint_context_proofs: [{ endpoint_class: "public_content", count: 12 }],
    };
    expect(collectionRateLabel(collection)).toContain("accepted batches");
    expect(collectionStateCopy(collection)).toContain("not a site-traffic coverage claim");
  });

  it("shows missing samples and degraded collection explicitly", () => {
    const base = {
      traffic_denominator: "external_total_unavailable" as const, context_proofs_issued: 0,
      accepted_event_batches: 0, recorded_shadow_decisions: 0, rejected_before_ingest: 0,
      dropped_after_ingest: 0, batch_recording_rate: 0, endpoint_context_proofs: [],
    };
    expect(collectionRateLabel({ ...base, state: "no_samples" })).toBe("no accepted batch sample");
    expect(collectionStateCopy({ ...base, state: "degraded" })).toContain("investigate");
  });

  it("bounds authenticated coverage to the protected handler", () => {
    const coverage = {
      state: "collecting" as const, scope: "protected_handler_requests" as const,
      traffic_denominator: "authenticated_origin_reports" as const, sources: 1,
      observed_since: "2026-08-28T12:00:00Z", last_reported_at: "2026-08-28T12:01:00Z",
      protected_requests: 10, evaluated_requests: 9, bypassed_requests: 0, rejected_requests: 0,
      granted_retries: 1, decision_coverage_rate: 1, endpoints: [],
    };
    expect(originCoverageCopy(coverage)).toContain("configured protected handler");
    expect(originCoverageCopy({ ...coverage, state: "unavailable" })).toContain("No authenticated");
    expect(originCoverageCopy({ ...coverage, state: "degraded", bypassed_requests: 1 })).toContain("bypassed");
  });

  it("does not present accepted outcome events as ground-truth labels", () => {
    expect(outcomeFlowCopy({ state: "collecting", accepted: 10, rejected: 0, dropped: 0 })).toContain("events");
    expect(outcomeFlowCopy({ state: "degraded", accepted: 10, rejected: 1, dropped: 0 })).toContain("incomplete");
  });
});
