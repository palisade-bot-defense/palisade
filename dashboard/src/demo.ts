import type { Summary } from "./App";

const proportion = (count: number, total: number, lower = 0, upper = 0) => ({
  count, total, rate: total === 0 ? 0 : count / total, lower_95: lower, upper_95: upper,
});

export const createDemoSummary = (now: Date): Summary => ({
  schema_version: "palisade.admin-summary.v9",
  generated_at: now.toISOString(),
  uptime_seconds: 7540,
  runtime: { mode: "shadow", policy_version: "default-v5", model_version: "transparent-baseline-v13" },
  capabilities: { shadow_log: true, event_shadow: true, event_shadow_proof_contexts: true, analysis_report: true },
  traffic: {
    accepted_event_batches: 412, accepted_events: 2864, decisions: 480, origin_checks: 442,
    enforced: { allow: 0, observe: 480, delay: 0, throttle: 0, challenge: 0, block: 0 },
    computed: { allow: 188, observe: 154, delay: 32, throttle: 58, challenge: 42, block: 6 },
    reasons: [
      { code: "BASELINE_LOW_RISK", count: 188 }, { code: "EDGE_AUTOMATION_PROFILE", count: 76 },
      { code: "NETWORK_REPUTATION_ELEVATED", count: 51 }, { code: "STEP_UP_REQUIRED", count: 42 },
      { code: "SHADOW_ACTION_OVERRIDDEN", count: 138 },
    ],
  },
  recording: { decisions: 480, outcomes: 96, dropped: 0, event_shadow_dropped: 2 },
  collection: {
    state: "degraded", traffic_denominator: "external_total_unavailable", context_proofs_issued: 430,
    accepted_event_batches: 412, recorded_shadow_decisions: 410, rejected_before_ingest: 3,
    dropped_after_ingest: 2, batch_recording_rate: 410 / 412,
    endpoint_context_proofs: [{ endpoint_class: "public_content", count: 290 }, { endpoint_class: "login", count: 140 }],
  },
  origin_coverage: {
    state: "collecting", scope: "protected_handler_requests", traffic_denominator: "authenticated_origin_reports",
    sources: 1, observed_since: new Date(now.getTime() - 7_200_000).toISOString(), last_reported_at: now.toISOString(),
    protected_requests: 500, evaluated_requests: 442, bypassed_requests: 0, rejected_requests: 0,
    granted_retries: 4, decision_coverage_rate: 442 / 500,
    endpoints: [
      { endpoint_class: "public_content", protected_requests: 340, evaluated_requests: 310, bypassed_requests: 0, rejected_requests: 0, granted_retries: 2 },
      { endpoint_class: "login", protected_requests: 160, evaluated_requests: 132, bypassed_requests: 0, rejected_requests: 0, granted_retries: 2 },
    ],
  },
  outcome_flow: { state: "collecting", accepted: 96, rejected: 4, dropped: 0 },
  transport_posture: {
    state: "attention", scope: "evaluated_decisions", samples: 442,
    protocol: { http1: 94, http2: 338, http3: 0, unknown: 10 },
    security: { direct_tls: 0, trusted_proxy_tls: 432, plaintext: 0, unknown: 10 },
    address_source: { direct: 0, trusted_proxy: 432, invalid_trusted_proxy: 0, unknown: 10 },
  },
  crawler_identity: {
    state: "attention", scope: "evaluated_identity_observations", observations: 18, qualified_public: 15, unqualified: 3,
    classes: { search_indexer: 8, answer_engine: 5, training_crawler: 3, user_triggered_agent: 1, preview: 1, monitoring: 0, other: 0, unknown: 0 },
    verification: { ip_ua_registry: 14, fcrdns_ua: 3, http_signature: 1, unknown: 0 },
  },
  analysis_status: { state: "ready", loaded_at: now.toISOString(), last_attempt_at: now.toISOString() },
  analysis: {
    source: { first_at: new Date(now.getTime() - 7_200_000).toISOString(), last_at: now.toISOString(), decisions: 480, outcomes: 96 },
    readiness: { state: "collecting", operator_action: "remain_shadow", automatic_enforcement: false, reason_codes: ["COLLECT_MORE_DECISIONS", "IMPROVE_OUTCOME_COVERAGE", "EXPAND_CONFIRMED_HUMANS"] },
    decisions: { total: 480, computed_challenge_rate: 42 / 480 },
    outcomes: { total: 96, coverage: 0.2, human_confirmed: 24, operator_confirmed_abuse: 18, challenge_failure_rate: 0.125 },
    scores: {
      automation_risk: { minimum: 0.21, maximum: 0.91, mean: 0.57 },
      abuse_intent_risk: { minimum: 0.18, maximum: 0.88, mean: 0.49 },
      account_continuity: { minimum: 0.2, maximum: 0.79, mean: 0.51 },
    },
    linkage: { confirmed_decision_labels: 42, confirmed_label_coverage: proportion(42, 480, 0.071, 0.116), ambiguous_ground_truth_decisions: 3, ambiguous_challenge_decisions: 2 },
    evaluation_slices: [],
    endpoints: [{
      endpoint_class: "public_content", decisions: 310, outcomes: 72, human_confirmed: 20, operator_confirmed_abuse: 12,
      evaluation: { computed_risky_rate: proportion(68, 310, 0.178, 0.27), challenge_failure_rate: proportion(4, 28, 0.057, 0.314), challenge_abandonment_rate: proportion(3, 28, 0.037, 0.272), fallback_outcome_share: proportion(2, 72, 0.008, 0.095), unknown_outcome_share: proportion(37, 72, 0.401, 0.625), confirmed_labels: 32, abuse_label_share: proportion(12, 32, 0.229, 0.546) },
      linked_evaluation: { decisions: 310, confirmed_labels: 32, ambiguous_ground_truth: 2, confusion: { true_positive: 9, false_positive: 2, true_negative: 18, false_negative: 3 }, false_positive_rate: proportion(2, 20, 0.028, 0.301), abuse_recall: proportion(9, 12, 0.468, 0.911), abuse_precision: proportion(9, 11, 0.523, 0.949), mature_challenges: 28, challenge_passed: 19, challenge_failed: 4, challenge_abandoned: 3, fallback_used: 2, unresolved_mature_challenges: 0, ambiguous_challenge_outcomes: 0, challenge_pass_rate: proportion(19, 28, 0.494, 0.817), challenge_failure_rate: proportion(4, 28, 0.057, 0.314), challenge_abandonment_rate: proportion(3, 28, 0.037, 0.272), fallback_rate: proportion(2, 28, 0.02, 0.226) },
    }],
    canary_comparisons: [{ rollout_id: "synthetic-canary", endpoint_class: "public_content", comparable: true, canary_decisions: 120, computed_risk_difference: { estimate: 0.01, lower_95: -0.03, upper_95: 0.05 } }],
    canary_challenge_budgets: [{
      rollout_id: "synthetic-canary", endpoint_class: "public_content", mature_challenges: 120,
      terminal_outcome_coverage: proportion(118, 120, 0.941, 0.995),
      challenge_abandonment_rate: proportion(2, 120, 0.005, 0.058),
      fallback_rate: proportion(1, 120, 0.001, 0.045),
    }],
    recommendations: [
      { code: "COLLECT_MORE_DECISIONS", priority: "high", message: "Collect a complete representative traffic cycle before calibration." },
      { code: "EXPAND_CONFIRMED_HUMANS", priority: "high", message: "Link more authenticated or reviewed human outcomes to exact decisions." },
      { code: "KEEP_SHADOW_MODE", priority: "high", message: "Keep automatic enforcement disabled until validation gates pass." },
    ],
  },
});
