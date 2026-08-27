package shadowanalysis

import (
	"errors"
	"fmt"
	"reflect"
	"slices"
	"testing"

	"github.com/palisade-bot-defense/palisade/internal/core"
	"github.com/palisade-bot-defense/palisade/internal/shadowlog"
)

func TestSparseEvidenceKeepsShadowAndExplainsGaps(t *testing.T) {
	config := normalizedTestConfig(t, Config{})
	analysis := newAnalyzer(config)
	for index := 0; index < 20; index++ {
		if err := analysis.observe(decisionRecord(fmt.Sprintf("decision-%d", index), core.ActionObserve, core.ActionChallenge, "STEP_UP_REQUIRED")); err != nil {
			t.Fatal(err)
		}
	}
	if err := analysis.observe(outcomeRecord("human_confirmed")); err != nil {
		t.Fatal(err)
	}
	report := analysis.finish(shadowlog.Verification{Records: 21, Decisions: 20, Outcomes: 1})
	if report.Readiness.State != "collecting" || report.Readiness.OperatorAction != "remain_shadow" || report.Readiness.AutomaticEnforcement {
		t.Fatalf("unexpected readiness: %+v", report.Readiness)
	}
	for _, code := range []string{"COLLECT_MORE_DECISIONS", "IMPROVE_OUTCOME_COVERAGE", "EXPAND_CONFIRMED_HUMANS", "EXPAND_CONFIRMED_ABUSE", "REVIEW_COMPUTED_CHALLENGE_RATE", "KEEP_SHADOW_MODE"} {
		if !hasRecommendation(report, code) {
			t.Fatalf("missing recommendation %s: %+v", code, report.Recommendations)
		}
	}
	if report.Decisions.ComputedChallengeRate != 1 || report.TopReasonCodes[0].Count != 20 {
		t.Fatalf("unexpected aggregates: %+v %+v", report.Decisions, report.TopReasonCodes)
	}
}

func TestAggregateValidationAllowsCollectionReportButRolloutRequiresFullWindow(t *testing.T) {
	analysis := newAnalyzer(normalizedTestConfig(t, Config{}))
	if err := analysis.observe(decisionRecord("decision-1", core.ActionAllow, core.ActionAllow, "BASELINE")); err != nil {
		t.Fatal(err)
	}
	report := analysis.finish(shadowlog.Verification{
		Files: 1, Records: 1, Decisions: 1, FirstAt: "2026-08-27T12:00:00Z", LastAt: "2026-08-27T12:01:00Z",
	})
	if err := ValidateReport(report); err != nil {
		t.Fatalf("valid collection report was rejected: %v", err)
	}
	if !errors.Is(ValidateForRollout(report), ErrInvalidReport) {
		t.Fatal("short observation window was accepted for rollout")
	}
}

func TestPopulatedEvidenceOnlyBecomesOperatorReviewCandidate(t *testing.T) {
	config := normalizedTestConfig(t, Config{
		MinDecisions: 2, MinOutcomeCoverage: 0.5, MinConfirmedHumans: 1, MinConfirmedAbuse: 1,
		MaxChallengeRate: 1, MaxChallengeFailure: 1, MinChallengeResults: 1,
	})
	analysis := newAnalyzer(config)
	for index := 0; index < 2; index++ {
		if err := analysis.observe(decisionRecord(fmt.Sprintf("decision-%d", index), core.ActionObserve, core.ActionAllow, "BASELINE")); err != nil {
			t.Fatal(err)
		}
	}
	if err := analysis.observe(linkedOutcomeRecord("decision-0", "account", "human_confirmed")); err != nil {
		t.Fatal(err)
	}
	if err := analysis.observe(linkedOutcomeRecord("decision-1", "account", "operator_confirmed_abuse")); err != nil {
		t.Fatal(err)
	}
	report := analysis.finish(shadowlog.Verification{Records: 4, Decisions: 2, Outcomes: 2})
	if report.Readiness.State != "operator_review_candidate" || report.Readiness.OperatorAction != "review_reversible_canary" || report.Readiness.AutomaticEnforcement {
		t.Fatalf("unexpected readiness: %+v", report.Readiness)
	}
	if !hasRecommendation(report, "PREPARE_OPERATOR_REVIEW") || hasRecommendation(report, "KEEP_SHADOW_MODE") {
		t.Fatalf("unexpected recommendations: %+v", report.Recommendations)
	}
}

func TestRiskyEnforcedActionInShadowIsCritical(t *testing.T) {
	config := normalizedTestConfig(t, Config{})
	analysis := newAnalyzer(config)
	if err := analysis.observe(decisionRecord("decision-risky", core.ActionBlock, core.ActionBlock, "HIGH_RISK")); err != nil {
		t.Fatal(err)
	}
	report := analysis.finish(shadowlog.Verification{Records: 1, Decisions: 1})
	if report.Readiness.State != "invalid_shadow_behavior" || !hasRecommendation(report, "FIX_SHADOW_ENFORCEMENT") {
		t.Fatalf("unsafe shadow behavior was not rejected: %+v", report)
	}
}

func TestCanaryDecisionsAreAttributedToExactRollout(t *testing.T) {
	analysis := newAnalyzer(normalizedTestConfig(t, Config{}))
	for index := 0; index < 3; index++ {
		record := decisionRecord(fmt.Sprintf("canary-decision-%d", index), core.ActionThrottle, core.ActionThrottle, "VELOCITY_HIGH")
		record.Decision.Mode = core.RuntimeModeCanary
		record.Decision.RolloutID = "canary-20260827"
		if err := analysis.observe(record); err != nil {
			t.Fatal(err)
		}
	}
	report := analysis.finish(shadowlog.Verification{Records: 3, Decisions: 3})
	if report.Decisions.Modes.Canary != 3 || len(report.CanaryRollouts) != 1 || report.CanaryRollouts[0].Value != "canary-20260827" || report.CanaryRollouts[0].Count != 3 {
		t.Fatalf("canary attribution=%+v modes=%+v", report.CanaryRollouts, report.Decisions.Modes)
	}
}

func TestEndpointIntervalsAndCanaryComparisonRemainAggregate(t *testing.T) {
	analysis := newAnalyzer(normalizedTestConfig(t, Config{}))
	for index := 0; index < 100; index++ {
		record := decisionRecord(fmt.Sprintf("shadow-%d", index), core.ActionObserve, core.ActionAllow, "BASELINE")
		if index < 10 {
			record.Decision.ComputedAction = core.ActionThrottle
		}
		if err := analysis.observe(record); err != nil {
			t.Fatal(err)
		}
	}
	for index := 0; index < 50; index++ {
		record := decisionRecord(fmt.Sprintf("canary-%d", index), core.ActionAllow, core.ActionAllow, "BASELINE")
		record.Decision.Mode = core.RuntimeModeCanary
		record.Decision.RolloutID = "canary-evidence"
		if index < 10 {
			record.Decision.Action = core.ActionThrottle
			record.Decision.ComputedAction = core.ActionThrottle
		}
		if err := analysis.observe(record); err != nil {
			t.Fatal(err)
		}
	}
	for _, outcome := range []string{"challenge_passed", "challenge_failed", "challenge_abandoned", "fallback_used", "appeal_requested", "unknown", "human_confirmed", "operator_confirmed_abuse"} {
		if err := analysis.observe(outcomeRecord(outcome)); err != nil {
			t.Fatal(err)
		}
	}
	report := analysis.finish(shadowlog.Verification{Files: 1, Records: 158, Decisions: 150, Outcomes: 8, FirstAt: "2026-08-27T00:00:00Z", LastAt: "2026-08-27T01:00:00Z"})
	endpoint := report.Endpoints[0]
	if endpoint.Evaluation.ComputedRiskyRate.Count != 20 || endpoint.Evaluation.ComputedRiskyRate.Total != 150 || endpoint.Evaluation.ConfirmedLabels != 2 ||
		endpoint.Evaluation.ChallengeFailureRate.Count != 2 || endpoint.Evaluation.ChallengeFailureRate.Total != 3 || endpoint.Evaluation.ChallengeAbandonmentRate.Count != 1 {
		t.Fatalf("endpoint evaluation = %+v", endpoint.Evaluation)
	}
	if len(report.CanaryComparisons) != 1 {
		t.Fatalf("canary comparisons = %+v", report.CanaryComparisons)
	}
	comparison := report.CanaryComparisons[0]
	if comparison.RolloutID != "canary-evidence" || comparison.EndpointClass != "account" || !comparison.Comparable || comparison.ShadowDecisions != 100 || comparison.CanaryDecisions != 50 ||
		comparison.ShadowComputedRisky.Count != 10 || comparison.CanaryComputedRisky.Count != 10 || comparison.CanaryEnforcedRisky.Count != 10 {
		t.Fatalf("canary comparison = %+v", comparison)
	}
	if !validEndpoints(report) {
		t.Fatalf("endpoint validation failed: %+v", endpoint)
	}
	if !validCanaryComparisons(report) {
		t.Fatalf("canary comparison validation failed: %+v", comparison)
	}
	if !validScore(report.Scores.AutomationRisk, report.Decisions.Total) || !validScore(report.Scores.AbuseIntentRisk, report.Decisions.Total) || !validScore(report.Scores.AccountContinuity, report.Decisions.Total) {
		t.Fatalf("score validation failed: %+v", report.Scores)
	}
	expectedRecommendations, expectedReadiness := recommend(report, normalizedTestConfig(t, Config{}))
	if !slices.Equal(report.Recommendations, expectedRecommendations) || !reflect.DeepEqual(report.Readiness, expectedReadiness) {
		t.Fatalf("recommendation validation failed:\nreport=%+v %+v\nexpected=%+v %+v", report.Readiness, report.Recommendations, expectedReadiness, expectedRecommendations)
	}
	if err := ValidateReport(report); err != nil {
		t.Fatalf("aggregate endpoint evaluation was rejected: %v", err)
	}
	report.TopReasonCodes[0].Value = "raw value with spaces"
	if !errors.Is(ValidateReport(report), ErrInvalidReport) {
		t.Fatal("non-closed aggregate metadata was accepted")
	}
	report.TopReasonCodes[0].Value = "BASELINE"
	report.CanaryComparisons[0].CanaryComputedRisky.Count++
	if !errors.Is(ValidateReport(report), ErrInvalidReport) {
		t.Fatal("tampered canary interval was accepted")
	}
}

func TestReportWithRecordsRequiresCanonicalSourceTimes(t *testing.T) {
	analysis := newAnalyzer(normalizedTestConfig(t, Config{}))
	if err := analysis.observe(decisionRecord("decision-time", core.ActionAllow, core.ActionAllow, "BASELINE")); err != nil {
		t.Fatal(err)
	}
	report := analysis.finish(shadowlog.Verification{Files: 1, Records: 1, Decisions: 1})
	if !errors.Is(ValidateReport(report), ErrInvalidReport) {
		t.Fatal("report with records but no authenticated source times was accepted")
	}
}

func TestLinkedEvaluationProducesDecisionLevelMetricsByCohort(t *testing.T) {
	analysis := newAnalyzer(normalizedTestConfig(t, Config{}))
	decision := func(id string, cohort core.EvaluationCohort, enforced, computed core.Action) {
		record := decisionRecord(id, enforced, computed, "LINK_TEST")
		record.Decision.EndpointClass = "public_content"
		record.Decision.EvaluationCohort = cohort
		if err := analysis.observe(record); err != nil {
			t.Fatal(err)
		}
	}
	outcome := func(id, endpoint, kind string) {
		if err := analysis.observe(linkedOutcomeRecord(id, endpoint, kind)); err != nil {
			t.Fatal(err)
		}
	}

	decision("decision-human-risky", core.EvaluationCohortStandard, core.ActionChallenge, core.ActionChallenge)
	outcome("decision-human-risky", "public_content", "human_confirmed")
	outcome("decision-human-risky", "public_content", "challenge_passed")
	outcome("decision-human-risky", "public_content", "challenge_passed")
	decision("decision-abuse-allowed", core.EvaluationCohortStandard, core.ActionAllow, core.ActionAllow)
	outcome("decision-abuse-allowed", "public_content", "operator_confirmed_abuse")
	decision("decision-fallback", core.EvaluationCohortReducedMotion, core.ActionChallenge, core.ActionChallenge)
	outcome("decision-fallback", "public_content", "fallback_used")
	decision("decision-unresolved", core.EvaluationCohortStandard, core.ActionChallenge, core.ActionChallenge)
	decision("decision-ambiguous", core.EvaluationCohortStandard, core.ActionAllow, core.ActionAllow)
	outcome("decision-ambiguous", "public_content", "human_confirmed")
	outcome("decision-ambiguous", "public_content", "operator_confirmed_abuse")
	decision("decision-mismatch", core.EvaluationCohortStandard, core.ActionAllow, core.ActionAllow)
	outcome("decision-mismatch", "account", "human_confirmed")
	outcome("missing-decision", "public_content", "human_confirmed")
	if err := analysis.observe(outcomeRecord("unknown")); err != nil {
		t.Fatal(err)
	}

	report := analysis.finish(shadowlog.Verification{
		Files: 1, Records: 16, Decisions: 6, Outcomes: 10, FirstAt: "2026-08-27T00:00:00Z", LastAt: "2026-08-27T01:00:00Z",
	})
	if report.Linkage.UniqueDecisionIDs != 6 || report.Linkage.OutcomeEventsWithDecisionID != 9 || report.Linkage.LegacyOutcomeEventsWithoutID != 1 ||
		report.Linkage.MatchedOutcomeEvents != 7 || report.Linkage.UnknownDecisionOutcomeEvents != 1 || report.Linkage.EndpointMismatchOutcomeEvents != 1 ||
		report.Linkage.DuplicateOutcomeEvents != 1 || report.Linkage.ConfirmedDecisionLabels != 2 ||
		report.Linkage.ConfirmedLabelCoverage != Proportion(2, 6) || report.Linkage.AmbiguousGroundTruthDecisions != 1 {
		t.Fatalf("linkage summary = %+v", report.Linkage)
	}
	if len(report.EvaluationSlices) != 2 {
		t.Fatalf("evaluation slices = %+v", report.EvaluationSlices)
	}
	standard := report.EvaluationSlices[1].Evaluation
	if report.EvaluationSlices[1].EvaluationCohort != core.EvaluationCohortStandard || standard.Decisions != 5 || standard.ConfirmedLabels != 2 ||
		standard.Confusion.FalsePositive != 1 || standard.Confusion.FalseNegative != 1 || standard.AmbiguousGroundTruth != 1 ||
		standard.MatureChallenges != 2 || standard.ChallengePassed != 1 || standard.UnresolvedMatureChallenges != 1 || standard.FalsePositiveRate.Rate != 1 {
		t.Fatalf("standard evaluation = %+v", standard)
	}
	reduced := report.EvaluationSlices[0].Evaluation
	if report.EvaluationSlices[0].EvaluationCohort != core.EvaluationCohortReducedMotion || reduced.MatureChallenges != 1 || reduced.FallbackUsed != 1 || reduced.FallbackRate.Rate != 1 {
		t.Fatalf("reduced-motion evaluation = %+v", reduced)
	}
	if err := ValidateReport(report); err != nil {
		t.Fatalf("linked aggregate report was rejected: %v", err)
	}
	report.EvaluationSlices[0].Evaluation.FalsePositiveRate.Count++
	if !errors.Is(ValidateReport(report), ErrInvalidReport) {
		t.Fatal("tampered linked interval was accepted")
	}
}

func TestDecisionLinkageIsOrderIndependentAndExcludesDuplicateDecisionIDs(t *testing.T) {
	analysis := newAnalyzer(normalizedTestConfig(t, Config{}))
	if err := analysis.observe(linkedOutcomeRecord("decision-late", "account", "human_confirmed")); err != nil {
		t.Fatal(err)
	}
	if err := analysis.observe(decisionRecord("decision-late", core.ActionAllow, core.ActionAllow, "BASELINE")); err != nil {
		t.Fatal(err)
	}
	if err := analysis.observe(decisionRecord("decision-duplicate", core.ActionAllow, core.ActionAllow, "BASELINE")); err != nil {
		t.Fatal(err)
	}
	if err := analysis.observe(decisionRecord("decision-duplicate", core.ActionAllow, core.ActionAllow, "BASELINE")); err != nil {
		t.Fatal(err)
	}
	report := analysis.finish(shadowlog.Verification{
		Files: 1, Records: 4, Decisions: 3, Outcomes: 1, FirstAt: "2026-08-27T00:00:00Z", LastAt: "2026-08-27T00:20:00Z",
	})
	if report.Linkage.UniqueDecisionIDs != 2 || report.Linkage.DuplicateDecisionIDs != 1 || report.Linkage.DuplicateDecisionRecords != 1 ||
		report.Linkage.MatchedOutcomeEvents != 1 || report.Linkage.ConfirmedDecisionLabels != 1 ||
		len(report.EvaluationSlices) != 1 || report.EvaluationSlices[0].Evaluation.Decisions != 1 || report.EvaluationSlices[0].Evaluation.Confusion.TrueNegative != 1 {
		t.Fatalf("order-independent linkage = %+v slices=%+v", report.Linkage, report.EvaluationSlices)
	}
	if err := ValidateReport(report); err != nil {
		t.Fatalf("order-independent report was rejected: %v", err)
	}
}

func TestDecisionLinkBudgetFailsClosed(t *testing.T) {
	analysis := newAnalyzer(normalizedTestConfig(t, Config{MaxDecisionLinks: 1}))
	if err := analysis.observe(decisionRecord("decision-one", core.ActionAllow, core.ActionAllow, "BASELINE")); err != nil {
		t.Fatal(err)
	}
	if err := analysis.observe(decisionRecord("decision-two", core.ActionAllow, core.ActionAllow, "BASELINE")); !errors.Is(err, ErrLinkBudget) {
		t.Fatalf("decision-link budget error = %v", err)
	}
}

func TestCanaryComparisonWithoutShadowBaselineIsMarkedUnavailable(t *testing.T) {
	analysis := newAnalyzer(normalizedTestConfig(t, Config{}))
	record := decisionRecord("canary-only", core.ActionThrottle, core.ActionThrottle, "VELOCITY_HIGH")
	record.Decision.Mode = core.RuntimeModeCanary
	record.Decision.RolloutID = "canary-only"
	if err := analysis.observe(record); err != nil {
		t.Fatal(err)
	}
	report := analysis.finish(shadowlog.Verification{Files: 1, Records: 1, Decisions: 1, FirstAt: "2026-08-27T00:00:00Z", LastAt: "2026-08-27T00:00:00Z"})
	comparison := report.CanaryComparisons[0]
	if comparison.Comparable || comparison.ComputedRiskDifference != (DifferenceEstimate{}) || comparison.ShadowDecisions != 0 {
		t.Fatalf("missing shadow baseline was presented as comparable: %+v", comparison)
	}
	if err := ValidateReport(report); err != nil {
		t.Fatalf("honest unavailable comparison was rejected: %v", err)
	}
}

func TestChallengeFrictionRequiresTuningBeforeReview(t *testing.T) {
	config := normalizedTestConfig(t, Config{
		MinDecisions: 2, MinOutcomeCoverage: 0.5, MinConfirmedHumans: 1, MinConfirmedAbuse: 1,
		MaxChallengeRate: 1, MaxChallengeFailure: 0.1, MinChallengeResults: 2,
	})
	analysis := newAnalyzer(config)
	for index := 0; index < 2; index++ {
		record := decisionRecord(fmt.Sprintf("decision-%d", index), core.ActionChallenge, core.ActionChallenge, "STEP_UP_REQUIRED")
		record.Decision.Mode = core.RuntimeModeCanary
		record.Decision.RolloutID = "canary-friction"
		if err := analysis.observe(record); err != nil {
			t.Fatal(err)
		}
	}
	for _, linked := range []struct {
		decisionID string
		outcome    string
	}{
		{decisionID: "decision-0", outcome: "human_confirmed"},
		{decisionID: "decision-1", outcome: "operator_confirmed_abuse"},
		{decisionID: "decision-0", outcome: "challenge_failed"},
		{decisionID: "decision-1", outcome: "challenge_abandoned"},
	} {
		if err := analysis.observe(linkedOutcomeRecord(linked.decisionID, "account", linked.outcome)); err != nil {
			t.Fatal(err)
		}
	}
	report := analysis.finish(shadowlog.Verification{Files: 1, Records: 6, Decisions: 2, Outcomes: 4, FirstAt: "2026-08-27T00:00:00Z", LastAt: "2026-08-27T00:20:00Z"})
	if report.Readiness.State != "needs_tuning" || !hasRecommendation(report, "REDUCE_CHALLENGE_FRICTION") || !hasRecommendation(report, "KEEP_SHADOW_MODE") {
		t.Fatalf("challenge friction did not hold shadow: %+v", report)
	}
}

func TestDistinctMetadataBudgetFailsClosed(t *testing.T) {
	config := normalizedTestConfig(t, Config{MaxDistinctMetadata: 16, TopReasonCodes: 16})
	analysis := newAnalyzer(config)
	for index := 0; index < 17; index++ {
		record := decisionRecord(fmt.Sprintf("decision-%d", index), core.ActionObserve, core.ActionAllow, "BASELINE")
		record.Decision.PolicyVersion = fmt.Sprintf("policy-%d", index)
		err := analysis.observe(record)
		if index < 16 && err != nil {
			t.Fatal(err)
		}
		if index == 16 && !errors.Is(err, ErrDistinctBudget) {
			t.Fatalf("distinct budget error = %v", err)
		}
	}
}

func decisionRecord(id string, enforced, computed core.Action, reason string) shadowlog.Record {
	return shadowlog.Record{Kind: "decision", RecordedAt: "2026-08-27T00:00:00Z", Decision: &shadowlog.DecisionEntry{
		DecisionID: id, RequestAction: "read", EndpointClass: "account", Action: enforced, ComputedAction: computed,
		Mode: core.RuntimeModeShadow, Scores: core.Scores{AutomationRisk: 0.4, AbuseIntentRisk: 0.3, AccountContinuity: 0.8},
		ReasonCodes: []string{reason}, PolicyVersion: "default-v3", ModelVersion: "transparent-baseline-v6",
	}}
}

func outcomeRecord(outcome string) shadowlog.Record {
	entry := &shadowlog.OutcomeEntry{EndpointClass: "account", Outcome: outcome, Confidence: "confirmed"}
	switch outcome {
	case "human_confirmed":
		entry.Provenance = "authenticated_account"
	case "operator_confirmed_abuse":
		entry.Provenance = "operator_review"
	default:
		entry.Provenance = "server_observed"
	}
	return shadowlog.Record{Kind: "outcome", Outcome: entry}
}

func linkedOutcomeRecord(decisionID, endpoint, outcome string) shadowlog.Record {
	record := outcomeRecord(outcome)
	record.RecordedAt = "2026-08-27T00:10:00Z"
	record.Outcome.DecisionID = decisionID
	record.Outcome.EndpointClass = endpoint
	return record
}

func normalizedTestConfig(t *testing.T, config Config) Config {
	t.Helper()
	normalized, err := normalizeConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	return normalized
}

func hasRecommendation(report Report, code string) bool {
	for _, recommendation := range report.Recommendations {
		if recommendation.Code == code {
			return true
		}
	}
	return false
}
