package shadowanalysis

import (
	"errors"
	"fmt"
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
	if err := analysis.observe(outcomeRecord("human_confirmed")); err != nil {
		t.Fatal(err)
	}
	if err := analysis.observe(outcomeRecord("operator_confirmed_abuse")); err != nil {
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

func TestChallengeFrictionRequiresTuningBeforeReview(t *testing.T) {
	config := normalizedTestConfig(t, Config{
		MinDecisions: 2, MinOutcomeCoverage: 0.5, MinConfirmedHumans: 1, MinConfirmedAbuse: 1,
		MaxChallengeRate: 1, MaxChallengeFailure: 0.1, MinChallengeResults: 2,
	})
	analysis := newAnalyzer(config)
	for index := 0; index < 2; index++ {
		if err := analysis.observe(decisionRecord(fmt.Sprintf("decision-%d", index), core.ActionObserve, core.ActionAllow, "BASELINE")); err != nil {
			t.Fatal(err)
		}
	}
	for _, outcome := range []string{"human_confirmed", "operator_confirmed_abuse", "challenge_failed", "challenge_abandoned"} {
		if err := analysis.observe(outcomeRecord(outcome)); err != nil {
			t.Fatal(err)
		}
	}
	report := analysis.finish(shadowlog.Verification{Records: 6, Decisions: 2, Outcomes: 4})
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
	return shadowlog.Record{Kind: "decision", Decision: &shadowlog.DecisionEntry{
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
