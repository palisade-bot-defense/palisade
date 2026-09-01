package rollout

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"testing"
	"time"

	"github.com/palisade-human-trust/palisade/internal/core"
	"github.com/palisade-human-trust/palisade/internal/shadowanalysis"
	"github.com/palisade-human-trust/palisade/internal/shadowlog"
)

func TestPrepareVerifyAndTamper(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	report := candidateReport(2000, 0)
	reportBytes := encodedReport(t, report)
	proposal, err := BuildReviewProposal(report, reportBytes, ReviewOptions{Stage: core.RuntimeModeCanary})
	if err != nil {
		t.Fatal(err)
	}
	signed, err := PrepareFromReview(report, reportBytes, proposal, "canary-20260827", "review-123", now, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(signed, publicKey, now); err != nil {
		t.Fatal(err)
	}
	signed.Plan.MaxChallengeFallbackRate += 0.01
	if err := Verify(signed, publicKey, now); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("tampered plan error=%v", err)
	}
}

func TestPlanRejectsInvalidChallengeBudgets(t *testing.T) {
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	controller := testController(t, now, core.RuntimeModeCanary, 0)
	base := controller.plan
	tests := []struct {
		name   string
		mutate func(*Plan)
	}{
		{name: "zero sample", mutate: func(plan *Plan) { plan.MinMatureChallenges = 0 }},
		{name: "zero coverage", mutate: func(plan *Plan) { plan.MinChallengeOutcomeCoverage = 0 }},
		{name: "nan abandonment", mutate: func(plan *Plan) { plan.MaxChallengeAbandonmentRate = math.NaN() }},
		{name: "infinite fallback", mutate: func(plan *Plan) { plan.MaxChallengeFallbackRate = math.Inf(1) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			plan := base
			test.mutate(&plan)
			if err := plan.Validate(now); !errors.Is(err, ErrInvalidPlan) {
				t.Fatalf("invalid budget error=%v plan=%+v", err, plan)
			}
		})
	}
}

func TestReviewAndSigningRejectForgedMismatchedOrTamperedInputs(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	original := candidateReport(2000, 0)
	forged := original
	forged.Decisions.Enforced.Allow--
	if _, err := BuildReviewProposal(forged, encodedReport(t, forged), ReviewOptions{Stage: core.RuntimeModeCanary}); !errors.Is(err, ErrAnalysisNotReady) {
		t.Fatalf("forged aggregate error=%v", err)
	}
	if _, err := BuildReviewProposal(original, encodedReport(t, forged), ReviewOptions{Stage: core.RuntimeModeCanary}); !errors.Is(err, ErrAnalysisNotReady) {
		t.Fatalf("mismatched report bytes error=%v", err)
	}
	reportBytes := encodedReport(t, original)
	proposal, err := BuildReviewProposal(original, reportBytes, ReviewOptions{Stage: core.RuntimeModeCanary})
	if err != nil {
		t.Fatal(err)
	}
	proposal.RecommendedScope.CanaryBasisPoints++
	if _, err := PrepareFromReview(original, reportBytes, proposal, "canary-20260827", "review-123", now, privateKey); !errors.Is(err, ErrInvalidReview) {
		t.Fatalf("tampered proposal error=%v", err)
	}
}

func TestCanaryIsDeterministicScopedAndCapped(t *testing.T) {
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	controller := testController(t, now, core.RuntimeModeCanary, 0)
	selected := ""
	excluded := ""
	for index := 0; index < 10000 && (selected == "" || excluded == ""); index++ {
		sessionID := fmt.Sprintf("session-%08d", index)
		if controller.bucket(sessionID) < DefaultCanaryBasisPoints {
			selected = sessionID
		} else {
			excluded = sessionID
		}
	}
	if selected == "" || excluded == "" {
		t.Fatal("could not find deterministic canary cohorts")
	}
	included := controller.Apply(selected, "public_content", core.ActionBlock, now)
	if included.Mode != core.RuntimeModeCanary || included.Action != core.ActionChallenge || included.Directive.Handling != "challenge" ||
		included.Directive.RetryAfterSeconds != 0 || !contains(included.Reasons, "ROLLOUT_ACTION_CAPPED") {
		t.Fatalf("included result=%+v", included)
	}
	second := controller.Apply(selected, "public_content", core.ActionBlock, now)
	if included.Action != second.Action || included.Mode != second.Mode || included.RolloutID != second.RolloutID {
		t.Fatalf("canary selection was not deterministic: first=%+v second=%+v", included, second)
	}
	outsideCohort := controller.Apply(excluded, "public_content", core.ActionBlock, now)
	if outsideCohort.Mode != core.RuntimeModeShadow || outsideCohort.Action != core.ActionObserve || !contains(outsideCohort.Reasons, "ROLLOUT_CANARY_EXCLUDED") {
		t.Fatalf("excluded cohort result=%+v", outsideCohort)
	}
	outsideEndpoint := controller.Apply(selected, "login", core.ActionBlock, now)
	if outsideEndpoint.Mode != core.RuntimeModeShadow || outsideEndpoint.Action != core.ActionObserve || !contains(outsideEndpoint.Reasons, "ROLLOUT_ENDPOINT_EXCLUDED") {
		t.Fatalf("excluded endpoint result=%+v", outsideEndpoint)
	}
}

func TestEnforceRequiresMeasuredCanary(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	underMeasured := candidateReport(2000, MinimumCanaryDecisions-1)
	underBytes := encodedReport(t, underMeasured)
	underProposal, err := BuildReviewProposal(underMeasured, underBytes, ReviewOptions{Stage: core.RuntimeModeEnforce, PredecessorRolloutID: "canary-source"})
	if err != nil || underProposal.State != ReviewStateHold {
		t.Fatalf("under-measured enforce proposal=%+v error=%v", underProposal, err)
	}
	if _, err := PrepareFromReview(underMeasured, underBytes, underProposal, "enforce-20260827", "review-456", now, privateKey); !errors.Is(err, ErrInvalidReview) {
		t.Fatalf("under-measured enforce signing error=%v", err)
	}
	measured := candidateReport(2000, MinimumCanaryDecisions)
	measuredBytes := encodedReport(t, measured)
	proposal, err := BuildReviewProposal(measured, measuredBytes, ReviewOptions{Stage: core.RuntimeModeEnforce, PredecessorRolloutID: "canary-source"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := PrepareFromReview(measured, measuredBytes, proposal, "enforce-20260827", "review-456", now, privateKey); err != nil {
		t.Fatal(err)
	}
	measured.CanaryComparisons[0].RolloutID = "other-canary"
	measured.CanaryChallengeBudgets[0].RolloutID = "other-canary"
	measured.CanaryRollouts[0].Value = "other-canary"
	measuredBytes = encodedReport(t, measured)
	if proposal, err := BuildReviewProposal(measured, measuredBytes, ReviewOptions{Stage: core.RuntimeModeEnforce, PredecessorRolloutID: "canary-source"}); err != nil || proposal.State != ReviewStateHold {
		t.Fatalf("mismatched endpoint comparison proposal=%+v error=%v", proposal, err)
	}
}

func TestExpiredControllerFailsClosed(t *testing.T) {
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	controller := testController(t, now, core.RuntimeModeCanary, 0)
	result := controller.Apply("session-12345678", "public_content", core.ActionBlock, now.Add(25*time.Hour))
	if result.Mode != core.RuntimeModeShadow || result.Action != core.ActionObserve || !contains(result.Reasons, "ROLLOUT_EXPIRED") {
		t.Fatalf("expired result=%+v", result)
	}
}

func TestDirectiveCannotOutliveSignedPlan(t *testing.T) {
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	controller := testController(t, now, core.RuntimeModeEnforce, MinimumCanaryDecisions)
	decisionAt := now.Add(DefaultEnforcementDuration - 5*time.Second)
	result := controller.Apply("session-12345678", "public_content", core.ActionBlock, decisionAt)
	if !result.Directive.ExpiresAt.Equal(now.Add(DefaultEnforcementDuration)) || result.Directive.RetryAfterSeconds != 0 {
		t.Fatalf("directive outlived plan: %+v", result.Directive)
	}
}

func TestDelayIsBoundedAndRemainsShadowWithoutRollout(t *testing.T) {
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	controller := testController(t, now, core.RuntimeModeCanary, 0)
	selected := ""
	for index := 0; index < 10_000; index++ {
		candidate := fmt.Sprintf("delay-session-%08d", index)
		if controller.bucket(candidate) < DefaultCanaryBasisPoints {
			selected = candidate
			break
		}
	}
	if selected == "" {
		t.Fatal("could not find deterministic delay canary session")
	}
	result := controller.Apply(selected, "public_content", core.ActionDelay, now)
	if result.Action != core.ActionDelay || result.Directive.Handling != "delay" || result.Directive.HTTPStatus != 429 ||
		result.Directive.RetryAfterSeconds != DefaultDelaySeconds || !result.Directive.ExpiresAt.Equal(now.Add(time.Second)) {
		t.Fatalf("delay result = %+v", result)
	}
	shadow := shadowResult(core.ActionDelay, now, "TEST_SHADOW")
	if shadow.Action != core.ActionObserve || shadow.Mode != core.RuntimeModeShadow || shadow.Directive.Handling != "pass" {
		t.Fatalf("shadow delay result = %+v", shadow)
	}
}

func TestAdaptiveResponseCostUsesClosedFactorsAndSignedMaximum(t *testing.T) {
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	plan := Plan{ThrottleSeconds: DefaultThrottleSeconds}
	tests := []struct {
		name     string
		endpoint string
		context  AdaptiveContext
		seconds  int
		reason   string
	}{
		{name: "baseline is humane minimum", endpoint: "public_content", seconds: 1, reason: ReasonResponseCostBaseline},
		{name: "endpoint value", endpoint: "compare_noindex", seconds: 2, reason: ReasonResponseCostEndpoint},
		{name: "confident suspicious evidence", endpoint: "public_content", context: AdaptiveContext{SuspiciousEvidenceConfidence: .75}, seconds: 2, reason: ReasonResponseCostEvidence},
		{name: "recent bounded behavior", endpoint: "public_content", context: AdaptiveContext{RequestCount: 50}, seconds: 2, reason: ReasonResponseCostBehavior},
		{name: "retry history", endpoint: "public_content", context: AdaptiveContext{PrematureRetries: 1}, seconds: 2, reason: ReasonResponseCostRetry},
		{name: "all factors reach but cannot exceed signed maximum", endpoint: "compare_noindex", context: AdaptiveContext{
			SuspiciousEvidenceConfidence: .9, RequestCount: 50, RecentEnforcements: 2,
		}, seconds: DefaultThrottleSeconds, reason: ReasonResponseCostRetry},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			directive, reasons := adaptiveDirective(core.ActionThrottle, test.endpoint, test.context, now, plan)
			if directive.RetryAfterSeconds != test.seconds || directive.Handling != "throttle" || !contains(reasons, test.reason) {
				t.Fatalf("adaptive directive = %+v reasons=%v", directive, reasons)
			}
		})
	}
}

func TestAdaptiveBlockCostIsBoundedAndContextRejectsBenignEvidence(t *testing.T) {
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	plan := Plan{BlockSeconds: DefaultBlockSeconds}
	minimum, reasons := adaptiveDirective(core.ActionBlock, "public_content", AdaptiveContext{}, now, plan)
	maximum, maxReasons := adaptiveDirective(core.ActionBlock, "compare_noindex", AdaptiveContext{
		SuspiciousEvidenceConfidence: .9, RequestCount: 100, PrematureRetries: 1,
	}, now, plan)
	if minimum.RetryAfterSeconds != 60 || !contains(reasons, ReasonResponseCostBaseline) ||
		maximum.RetryAfterSeconds != DefaultBlockSeconds || len(maxReasons) != maximumResponseCostTier {
		t.Fatalf("minimum=%+v reasons=%v maximum=%+v maxReasons=%v", minimum, reasons, maximum, maxReasons)
	}
	context := AdaptiveContextFrom(core.SessionSnapshot{RequestCount: 49, EndpointTransitions: 5}, []core.Evidence{
		{Direction: core.DirectionBenign, Strength: 1, Confidence: 1},
		{Direction: core.DirectionSuspicious, Strength: .49, Confidence: 1},
		{Direction: core.DirectionSuspicious, Strength: .5, Confidence: .74},
	})
	if context.SuspiciousEvidenceConfidence != .74 {
		t.Fatalf("closed adaptive context = %+v", context)
	}
	_, contextReasons := responseCostTier("public_content", context)
	if len(contextReasons) != 1 || contextReasons[0] != ReasonResponseCostBaseline {
		t.Fatalf("weak or benign evidence raised cost: %v", contextReasons)
	}
}

func TestAdaptiveResponseCannotOutliveSignedPlan(t *testing.T) {
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	expiresAt := now.Add(30 * time.Second)
	directive, _ := adaptiveDirective(core.ActionBlock, "compare_noindex", AdaptiveContext{
		SuspiciousEvidenceConfidence: .9, RequestCount: 100, PrematureRetries: 1,
	}, now, Plan{BlockSeconds: DefaultBlockSeconds, ExpiresAt: expiresAt.Format(time.RFC3339)})
	if directive.RetryAfterSeconds != 30 || !directive.ExpiresAt.Equal(expiresAt) {
		t.Fatalf("adaptive directive outlived signed plan: %+v", directive)
	}
	invalid, reasons := adaptiveDirective(core.ActionThrottle, "public_content", AdaptiveContext{SuspiciousEvidenceConfidence: 2}, now, Plan{ThrottleSeconds: DefaultThrottleSeconds})
	if invalid.RetryAfterSeconds != 1 || len(reasons) != 1 || reasons[0] != ReasonResponseCostBaseline {
		t.Fatalf("invalid confidence raised cost: directive=%+v reasons=%v", invalid, reasons)
	}
}

func testController(t *testing.T, now time.Time, stage core.RuntimeMode, canaryDecisions uint64) *Controller {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	predecessor := ""
	if stage == core.RuntimeModeEnforce {
		predecessor = "canary-source"
	}
	report := candidateReport(2000, canaryDecisions)
	reportBytes := encodedReport(t, report)
	proposal, err := BuildReviewProposal(report, reportBytes, ReviewOptions{Stage: stage, PredecessorRolloutID: predecessor})
	if err != nil {
		t.Fatal(err)
	}
	signed, err := PrepareFromReview(report, reportBytes, proposal, "rollout-20260827", "review-123", now, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	controller, err := NewController(signed, publicKey, []byte("0123456789abcdef0123456789abcdef"), "default-v3", "transparent-baseline-v6", now)
	if err != nil {
		t.Fatal(err)
	}
	return controller
}

func candidateReport(decisions, canary uint64) shadowanalysis.Report {
	report := shadowanalysis.Report{
		SchemaVersion: shadowanalysis.SchemaVersion,
		Source:        shadowlog.Verification{Files: 1, Records: decisions + 200, Decisions: decisions, Outcomes: 200, EncryptedBytes: 4096, FirstAt: "2026-08-26T00:00:00Z", LastAt: "2026-08-27T00:00:00Z"},
		Readiness:     shadowanalysis.Readiness{State: "operator_review_candidate", OperatorAction: "review_reversible_canary", AutomaticEnforcement: false, ReasonCodes: []string{}},
		Decisions: shadowanalysis.DecisionSummary{
			Total: decisions, Enforced: shadowanalysis.ActionCounts{Allow: decisions}, Computed: shadowanalysis.ActionCounts{Allow: decisions - 20, Throttle: 20},
			Modes: shadowanalysis.ModeCounts{Shadow: decisions - canary, Canary: canary},
		},
		PolicyVersions: []shadowanalysis.CountedValue{{Value: "default-v3", Count: decisions}},
		ModelVersions:  []shadowanalysis.CountedValue{{Value: "transparent-baseline-v6", Count: decisions}},
		Recommendations: []shadowanalysis.Recommendation{{
			Code: "PREPARE_OPERATOR_REVIEW", Priority: "low", Disposition: "review_candidate", Metric: "automatic_enforcement",
			Unit: "boolean", Message: "Evidence gates are populated; an operator may review endpoint-specific confidence intervals and a reversible canary. PALISADE does not enable enforcement automatically.",
		}},
	}
	setTestEndpoints(&report, []shadowanalysis.EndpointSummary{testEndpoint("public_content", decisions, 200, 20, 100, 100)})
	if canary > 0 {
		report.CanaryRollouts = []shadowanalysis.CountedValue{{Value: "canary-source", Count: canary}}
		canaryRisky := minimumUint64(20, canary)
		shadowRisky := uint64(20) - canaryRisky
		shadowDecisions := decisions - canary
		shadowRate := shadowanalysis.Proportion(shadowRisky, shadowDecisions)
		canaryRate := shadowanalysis.Proportion(canaryRisky, canary)
		comparable := shadowDecisions > 0 && canary > 0
		difference := shadowanalysis.DifferenceEstimate{}
		if comparable {
			difference = shadowanalysis.ProportionDifference(canaryRate, shadowRate)
		}
		report.CanaryComparisons = []shadowanalysis.CanaryComparison{{
			RolloutID: "canary-source", EndpointClass: "public_content", Comparable: comparable, ShadowDecisions: shadowDecisions, CanaryDecisions: canary,
			ShadowComputedRisky: shadowRate, CanaryComputedRisky: canaryRate, CanaryEnforcedRisky: canaryRate,
			ComputedRiskDifference: difference,
		}}
		mature := minimumUint64(200, canary)
		budget := shadowanalysis.CanaryChallengeBudget{
			RolloutID: "canary-source", EndpointClass: "public_content", MatureChallenges: mature, ChallengePassed: mature,
			TerminalOutcomeCoverage: shadowanalysis.Proportion(mature, mature), ChallengeAbandonmentRate: shadowanalysis.Proportion(0, mature),
			FallbackRate: shadowanalysis.Proportion(0, mature),
		}
		report.CanaryChallengeBudgets = []shadowanalysis.CanaryChallengeBudget{budget}
		for index := range report.Endpoints {
			if report.Endpoints[index].EndpointClass != "public_content" {
				continue
			}
			report.Endpoints[index].LinkedEvaluation.MatureChallenges = mature
			report.Endpoints[index].LinkedEvaluation.ChallengePassed = mature
			report.Endpoints[index].LinkedEvaluation.ChallengePassRate = shadowanalysis.Proportion(mature, mature)
			report.Endpoints[index].LinkedEvaluation.ChallengeFailureRate = shadowanalysis.Proportion(0, mature)
			report.Endpoints[index].LinkedEvaluation.ChallengeAbandonmentRate = shadowanalysis.Proportion(0, mature)
			report.Endpoints[index].LinkedEvaluation.FallbackRate = shadowanalysis.Proportion(0, mature)
			for sliceIndex := range report.EvaluationSlices {
				if report.EvaluationSlices[sliceIndex].EndpointClass == "public_content" {
					report.EvaluationSlices[sliceIndex].Evaluation = report.Endpoints[index].LinkedEvaluation
				}
			}
		}
	} else {
		report.CanaryComparisons = []shadowanalysis.CanaryComparison{}
		report.CanaryChallengeBudgets = []shadowanalysis.CanaryChallengeBudget{}
	}
	return report
}

func testEndpoint(name string, decisions, outcomes, risky, humans, abuse uint64) shadowanalysis.EndpointSummary {
	labels := humans + abuse
	truePositive := minimumUint64(risky, abuse)
	confusion := shadowanalysis.ConfusionMatrix{TruePositive: truePositive, FalseNegative: abuse - truePositive, TrueNegative: humans}
	linked := shadowanalysis.LinkedEvaluation{
		Decisions: decisions, ConfirmedLabels: labels, Confusion: confusion,
		FalsePositiveRate: shadowanalysis.Proportion(0, humans), AbuseRecall: shadowanalysis.Proportion(truePositive, abuse),
		AbusePrecision: shadowanalysis.Proportion(truePositive, truePositive),
	}
	return shadowanalysis.EndpointSummary{
		EndpointClass: name, Decisions: decisions, Outcomes: outcomes, ComputedRiskyActions: risky,
		HumanConfirmed: humans, OperatorConfirmedAbuse: abuse,
		OutcomeKinds: shadowanalysis.OutcomeKindCounts{HumanConfirmed: humans, OperatorConfirmedAbuse: abuse},
		Evaluation: shadowanalysis.EndpointEvaluation{
			ComputedRiskyRate:    shadowanalysis.Proportion(risky, decisions),
			ChallengeFailureRate: shadowanalysis.Proportion(0, 0), ChallengeAbandonmentRate: shadowanalysis.Proportion(0, 0),
			FallbackOutcomeShare: shadowanalysis.Proportion(0, outcomes), AppealOutcomeShare: shadowanalysis.Proportion(0, outcomes), UnknownOutcomeShare: shadowanalysis.Proportion(0, outcomes),
			ConfirmedLabels: labels, AbuseLabelShare: shadowanalysis.Proportion(abuse, labels),
		},
		LinkedEvaluation: linked,
	}
}

func setTestEndpoints(report *shadowanalysis.Report, endpoints []shadowanalysis.EndpointSummary) {
	var decisions, outcomes, risky, humans, abuse uint64
	report.EvaluationSlices = make([]shadowanalysis.EvaluationSlice, 0, len(endpoints))
	for _, endpoint := range endpoints {
		decisions += endpoint.Decisions
		outcomes += endpoint.Outcomes
		risky += endpoint.ComputedRiskyActions
		humans += endpoint.HumanConfirmed
		abuse += endpoint.OperatorConfirmedAbuse
		if endpoint.LinkedEvaluation.Decisions > 0 {
			report.EvaluationSlices = append(report.EvaluationSlices, shadowanalysis.EvaluationSlice{
				EndpointClass: endpoint.EndpointClass, EvaluationCohort: core.EvaluationCohortUnknown, Evaluation: endpoint.LinkedEvaluation,
			})
		}
	}
	report.Endpoints = endpoints
	report.Source.Decisions = decisions
	report.Source.Outcomes = outcomes
	report.Source.Records = decisions + outcomes
	report.Decisions.Total = decisions
	report.Decisions.Enforced = shadowanalysis.ActionCounts{Allow: decisions}
	report.Decisions.Computed = shadowanalysis.ActionCounts{Allow: decisions - risky, Throttle: risky}
	report.Outcomes = shadowanalysis.OutcomeSummary{
		Total: outcomes, Coverage: minimumForTest(1, float64(outcomes)/float64(decisions)), HumanConfirmed: humans, OperatorConfirmedAbuse: abuse,
	}
	report.Linkage = shadowanalysis.LinkageSummary{
		UniqueDecisionIDs: decisions, OutcomeEventsWithDecisionID: outcomes, MatchedOutcomeEvents: outcomes,
		ConfirmedDecisionLabels: humans + abuse, ConfirmedLabelCoverage: shadowanalysis.Proportion(humans+abuse, decisions),
	}
}

func minimumUint64(left, right uint64) uint64 {
	if left < right {
		return left
	}
	return right
}

func minimumForTest(left, right float64) float64 {
	if left < right {
		return left
	}
	return right
}

func encodedReport(t *testing.T, report shadowanalysis.Report) []byte {
	t.Helper()
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func contains(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
