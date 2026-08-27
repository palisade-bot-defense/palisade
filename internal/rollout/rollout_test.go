package rollout

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/palisade-bot-defense/palisade/internal/core"
	"github.com/palisade-bot-defense/palisade/internal/shadowanalysis"
	"github.com/palisade-bot-defense/palisade/internal/shadowlog"
)

func TestPrepareVerifyAndTamper(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	report := candidateReport(2000, 0)
	signed, err := Prepare(report, encodedReport(t, report), PrepareOptions{
		RolloutID: "canary-20260827", ApprovalID: "review-123", Stage: core.RuntimeModeCanary,
		EndpointClasses: []string{"public_content"}, MaxAction: core.ActionChallenge, CanaryBasisPoints: 500,
		CreatedAt: now, ExpiresAt: now.Add(24 * time.Hour),
	}, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(signed, publicKey, now); err != nil {
		t.Fatal(err)
	}
	signed.Plan.CanaryBasisPoints++
	if err := Verify(signed, publicKey, now); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("tampered plan error=%v", err)
	}
}

func TestPrepareRejectsForgedOrMismatchedAnalysis(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	options := PrepareOptions{
		RolloutID: "canary-20260827", ApprovalID: "review-123", Stage: core.RuntimeModeCanary,
		EndpointClasses: []string{"public_content"}, MaxAction: core.ActionThrottle, CanaryBasisPoints: 100,
		CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	}
	original := candidateReport(2000, 0)
	forged := original
	forged.Decisions.Enforced.Allow--
	if _, err := Prepare(forged, encodedReport(t, forged), options, privateKey); !errors.Is(err, ErrAnalysisNotReady) {
		t.Fatalf("forged aggregate error=%v", err)
	}
	if _, err := Prepare(original, encodedReport(t, forged), options, privateKey); !errors.Is(err, ErrAnalysisNotReady) {
		t.Fatalf("mismatched report bytes error=%v", err)
	}
}

func TestCanaryIsDeterministicScopedAndCapped(t *testing.T) {
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	controller := testController(t, now, core.RuntimeModeCanary, core.ActionChallenge, 500, 0)
	selected := ""
	excluded := ""
	for index := 0; index < 10000 && (selected == "" || excluded == ""); index++ {
		sessionID := fmt.Sprintf("session-%08d", index)
		if controller.bucket(sessionID) < 500 {
			selected = sessionID
		} else {
			excluded = sessionID
		}
	}
	if selected == "" || excluded == "" {
		t.Fatal("could not find deterministic canary cohorts")
	}
	included := controller.Apply(selected, "public_content", core.ActionBlock, now)
	if included.Mode != core.RuntimeModeCanary || included.Action != core.ActionChallenge || included.Directive.Handling != "challenge" || !contains(included.Reasons, "ROLLOUT_ACTION_CAPPED") {
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
	_, err = Prepare(underMeasured, encodedReport(t, underMeasured), PrepareOptions{
		RolloutID: "enforce-20260827", ApprovalID: "review-456", PredecessorRolloutID: "canary-source", Stage: core.RuntimeModeEnforce,
		EndpointClasses: []string{"public_content"}, MaxAction: core.ActionBlock, CanaryBasisPoints: FullRolloutBasisPoints,
		CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	}, privateKey)
	if !errors.Is(err, ErrAnalysisNotReady) {
		t.Fatalf("under-measured enforce error=%v", err)
	}
	measured := candidateReport(2000, MinimumCanaryDecisions)
	if _, err := Prepare(measured, encodedReport(t, measured), PrepareOptions{
		RolloutID: "enforce-20260827", ApprovalID: "review-456", PredecessorRolloutID: "canary-source", Stage: core.RuntimeModeEnforce,
		EndpointClasses: []string{"public_content"}, MaxAction: core.ActionBlock, CanaryBasisPoints: FullRolloutBasisPoints,
		CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	}, privateKey); err != nil {
		t.Fatal(err)
	}
}

func TestExpiredControllerFailsClosed(t *testing.T) {
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	controller := testController(t, now, core.RuntimeModeCanary, core.ActionChallenge, 1000, 0)
	result := controller.Apply("session-12345678", "public_content", core.ActionBlock, now.Add(25*time.Hour))
	if result.Mode != core.RuntimeModeShadow || result.Action != core.ActionObserve || !contains(result.Reasons, "ROLLOUT_EXPIRED") {
		t.Fatalf("expired result=%+v", result)
	}
}

func TestDirectiveCannotOutliveSignedPlan(t *testing.T) {
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	controller := testController(t, now, core.RuntimeModeEnforce, core.ActionBlock, FullRolloutBasisPoints, MinimumCanaryDecisions)
	decisionAt := now.Add(24*time.Hour - 5*time.Second)
	result := controller.Apply("session-12345678", "public_content", core.ActionBlock, decisionAt)
	if !result.Directive.ExpiresAt.Equal(now.Add(24*time.Hour)) || result.Directive.RetryAfterSeconds != 5 {
		t.Fatalf("directive outlived plan: %+v", result.Directive)
	}
}

func testController(t *testing.T, now time.Time, stage core.RuntimeMode, maxAction core.Action, canaryBasisPoints uint32, canaryDecisions uint64) *Controller {
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
	signed, err := Prepare(report, encodedReport(t, report), PrepareOptions{
		RolloutID: "rollout-20260827", ApprovalID: "review-123", Stage: stage,
		PredecessorRolloutID: predecessor,
		EndpointClasses:      []string{"public_content"}, MaxAction: maxAction, CanaryBasisPoints: canaryBasisPoints,
		CreatedAt: now, ExpiresAt: now.Add(24 * time.Hour),
	}, privateKey)
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
			Total: decisions, Enforced: shadowanalysis.ActionCounts{Allow: decisions}, Computed: shadowanalysis.ActionCounts{Allow: decisions},
			Modes: shadowanalysis.ModeCounts{Shadow: decisions - canary, Canary: canary},
		},
		Outcomes:       shadowanalysis.OutcomeSummary{Total: 200, Coverage: minimumForTest(1, float64(200)/float64(decisions)), HumanConfirmed: 100, OperatorConfirmedAbuse: 100},
		Endpoints:      []shadowanalysis.EndpointSummary{{EndpointClass: "public_content", Decisions: decisions, Outcomes: 200, HumanConfirmed: 100, OperatorConfirmedAbuse: 100}},
		PolicyVersions: []shadowanalysis.CountedValue{{Value: "default-v3", Count: decisions}},
		ModelVersions:  []shadowanalysis.CountedValue{{Value: "transparent-baseline-v6", Count: decisions}},
		Recommendations: []shadowanalysis.Recommendation{{
			Code: "PREPARE_OPERATOR_REVIEW", Priority: "low", Disposition: "review_candidate", Metric: "automatic_enforcement",
			Unit: "boolean", Message: "Evidence gates are populated; an operator may review endpoint-specific confidence intervals and a reversible canary. PALISADE does not enable enforcement automatically.",
		}},
	}
	if canary > 0 {
		report.CanaryRollouts = []shadowanalysis.CountedValue{{Value: "canary-source", Count: canary}}
	}
	return report
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
