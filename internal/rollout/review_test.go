package rollout

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/palisade-bot-defense/palisade/internal/core"
	"github.com/palisade-bot-defense/palisade/internal/shadowanalysis"
)

func TestReviewProposalIsDeterministicAndChoosesNarrowestEligibleEndpoint(t *testing.T) {
	report := candidateReport(2000, 0)
	setTestEndpoints(&report, []shadowanalysis.EndpointSummary{
		testEndpoint("account", 500, 200, 1, 100, 100),
		testEndpoint("compare_index", 500, 200, 10, 100, 100),
		testEndpoint("other_public", 500, 200, 20, 100, 100),
		testEndpoint("public_content", 500, 200, 5, 100, 100),
	})
	reportBytes := encodedReport(t, report)
	first, err := BuildReviewProposal(report, reportBytes, ReviewOptions{Stage: core.RuntimeModeCanary})
	if err != nil {
		t.Fatal(err)
	}
	second, err := BuildReviewProposal(report, reportBytes, ReviewOptions{Stage: core.RuntimeModeCanary})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("proposal is not deterministic:\nfirst=%+v\nsecond=%+v", first, second)
	}
	if first.State != ReviewStateCandidate || first.AutomaticActivation || first.RecommendedScope == nil ||
		!reflect.DeepEqual(first.RecommendedScope.EndpointClasses, []string{"public_content"}) ||
		first.RecommendedScope.MaxAction != core.ActionChallenge || first.RecommendedScope.CanaryBasisPoints != 100 ||
		first.RecommendedScope.MinMatureChallenges != DefaultMinMatureChallenges ||
		first.RecommendedScope.MinChallengeOutcomeCoverage != DefaultMinChallengeOutcomeCoverage ||
		first.RecommendedScope.MaxChallengeAbandonmentRate != DefaultMaxChallengeAbandonmentRate ||
		first.RecommendedScope.MaxChallengeFallbackRate != DefaultMaxChallengeFallbackRate {
		t.Fatalf("unsafe or unexpected proposal: %+v", first)
	}
}

func TestReviewProposalHoldsWhenNoPublicRiskyEndpointExists(t *testing.T) {
	report := candidateReport(2000, 0)
	report.Endpoints[0].ComputedRiskyActions = 0
	report.Endpoints[0].Evaluation.ComputedRiskyRate = shadowanalysis.Proportion(0, 2000)
	report.Decisions.Computed = shadowanalysis.ActionCounts{Allow: 2000}
	reportBytes := encodedReport(t, report)
	proposal, err := BuildReviewProposal(report, reportBytes, ReviewOptions{Stage: core.RuntimeModeCanary})
	if err != nil {
		t.Fatal(err)
	}
	if proposal.State != ReviewStateHold || proposal.RecommendedScope != nil || !hasGate(proposal.Gates, "ELIGIBLE_ENDPOINT_SCOPE", ReviewGateHold) {
		t.Fatalf("proposal did not hold: %+v", proposal)
	}
}

func TestReviewProposalHoldsWithoutBothConfirmedLabelClassesAtEndpoint(t *testing.T) {
	report := candidateReport(2000, 0)
	setTestEndpoints(&report, []shadowanalysis.EndpointSummary{
		testEndpoint("account", 200, 200, 0, 100, 100),
		testEndpoint("public_content", 1800, 0, 20, 0, 0),
	})
	reportBytes := encodedReport(t, report)
	proposal, err := BuildReviewProposal(report, reportBytes, ReviewOptions{Stage: core.RuntimeModeCanary})
	if err != nil {
		t.Fatal(err)
	}
	if proposal.State != ReviewStateHold || proposal.RecommendedScope != nil || !hasGate(proposal.Gates, "ELIGIBLE_ENDPOINT_SCOPE", ReviewGateHold) {
		t.Fatalf("proposal without both endpoint label classes did not hold: %+v", proposal)
	}
}

func TestReviewProposalRejectsUnknownFieldsAndTampering(t *testing.T) {
	report := candidateReport(2000, 0)
	reportBytes := encodedReport(t, report)
	proposal, err := BuildReviewProposal(report, reportBytes, ReviewOptions{Stage: core.RuntimeModeCanary})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(proposal)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	decoded["automatic_activation"] = true
	tampered, err := json.Marshal(decoded)
	if err != nil {
		t.Fatal(err)
	}
	var parsed ReviewProposal
	if err := json.Unmarshal(tampered, &parsed); err != nil {
		t.Fatal(err)
	}
	if err := parsed.Validate(); !errors.Is(err, ErrInvalidReview) {
		t.Fatalf("tampered automatic activation error=%v", err)
	}
}

func TestReviewProposalRejectsReorderedSourceWindowAndGateSet(t *testing.T) {
	report := candidateReport(2000, 0)
	reportBytes := encodedReport(t, report)
	proposal, err := BuildReviewProposal(report, reportBytes, ReviewOptions{Stage: core.RuntimeModeCanary})
	if err != nil {
		t.Fatal(err)
	}
	proposal.SourceFirstAt, proposal.SourceLastAt = proposal.SourceLastAt, proposal.SourceFirstAt
	if err := proposal.Validate(); !errors.Is(err, ErrInvalidReview) {
		t.Fatalf("reversed source window error=%v", err)
	}
	proposal, err = BuildReviewProposal(report, reportBytes, ReviewOptions{Stage: core.RuntimeModeCanary})
	if err != nil {
		t.Fatal(err)
	}
	proposal.Gates[0], proposal.Gates[1] = proposal.Gates[1], proposal.Gates[0]
	if err := proposal.Validate(); !errors.Is(err, ErrInvalidReview) {
		t.Fatalf("reordered gates error=%v", err)
	}
}

func TestEnforcementReviewAppliesExactChallengeBudgets(t *testing.T) {
	tests := []struct {
		name       string
		passed     uint64
		abandoned  uint64
		fallback   uint64
		unresolved uint64
		gate       string
	}{
		{name: "mature challenge sample", gate: "PREDECESSOR_CHALLENGE_SAMPLE"},
		{name: "terminal outcome coverage", passed: 160, unresolved: 40, gate: "CHALLENGE_OUTCOME_COVERAGE_BUDGET"},
		{name: "abandonment", passed: 180, abandoned: 20, gate: "CHALLENGE_ABANDONMENT_BUDGET"},
		{name: "accessible fallback", passed: 180, fallback: 20, gate: "CHALLENGE_FALLBACK_BUDGET"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			report := candidateReport(2000, MinimumCanaryDecisions)
			setCanaryChallengeFixture(&report, test.passed, test.abandoned, test.fallback, test.unresolved)
			proposal, err := BuildReviewProposal(report, encodedReport(t, report), ReviewOptions{Stage: core.RuntimeModeEnforce, PredecessorRolloutID: "canary-source"})
			if err != nil {
				t.Fatal(err)
			}
			if proposal.State != ReviewStateHold || proposal.RecommendedScope != nil || !hasGate(proposal.Gates, test.gate, ReviewGateHold) {
				t.Fatalf("budget did not hold enforcement: %+v", proposal)
			}
		})
	}
}

func TestReviewScopeBudgetTamperingIsRejected(t *testing.T) {
	report := candidateReport(2000, 0)
	proposal, err := BuildReviewProposal(report, encodedReport(t, report), ReviewOptions{Stage: core.RuntimeModeCanary})
	if err != nil {
		t.Fatal(err)
	}
	proposal.RecommendedScope.MaxChallengeAbandonmentRate += 0.01
	if err := proposal.Validate(); !errors.Is(err, ErrInvalidReview) {
		t.Fatalf("tampered challenge budget error=%v", err)
	}
}

func setCanaryChallengeFixture(report *shadowanalysis.Report, passed, abandoned, fallback, unresolved uint64) {
	mature := passed + abandoned + fallback + unresolved
	report.CanaryChallengeBudgets[0] = shadowanalysis.CanaryChallengeBudget{
		RolloutID: "canary-source", EndpointClass: "public_content", MatureChallenges: mature,
		ChallengePassed: passed, ChallengeAbandoned: abandoned, FallbackUsed: fallback, UnresolvedMatureChallenges: unresolved,
		TerminalOutcomeCoverage:  shadowanalysis.Proportion(passed+abandoned+fallback, mature),
		ChallengeAbandonmentRate: shadowanalysis.Proportion(abandoned, mature), FallbackRate: shadowanalysis.Proportion(fallback, mature),
	}
	for index := range report.Endpoints {
		if report.Endpoints[index].EndpointClass != "public_content" {
			continue
		}
		linked := &report.Endpoints[index].LinkedEvaluation
		linked.MatureChallenges = MinimumCanaryDecisions
		linked.ChallengePassed = MinimumCanaryDecisions - abandoned - fallback - unresolved
		linked.ChallengeFailed = 0
		linked.ChallengeAbandoned = abandoned
		linked.FallbackUsed = fallback
		linked.UnresolvedMatureChallenges = unresolved
		linked.AmbiguousChallengeOutcomes = 0
		linked.ChallengePassRate = shadowanalysis.Proportion(linked.ChallengePassed, linked.MatureChallenges)
		linked.ChallengeFailureRate = shadowanalysis.Proportion(0, linked.MatureChallenges)
		linked.ChallengeAbandonmentRate = shadowanalysis.Proportion(abandoned, linked.MatureChallenges)
		linked.FallbackRate = shadowanalysis.Proportion(fallback, linked.MatureChallenges)
		for sliceIndex := range report.EvaluationSlices {
			if report.EvaluationSlices[sliceIndex].EndpointClass == "public_content" {
				report.EvaluationSlices[sliceIndex].Evaluation = *linked
			}
		}
	}
}

func hasGate(gates []ReviewGate, code, status string) bool {
	for _, gate := range gates {
		if gate.Code == code && gate.Status == status {
			return true
		}
	}
	return false
}
