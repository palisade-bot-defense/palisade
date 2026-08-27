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
	report.Endpoints = []shadowanalysis.EndpointSummary{
		testEndpoint("account", 500, 200, 1, 100, 100),
		testEndpoint("compare_index", 500, 200, 10, 100, 100),
		testEndpoint("other_public", 500, 200, 20, 100, 100),
		testEndpoint("public_content", 500, 200, 5, 100, 100),
	}
	report.Outcomes.Total = 800
	report.Outcomes.Coverage = 0.4
	report.Outcomes.HumanConfirmed = 400
	report.Outcomes.OperatorConfirmedAbuse = 400
	report.Source.Outcomes = 800
	report.Source.Records = report.Source.Decisions + report.Source.Outcomes
	report.Decisions.Computed.Allow = 1964
	report.Decisions.Computed.Throttle = 36
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
		first.RecommendedScope.MaxAction != core.ActionThrottle || first.RecommendedScope.CanaryBasisPoints != 100 {
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
	report.Endpoints = []shadowanalysis.EndpointSummary{
		testEndpoint("account", 200, 200, 0, 100, 100),
		testEndpoint("public_content", 1800, 0, 20, 0, 0),
	}
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

func hasGate(gates []ReviewGate, code, status string) bool {
	for _, gate := range gates {
		if gate.Code == code && gate.Status == status {
			return true
		}
	}
	return false
}
