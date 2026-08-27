package detector

import (
	"context"
	"testing"
	"time"

	"github.com/palisade-bot-defense/palisade/internal/core"
)

func TestVerifiedBotIdentityOnlyOffsetsAutomation(t *testing.T) {
	evidence, err := (ExternalVerdicts{}).Evaluate(context.Background(), core.DetectorInput{
		Request: core.DecisionRequest{Observations: core.Observations{VerifiedBot: true, ExternalRiskScore: 1}},
	})
	if err != nil {
		t.Fatal(err)
	}
	verifiedFound := false
	externalRiskFound := false
	for _, item := range evidence {
		if item.Detector != "external_verdicts_v2" {
			t.Fatalf("detector ID = %s, want external_verdicts_v2", item.Detector)
		}
		if item.Code == "VERIFIED_BOT_IDENTITY" {
			verifiedFound = true
			if item.Dimension != core.DimensionAutomation {
				t.Fatalf("verified identity dimension = %s, want automation", item.Dimension)
			}
		}
		if item.Code == "EXTERNAL_RISK" {
			externalRiskFound = true
			if item.Dimension != core.DimensionIntent {
				t.Fatalf("external risk dimension = %s, want intent", item.Dimension)
			}
		}
	}
	if !verifiedFound || !externalRiskFound {
		t.Fatalf("missing expected evidence: %+v", evidence)
	}
}

func TestSolvedChallengeIsNotHumanEvidence(t *testing.T) {
	evidence, err := (ExternalVerdicts{}).Evaluate(context.Background(), core.DetectorInput{
		Request: core.DecisionRequest{Observations: core.Observations{ChallengeVerdict: "passed"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(evidence) != 0 {
		t.Fatalf("a solved proof-of-work was treated as benign evidence: %+v", evidence)
	}
}

func TestSignedSessionAffectsContinuityOnly(t *testing.T) {
	evidence, err := (ProtocolConsistency{}).Evaluate(context.Background(), core.DetectorInput{
		Request: core.DecisionRequest{Observations: core.Observations{ServerSessionVerified: true}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(evidence) != 2 {
		// UA_MISSING remains separate suspicious automation evidence; the cookie
		// must not erase it.
		t.Fatalf("unexpected evidence: %+v", evidence)
	}
	found := false
	for _, item := range evidence {
		if item.Code == "SERVER_SESSION_VERIFIED" {
			found = true
			if item.Dimension != core.DimensionContinuity || item.Direction != core.DirectionBenign {
				t.Fatalf("signed session changed the wrong dimension: %+v", item)
			}
		}
	}
	if !found {
		t.Fatalf("missing signed-session evidence: %+v", evidence)
	}
}

func TestNoindexCompareIsIntentEvidenceOnly(t *testing.T) {
	evidence, err := (CampaignSurface{}).Evaluate(context.Background(), core.DetectorInput{
		Request: core.DecisionRequest{EndpointClass: "compare_noindex"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(evidence) != 1 || evidence[0].Code != "COMPARE_NOINDEX_CAMPAIGN_SURFACE" || evidence[0].Dimension != core.DimensionIntent {
		t.Fatalf("unexpected noindex campaign evidence: %+v", evidence)
	}
	for _, endpoint := range []string{"compare_index", "public_content", "account"} {
		evidence, err := (CampaignSurface{}).Evaluate(context.Background(), core.DetectorInput{
			Request: core.DecisionRequest{EndpointClass: endpoint},
		})
		if err != nil || len(evidence) != 0 {
			t.Fatalf("endpoint %q produced campaign evidence: %+v err=%v", endpoint, evidence, err)
		}
	}
}

func TestSequenceVelocityUsesConservativeDataBoundThresholds(t *testing.T) {
	tests := []struct {
		name       string
		count      uint64
		duration   time.Duration
		wantCodes  []string
		rejectCode string
	}{
		{name: "legacy threshold no longer escalates", count: 41, duration: 30 * time.Second, rejectCode: "SESSION_BURST"},
		{name: "fast burst", count: 50, duration: 30 * time.Second, wantCodes: []string{"SESSION_BURST_FAST"}},
		{name: "slow high volume", count: 100, duration: 2 * time.Minute, wantCodes: []string{"SESSION_VOLUME_HIGH"}, rejectCode: "SESSION_BURST_FAST"},
		{name: "fast high volume combines evidence", count: 100, duration: 30 * time.Second, wantCodes: []string{"SESSION_VOLUME_HIGH", "SESSION_BURST_FAST"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			first := time.Unix(1_800_000_000, 0).UTC()
			evidence, err := (SequenceVelocity{}).Evaluate(context.Background(), core.DetectorInput{
				Session: core.SessionSnapshot{
					FirstSeen: first, LastSeen: first.Add(test.duration), RequestCount: test.count,
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			codes := make(map[string]bool)
			for _, item := range evidence {
				if item.Detector != "sequence_velocity_v2" {
					t.Fatalf("detector ID = %s, want sequence_velocity_v2", item.Detector)
				}
				codes[item.Code] = true
			}
			for _, expected := range test.wantCodes {
				if !codes[expected] {
					t.Fatalf("missing %s in %+v", expected, evidence)
				}
			}
			if test.rejectCode != "" && codes[test.rejectCode] {
				t.Fatalf("unexpected %s in %+v", test.rejectCode, evidence)
			}
		})
	}
}
