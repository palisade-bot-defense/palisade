package detector

import (
	"context"
	"testing"
	"time"

	"github.com/palisade-bot-defense/palisade/internal/core"
)

func TestVerifiedBotIdentityOnlyOffsetsAutomation(t *testing.T) {
	evidence, err := (ExternalVerdicts{}).Evaluate(context.Background(), core.DetectorInput{
		Request: core.DecisionRequest{EndpointClass: "public_content", Observations: core.Observations{
			VerifiedBot: true, CrawlerClass: core.CrawlerClassSearchIndexer,
			CrawlerVerification: core.CrawlerVerificationIPUARegistry, ExternalRiskScore: 1,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	verifiedFound := false
	externalRiskFound := false
	for _, item := range evidence {
		if item.Detector != "external_verdicts_v3" {
			t.Fatalf("detector ID = %s, want external_verdicts_v3", item.Detector)
		}
		if item.Code == "VERIFIED_PUBLIC_CRAWLER" {
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

func TestUnqualifiedCrawlerClaimCreatesNoBenignEvidence(t *testing.T) {
	tests := []core.DecisionRequest{
		{EndpointClass: "public_content", Observations: core.Observations{VerifiedBot: true}},
		{EndpointClass: "login", Observations: core.Observations{VerifiedBot: true, CrawlerClass: core.CrawlerClassSearchIndexer, CrawlerVerification: core.CrawlerVerificationIPUARegistry}},
		{EndpointClass: "public_content", Observations: core.Observations{VerifiedBot: true, CrawlerClass: core.CrawlerClassTrainingCrawler, CrawlerVerification: core.CrawlerVerificationIPUARegistry}},
	}
	for _, request := range tests {
		evidence, err := (ExternalVerdicts{}).Evaluate(context.Background(), core.DetectorInput{Request: request})
		if err != nil {
			t.Fatal(err)
		}
		for _, item := range evidence {
			if item.Direction == core.DirectionBenign {
				t.Fatalf("unqualified claim produced benign evidence: %+v", evidence)
			}
		}
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

func TestEdgeIntelligenceIsSuspiciousOnlyAndClosed(t *testing.T) {
	tests := []struct {
		name         string
		observations core.Observations
		wantCodes    []string
	}{
		{name: "browser and residential are not human evidence", observations: core.Observations{
			EdgeFingerprintClass: "browser_consistent", EdgeFingerprintMethod: "tls_http2",
			NetworkReputation: "low_risk", NetworkType: "residential",
		}},
		{name: "automation and high reputation combine", observations: core.Observations{
			EdgeFingerprintClass: "automation_consistent", EdgeFingerprintMethod: "tls",
			NetworkReputation: "high_risk", NetworkType: "hosting",
		}, wantCodes: []string{"EDGE_AUTOMATION_PROFILE", "NETWORK_REPUTATION_HIGH", "NETWORK_HOSTING_CONTEXT"}},
		{name: "anomaly and anonymizer remain conservative context", observations: core.Observations{
			EdgeFingerprintClass: "anomalous", EdgeFingerprintMethod: "http2",
			NetworkReputation: "elevated_risk", NetworkType: "anonymizer",
		}, wantCodes: []string{"EDGE_PROTOCOL_ANOMALY", "NETWORK_REPUTATION_ELEVATED", "NETWORK_ANONYMIZER_CONTEXT"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			evidence, err := (EdgeIntelligence{}).Evaluate(context.Background(), core.DetectorInput{Request: core.DecisionRequest{Observations: test.observations}})
			if err != nil {
				t.Fatal(err)
			}
			if len(evidence) != len(test.wantCodes) {
				t.Fatalf("evidence=%+v, want codes=%v", evidence, test.wantCodes)
			}
			for index, item := range evidence {
				if item.Code != test.wantCodes[index] || item.Detector != "edge_intelligence_v1" || item.Direction != core.DirectionSuspicious {
					t.Fatalf("unexpected edge evidence: %+v", item)
				}
			}
		})
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

func TestBrowserSequenceRequiresServerVerifiedEvents(t *testing.T) {
	tests := []struct {
		name         string
		observations core.Observations
		wantSequence bool
		wantConflict bool
	}{
		{
			name:         "unverified count cannot look benign",
			observations: core.Observations{UserAgentPresent: true, BrowserEventCount: 10},
		},
		{
			name: "verified sequence is continuity evidence",
			observations: core.Observations{
				UserAgentPresent: true, BrowserEventCount: 10, BrowserEventsVerified: true,
			},
			wantSequence: true,
		},
		{
			name: "unverified count cannot manufacture a contradiction",
			observations: core.Observations{
				BrowserEventCount: 10,
			},
		},
		{
			name: "verified count exposes protocol contradiction",
			observations: core.Observations{
				BrowserEventCount: 10, BrowserEventsVerified: true,
			},
			wantConflict: true,
		},
		{
			name: "missing sensor is neutral when user agent exists",
			observations: core.Observations{
				UserAgentPresent: true, BrowserEventsVerified: true,
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			evidence, err := (ProtocolConsistency{}).Evaluate(context.Background(), core.DetectorInput{
				Request: core.DecisionRequest{Observations: test.observations},
			})
			if err != nil {
				t.Fatal(err)
			}
			sequence := false
			conflict := false
			for _, item := range evidence {
				if item.Detector != "protocol_consistency_v2" {
					t.Fatalf("detector ID = %s, want protocol_consistency_v2", item.Detector)
				}
				sequence = sequence || item.Code == "BROWSER_SEQUENCE_PRESENT"
				conflict = conflict || item.Code == "BROWSER_PROTOCOL_CONTRADICTION"
			}
			if sequence != test.wantSequence || conflict != test.wantConflict {
				t.Fatalf("evidence=%+v sequence=%t conflict=%t", evidence, sequence, conflict)
			}
		})
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

func TestNavigationGraphEmitsOnlyConservativeSweepEvidence(t *testing.T) {
	first := time.Unix(1_800_000_000, 0).UTC()
	tests := []struct {
		name     string
		snapshot core.SessionSnapshot
		want     bool
	}{
		{name: "broad fast sweep", snapshot: core.SessionSnapshot{FirstSeen: first, LastSeen: first.Add(time.Minute), DistinctEndpointClasses: 5, EndpointTransitions: 6}, want: true},
		{name: "two surface bounce poisoning", snapshot: core.SessionSnapshot{FirstSeen: first, LastSeen: first.Add(time.Minute), DistinctEndpointClasses: 2, EndpointTransitions: 500}},
		{name: "slow broad navigation", snapshot: core.SessionSnapshot{FirstSeen: first, LastSeen: first.Add(10 * time.Minute), DistinctEndpointClasses: 8, EndpointTransitions: 20}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			evidence, err := (NavigationGraph{}).Evaluate(context.Background(), core.DetectorInput{Session: test.snapshot})
			if err != nil {
				t.Fatal(err)
			}
			if (len(evidence) == 1) != test.want {
				t.Fatalf("evidence = %+v", evidence)
			}
			if test.want && (evidence[0].Code != "NAVIGATION_SURFACE_SWEEP" || evidence[0].Detector != "navigation_graph_v1" || evidence[0].Dimension != core.DimensionIntent || evidence[0].Direction != core.DirectionSuspicious) {
				t.Fatalf("unexpected navigation evidence = %+v", evidence)
			}
		})
	}
}

func TestDecoyInteractionIsSeparateIntentEvidence(t *testing.T) {
	for _, hits := range []int{0, 1, 100} {
		evidence, err := (DecoyInteraction{}).Evaluate(context.Background(), core.DetectorInput{
			Request: core.DecisionRequest{Observations: core.Observations{HoneypotHits: hits}},
		})
		if err != nil {
			t.Fatal(err)
		}
		if hits == 0 && len(evidence) != 0 {
			t.Fatalf("zero hits evidence = %+v", evidence)
		}
		if hits > 0 && (len(evidence) != 1 || evidence[0].Detector != "decoy_interaction_v1" || evidence[0].Dimension != core.DimensionIntent || evidence[0].Strength > 1) {
			t.Fatalf("hits=%d evidence=%+v", hits, evidence)
		}
	}
}
