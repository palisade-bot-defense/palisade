package palisadecontract

import "testing"

func TestClosedValueSetsAcceptOnlyPublishedValues(t *testing.T) {
	sets := []struct {
		name     string
		values   func() []string
		validate func(string) bool
	}{
		{"request actions", RequestActions, ValidRequestAction},
		{"proof actions", ProofActions, ValidProofAction},
		{"endpoint classes", EndpointClasses, ValidEndpointClass},
		{"evaluation cohorts", EvaluationCohorts, ValidEvaluationCohort},
		{"challenge verdicts", ChallengeVerdicts, ValidChallengeVerdict},
		{"crawler classes", CrawlerClasses, ValidCrawlerClass},
		{"crawler verifications", CrawlerVerifications, ValidCrawlerVerification},
		{"transport protocols", TransportProtocols, ValidTransportProtocol},
		{"transport securities", TransportSecurities, ValidTransportSecurity},
		{"client address sources", ClientAddressSources, ValidClientAddressSource},
		{"edge fingerprint classes", EdgeFingerprintClasses, ValidEdgeFingerprintClass},
		{"edge fingerprint methods", EdgeFingerprintMethods, ValidEdgeFingerprintMethod},
		{"network reputations", NetworkReputations, ValidNetworkReputation},
		{"network types", NetworkTypes, ValidNetworkType},
		{"decision actions", DecisionActions, ValidDecisionAction},
		{"runtime modes", RuntimeModes, ValidRuntimeMode},
		{"enforcement handlings", EnforcementHandlings, ValidEnforcementHandling},
	}
	for _, set := range sets {
		t.Run(set.name, func(t *testing.T) {
			values := set.values()
			if len(values) == 0 {
				t.Fatal("published set is empty")
			}
			seen := map[string]bool{}
			for _, value := range values {
				if value == "" || seen[value] || !set.validate(value) {
					t.Fatalf("invalid or duplicate published value %q", value)
				}
				seen[value] = true
			}
			for _, invalid := range []string{"", "raw/value", "vendor-score-92", "unknown\npoison"} {
				if set.validate(invalid) {
					t.Fatalf("accepted free-form value %q", invalid)
				}
			}
			values[0] = "mutated"
			if set.validate("mutated") || !set.validate(set.values()[0]) {
				t.Fatal("caller mutated the canonical value set")
			}
		})
	}
	if ValidRequestAction(EventProofAction) || !ValidProofAction(EventProofAction) {
		t.Fatal("events proof action leaked into the DecisionRequest action set")
	}
}

func TestCrossFieldInvariantsFailClosed(t *testing.T) {
	for _, test := range []struct {
		name                string
		verified            bool
		class, verification string
		want                bool
	}{
		{"omitted unverified", false, "", "", true},
		{"closed unverified context", false, "training_crawler", "ip_ua_registry", true},
		{"verified pair", true, "search_indexer", "ip_ua_registry", true},
		{"verified class missing", true, "", "ip_ua_registry", false},
		{"verified method unknown", true, "search_indexer", "unknown", false},
		{"raw class", false, "crawler-product", "ip_ua_registry", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := ValidCrawlerIdentity(test.verified, test.class, test.verification); got != test.want {
				t.Fatalf("crawler identity = %v, want %v", got, test.want)
			}
		})
	}

	for _, test := range []struct {
		name                                   string
		class, method, reputation, networkType string
		want                                   bool
	}{
		{"omitted", "", "", "", "", true},
		{"unknown", "unknown", "unknown", "unknown", "unknown", true},
		{"paired", "automation_consistent", "tls_http2", "high_risk", "hosting", true},
		{"class without method", "anomalous", "unknown", "unknown", "unknown", false},
		{"method without class", "unknown", "tls", "unknown", "unknown", false},
		{"raw fingerprint", "ja4:a1b2", "tls", "unknown", "unknown", false},
		{"raw ASN", "unknown", "unknown", "unknown", "AS13335", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := ValidEdgeIntelligence(test.class, test.method, test.reputation, test.networkType); got != test.want {
				t.Fatalf("edge intelligence = %v, want %v", got, test.want)
			}
		})
	}
}
