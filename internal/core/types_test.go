package core

import "testing"

func TestVerifiedPublicCrawlerRequiresCompleteEligibleTuple(t *testing.T) {
	verifiedSearch := Observations{
		VerifiedBot: true, CrawlerClass: CrawlerClassSearchIndexer,
		CrawlerVerification: CrawlerVerificationIPUARegistry,
	}
	tests := []struct {
		name        string
		observation Observations
		endpoint    string
		want        bool
	}{
		{name: "verified search on public content", observation: verifiedSearch, endpoint: "public_content", want: true},
		{name: "verified answer engine on index page", observation: Observations{VerifiedBot: true, CrawlerClass: CrawlerClassAnswerEngine, CrawlerVerification: CrawlerVerificationFCrDNSUA}, endpoint: "compare_index", want: true},
		{name: "signed user-triggered agent", observation: Observations{VerifiedBot: true, CrawlerClass: CrawlerClassUserTriggeredAgent, CrawlerVerification: CrawlerVerificationHTTPSignature}, endpoint: "other_public", want: true},
		{name: "user agent claim only", observation: Observations{VerifiedBot: true, CrawlerClass: CrawlerClassSearchIndexer}, endpoint: "public_content"},
		{name: "verification without class", observation: Observations{VerifiedBot: true, CrawlerVerification: CrawlerVerificationIPUARegistry}, endpoint: "public_content"},
		{name: "class without identity", observation: Observations{CrawlerClass: CrawlerClassSearchIndexer, CrawlerVerification: CrawlerVerificationIPUARegistry}, endpoint: "public_content"},
		{name: "login never qualifies", observation: verifiedSearch, endpoint: "login"},
		{name: "account never qualifies", observation: verifiedSearch, endpoint: "account"},
		{name: "checkout never qualifies", observation: verifiedSearch, endpoint: "checkout"},
		{name: "noindex never qualifies", observation: verifiedSearch, endpoint: "compare_noindex"},
		{name: "training is policy-controlled", observation: Observations{VerifiedBot: true, CrawlerClass: CrawlerClassTrainingCrawler, CrawlerVerification: CrawlerVerificationIPUARegistry}, endpoint: "public_content"},
		{name: "monitoring is not an indexer", observation: Observations{VerifiedBot: true, CrawlerClass: CrawlerClassMonitoring, CrawlerVerification: CrawlerVerificationIPUARegistry}, endpoint: "public_content"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := VerifiedPublicCrawler(test.observation, test.endpoint); got != test.want {
				t.Fatalf("VerifiedPublicCrawler=%t, want %t", got, test.want)
			}
		})
	}
}

func TestCrawlerEnumsAreClosed(t *testing.T) {
	if _, ok := NormalizeCrawlerClass("crawler-name-or-fingerprint"); ok {
		t.Fatal("free-form crawler class accepted")
	}
	if _, ok := NormalizeCrawlerVerification("user-agent-only"); ok {
		t.Fatal("weak or free-form verification accepted")
	}
}

func TestValidEdgeIntelligenceRequiresClosedPairedClasses(t *testing.T) {
	valid := [][4]string{
		{"", "", "", ""},
		{"unknown", "unknown", "unknown", "unknown"},
		{"browser_consistent", "tls_http2", "low_risk", "residential"},
		{"automation_consistent", "tls", "high_risk", "hosting"},
	}
	for _, values := range valid {
		if !ValidEdgeIntelligence(values[0], values[1], values[2], values[3]) {
			t.Fatalf("valid values rejected: %v", values)
		}
	}
	invalid := [][4]string{
		{"ja4:a1b2c3", "tls", "unknown", "unknown"},
		{"automation_consistent", "", "unknown", "unknown"},
		{"", "http2", "unknown", "unknown"},
		{"unknown", "unknown", "provider-score", "unknown"},
		{"unknown", "unknown", "unknown", "AS13335"},
	}
	for _, values := range invalid {
		if ValidEdgeIntelligence(values[0], values[1], values[2], values[3]) {
			t.Fatalf("invalid values accepted: %v", values)
		}
	}
}
