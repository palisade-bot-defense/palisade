package palisadehttp

import (
	"net/http/httptest"
	"net/netip"
	"testing"
)

func TestCrawlerRegistryRequiresAddressAndUserAgent(t *testing.T) {
	registry, err := NewCrawlerRegistry([]CrawlerIdentity{{
		Name: "example-search", Class: CrawlerClassSearchIndexer,
		UserAgentTokens: []string{"ExampleSearchBot"}, CIDRs: []string{"192.0.2.0/24", "2001:db8::/32"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name      string
		userAgent string
		address   string
		verified  bool
	}{
		{name: "both factors", userAgent: "Mozilla/5.0 compatible ExampleSearchBot/1.0", address: "192.0.2.15", verified: true},
		{name: "case insensitive token", userAgent: "examplesearchbot/1.0", address: "2001:db8::15", verified: true},
		{name: "spoofed user agent", userAgent: "ExampleSearchBot/1.0", address: "198.51.100.10"},
		{name: "matching network without claim", userAgent: "Mozilla/5.0", address: "192.0.2.15"},
		{name: "embedded token spoof", userAgent: "NotExampleSearchBotFake/1.0", address: "192.0.2.15"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			verified, class, method := registry.verify(test.userAgent, netip.MustParseAddr(test.address))
			if verified != test.verified {
				t.Fatalf("verified=%t class=%s method=%s", verified, class, method)
			}
			if verified && (class != CrawlerClassSearchIndexer || method != CrawlerVerificationIPUARegistry) {
				t.Fatalf("unexpected verified tuple: %s/%s", class, method)
			}
			if !verified && (class != CrawlerClassUnknown || method != CrawlerVerificationUnknown) {
				t.Fatalf("unverified result leaked a classification: %s/%s", class, method)
			}
		})
	}
}

func TestCrawlerRegistryRejectsAmbiguousMatch(t *testing.T) {
	registry, err := NewCrawlerRegistry([]CrawlerIdentity{
		{Name: "search", Class: CrawlerClassSearchIndexer, UserAgentTokens: []string{"SharedCrawler"}, CIDRs: []string{"192.0.2.0/24"}},
		{Name: "training", Class: CrawlerClassTrainingCrawler, UserAgentTokens: []string{"SharedCrawler"}, CIDRs: []string{"192.0.2.0/25"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	verified, class, method := registry.verify("SharedCrawler/1.0", netip.MustParseAddr("192.0.2.10"))
	if verified || class != CrawlerClassUnknown || method != CrawlerVerificationUnknown {
		t.Fatalf("ambiguous match was trusted: %t/%s/%s", verified, class, method)
	}
}

func TestCrawlerRegistryRejectsUnsafeConfiguration(t *testing.T) {
	tests := []CrawlerIdentity{
		{Name: "private", Class: CrawlerClassSearchIndexer, UserAgentTokens: []string{"ExampleBot"}, CIDRs: []string{"10.0.0.0/8"}},
		{Name: "host-bits", Class: CrawlerClassSearchIndexer, UserAgentTokens: []string{"ExampleBot"}, CIDRs: []string{"192.0.2.1/24"}},
		{Name: "generic", Class: CrawlerClassSearchIndexer, UserAgentTokens: []string{"bot"}, CIDRs: []string{"192.0.2.0/24"}},
		{Name: "unknown", Class: CrawlerClassUnknown, UserAgentTokens: []string{"ExampleBot"}, CIDRs: []string{"192.0.2.0/24"}},
	}
	for _, entry := range tests {
		t.Run(entry.Name, func(t *testing.T) {
			if _, err := NewCrawlerRegistry([]CrawlerIdentity{entry}); err != ErrInvalidConfig {
				t.Fatalf("error=%v, want ErrInvalidConfig", err)
			}
		})
	}
}

func TestCrawlerVerificationUsesOnlyTrustedAddressBoundary(t *testing.T) {
	registry, err := NewCrawlerRegistry([]CrawlerIdentity{{
		Name: "example-search", Class: CrawlerClassSearchIndexer,
		UserAgentTokens: []string{"ExampleSearchBot"}, CIDRs: []string{"192.0.2.0/24"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	normalizer, err := newTransportNormalizer(Config{
		TrustedProxyCIDRs: []string{"203.0.113.0/24"}, TrustedClientIPHeader: "CF-Connecting-IP", TrustedProtoHeader: "X-Forwarded-Proto",
	})
	if err != nil {
		t.Fatal(err)
	}

	direct := httptest.NewRequest("GET", "https://origin.example/", nil)
	direct.RemoteAddr = "198.51.100.7:443"
	direct.Header.Set("CF-Connecting-IP", "192.0.2.15")
	direct.Header.Set("User-Agent", "ExampleSearchBot/1.0")
	_, _, source, address, ok := normalizer.normalizeWithAddress(direct)
	verified, _, _ := registry.verify(direct.UserAgent(), address)
	if source != ClientAddressSourceDirect || !ok || verified {
		t.Fatalf("direct spoof accepted: source=%s address=%s ok=%t verified=%t", source, address, ok, verified)
	}

	proxied := httptest.NewRequest("GET", "https://origin.example/", nil)
	proxied.RemoteAddr = "203.0.113.7:443"
	proxied.Header.Set("CF-Connecting-IP", "192.0.2.15")
	proxied.Header.Set("X-Forwarded-Proto", "https")
	proxied.Header.Set("User-Agent", "ExampleSearchBot/1.0")
	_, _, source, address, ok = normalizer.normalizeWithAddress(proxied)
	verified, class, method := registry.verify(proxied.UserAgent(), address)
	if source != ClientAddressSourceTrustedProxy || !ok || !verified || class != CrawlerClassSearchIndexer || method != CrawlerVerificationIPUARegistry {
		t.Fatalf("trusted verification failed: source=%s address=%s ok=%t verified=%t class=%s method=%s", source, address, ok, verified, class, method)
	}
}
