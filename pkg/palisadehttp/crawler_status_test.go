package palisadehttp

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCrawlerRegistryStatusReportingIsExplicitAuthenticatedAndClosed(t *testing.T) {
	var reports []crawlerStatusReport
	service := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/crawler-registry-status" || r.Header.Get("Authorization") != "Bearer adapter-key" {
			t.Errorf("request path/auth=%s/%q", r.URL.Path, r.Header.Get("Authorization"))
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var report crawlerStatusReport
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&report); err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		reports = append(reports, report)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer service.Close()
	registry, err := NewCrawlerRegistry([]CrawlerIdentity{{
		Name: "example-search", Class: CrawlerClassSearchIndexer,
		UserAgentTokens: []string{"ExampleSearchBot"}, CIDRs: []string{"192.0.2.0/24"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	middleware, err := New(Config{
		BaseURL: service.URL, APIKey: "adapter-key", Classifier: StaticClassification("read", "public_content"),
		FailureMode: FailClosed, CrawlerRegistry: registry, CrawlerRegistryReporting: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.August, 28, 12, 0, 0, 0, time.UTC)
	middleware.now = func() time.Time { return now }
	if err := middleware.ReportCrawlerRegistryStatus(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := middleware.ReportCrawlerRegistryStatus(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(reports) != 2 || reports[0].Sequence != 1 || reports[1].Sequence != 2 || reports[0].SourceID != reports[1].SourceID ||
		len(reports[0].SourceID) != 32 || !reports[0].ValidUntil.Equal(now.Add(DefaultCrawlerRegistryReportTTL)) ||
		reports[0].Status.State != "static" || reports[0].Status.IdentityCount != 1 || reports[0].Status.PrefixCount != 1 {
		t.Fatalf("reports=%+v", reports)
	}
	encoded, _ := json.Marshal(reports)
	for _, forbidden := range []string{"192.0.2.0", "ExampleSearchBot", "example-search", "registry.json"} {
		if bytes.Contains(encoded, []byte(forbidden)) {
			t.Fatalf("status report exposed %q: %s", forbidden, encoded)
		}
	}
}

func TestCrawlerRegistryReportingRequiresRegistryAndExplicitEnablement(t *testing.T) {
	base := Config{
		BaseURL: "http://127.0.0.1:8080", APIKey: "adapter-key", Classifier: StaticClassification("read", "public_content"),
		FailureMode: FailClosed, CrawlerRegistryReporting: true,
	}
	if _, err := New(base); err != ErrInvalidConfig {
		t.Fatalf("missing registry error=%v", err)
	}
	base.CrawlerRegistryReporting = false
	middleware, err := New(base)
	if err != nil {
		t.Fatal(err)
	}
	if err := middleware.ReportCrawlerRegistryStatus(context.Background()); err != ErrInvalidConfig {
		t.Fatalf("disabled report error=%v", err)
	}
	base.CrawlerRegistryReportTTL = time.Minute
	if _, err := New(base); err != ErrInvalidConfig {
		t.Fatalf("disabled reporting accepted TTL: %v", err)
	}
	registry, err := NewCrawlerRegistry([]CrawlerIdentity{{
		Name: "example-search", Class: CrawlerClassSearchIndexer,
		UserAgentTokens: []string{"ExampleSearchBot"}, CIDRs: []string{"192.0.2.0/24"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	base.CrawlerRegistry = registry
	base.CrawlerRegistryReporting = true
	for _, invalidTTL := range []time.Duration{time.Minute - time.Second, 25*time.Hour + time.Second} {
		base.CrawlerRegistryReportTTL = invalidTTL
		if _, err := New(base); err != ErrInvalidConfig {
			t.Fatalf("accepted invalid registry report TTL %s: %v", invalidTTL, err)
		}
	}
}

func TestCrawlerRegistryStatusRejectsNonAcceptedResponse(t *testing.T) {
	service := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusConflict)
	}))
	defer service.Close()
	registry, _ := NewCrawlerRegistry([]CrawlerIdentity{{
		Name: "example-search", Class: CrawlerClassSearchIndexer,
		UserAgentTokens: []string{"ExampleSearchBot"}, CIDRs: []string{"192.0.2.0/24"},
	}})
	middleware, err := New(Config{
		BaseURL: service.URL, APIKey: "adapter-key", Classifier: StaticClassification("read", "public_content"),
		FailureMode: FailClosed, CrawlerRegistry: registry, CrawlerRegistryReporting: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = middleware.ReportCrawlerRegistryStatus(context.Background())
	if err == nil || !strings.Contains(err.Error(), "HTTP 409") {
		t.Fatalf("conflict error=%v", err)
	}
}
