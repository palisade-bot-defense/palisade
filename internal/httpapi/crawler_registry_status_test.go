package httpapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/palisade-bot-defense/palisade/internal/token"
)

func TestCrawlerRegistryStatusStoreIsMonotonicAndExpiryAware(t *testing.T) {
	now := time.Date(2026, time.August, 28, 12, 0, 0, 0, time.UTC)
	store := newCrawlerRegistryStatusStore()
	report := testCrawlerRegistryStatusReport(now, "0123456789abcdef0123456789abcdef", 7, strings.Repeat("a", 64))
	report.Status.ExpiresAt = now.Add(2 * time.Minute)
	if err := store.observe(report, now); err != nil {
		t.Fatal(err)
	}
	if err := store.observe(report, now); err != nil {
		t.Fatalf("idempotent report error=%v", err)
	}
	snapshot := store.snapshot(now)
	if snapshot.State != "current" || snapshot.Sources != 1 || snapshot.CurrentSources != 1 || snapshot.MinimumRevision != 7 ||
		snapshot.MaximumRevision != 7 || snapshot.DistinctDigests != 1 || snapshot.EarliestExpiresAt == nil || snapshot.LastReportedAt == nil {
		t.Fatalf("current snapshot=%+v", snapshot)
	}
	if expired := store.snapshot(now.Add(3 * time.Minute)); expired.State != "attention" || expired.ExpiredSources != 1 || expired.CurrentSources != 0 {
		t.Fatalf("expired snapshot=%+v", expired)
	}
	conflict := report
	conflict.Status.Revision = 8
	if err := store.observe(conflict, now); !errors.Is(err, errCrawlerRegistryStatusConflict) {
		t.Fatalf("same-sequence conflict error=%v", err)
	}
	report.Sequence = 2
	report.ReportedAt = now.Add(time.Minute)
	report.Status.Revision = 8
	report.Status.DigestSHA256 = strings.Repeat("b", 64)
	if err := store.observe(report, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if updated := store.snapshot(now.Add(time.Minute)); updated.State != "current" || updated.MinimumRevision != 8 || updated.DistinctDigests != 1 {
		t.Fatalf("updated snapshot=%+v", updated)
	}
	if pruned := store.snapshot(now.Add(6 * time.Minute)); pruned.State != "unavailable" || pruned.Sources != 0 {
		t.Fatalf("expired heartbeat was not pruned: %+v", pruned)
	}
}

func TestCrawlerRegistryStatusStoreDetectsReplicaDriftAndClosedStates(t *testing.T) {
	now := time.Date(2026, time.August, 28, 12, 0, 0, 0, time.UTC)
	store := newCrawlerRegistryStatusStore()
	first := testCrawlerRegistryStatusReport(now, "0123456789abcdef0123456789abcdef", 7, strings.Repeat("a", 64))
	second := testCrawlerRegistryStatusReport(now, "abcdef0123456789abcdef0123456789", 8, strings.Repeat("b", 64))
	if err := store.observe(first, now); err != nil {
		t.Fatal(err)
	}
	if err := store.observe(second, now); err != nil {
		t.Fatal(err)
	}
	snapshot := store.snapshot(now)
	if snapshot.State != "attention" || snapshot.Sources != 2 || snapshot.CurrentSources != 2 || snapshot.MinimumRevision != 7 || snapshot.MaximumRevision != 8 || snapshot.DistinctDigests != 2 {
		t.Fatalf("drift snapshot=%+v", snapshot)
	}

	empty := crawlerRegistryStatusReport{
		SchemaVersion: crawlerRegistryStatusSchemaVersion, SourceID: "fedcba9876543210fedcba9876543210", Sequence: 1, ReportedAt: now, ValidUntil: now.Add(5 * time.Minute),
		Status: crawlerRegistryStatus{State: "empty"},
	}
	static := crawlerRegistryStatusReport{
		SchemaVersion: crawlerRegistryStatusSchemaVersion, SourceID: "00112233445566778899aabbccddeeff", Sequence: 1, ReportedAt: now, ValidUntil: now.Add(5 * time.Minute),
		Status: crawlerRegistryStatus{State: "static", IdentityCount: 1, PrefixCount: 2},
	}
	if err := store.observe(empty, now); err != nil {
		t.Fatal(err)
	}
	if err := store.observe(static, now); err != nil {
		t.Fatal(err)
	}
	snapshot = store.snapshot(now)
	if snapshot.EmptySources != 1 || snapshot.StaticSources != 1 || snapshot.State != "attention" {
		t.Fatalf("closed state snapshot=%+v", snapshot)
	}
}

func TestCrawlerRegistryStatusRejectsPoisoning(t *testing.T) {
	now := time.Date(2026, time.August, 28, 12, 0, 0, 0, time.UTC)
	for name, mutate := range map[string]func(*crawlerRegistryStatusReport){
		"source label":      func(report *crawlerRegistryStatusReport) { report.SourceID = "customer-production-origin" },
		"future":            func(report *crawlerRegistryStatusReport) { report.ReportedAt = now.Add(2 * time.Minute) },
		"expired heartbeat": func(report *crawlerRegistryStatusReport) { report.ValidUntil = now },
		"short heartbeat": func(report *crawlerRegistryStatusReport) {
			report.ValidUntil = report.ReportedAt.Add(time.Minute - time.Second)
		},
		"long heartbeat": func(report *crawlerRegistryStatusReport) {
			report.ValidUntil = report.ReportedAt.Add(25*time.Hour + time.Second)
		},
		"free state": func(report *crawlerRegistryStatusReport) { report.Status.State = "vendor-ready" },
		"bad digest": func(report *crawlerRegistryStatusReport) { report.Status.DigestSHA256 = "raw/path-or-vendor" },
		"bad count":  func(report *crawlerRegistryStatusReport) { report.Status.PrefixCount = 4097 },
		"future issue": func(report *crawlerRegistryStatusReport) {
			report.Status.IssuedAt = now.Add(6 * time.Minute)
			report.Status.ExpiresAt = now.Add(time.Hour)
		},
		"false current": func(report *crawlerRegistryStatusReport) {
			report.Status.ExpiresAt = now
		},
	} {
		t.Run(name, func(t *testing.T) {
			report := testCrawlerRegistryStatusReport(now, "0123456789abcdef0123456789abcdef", 7, strings.Repeat("a", 64))
			mutate(&report)
			if err := newCrawlerRegistryStatusStore().observe(report, now); !errors.Is(err, errInvalidCrawlerRegistryStatus) {
				t.Fatalf("poisoning error=%v", err)
			}
		})
	}
}

func TestCrawlerRegistryStatusWireRequiresClosedZeroValuedFields(t *testing.T) {
	missingRevision := `{"state":"empty","issued_at":"0001-01-01T00:00:00Z","expires_at":"0001-01-01T00:00:00Z","digest_sha256":"","identity_count":0,"prefix_count":0}`
	var status crawlerRegistryStatus
	if err := json.Unmarshal([]byte(missingRevision), &status); !errors.Is(err, errInvalidCrawlerRegistryStatus) {
		t.Fatalf("missing required zero-valued field error=%v", err)
	}
	complete := `{"state":"empty","revision":0,"issued_at":"0001-01-01T00:00:00Z","expires_at":"0001-01-01T00:00:00Z","digest_sha256":"","identity_count":0,"prefix_count":0}`
	if err := json.Unmarshal([]byte(complete), &status); err != nil || status.State != "empty" {
		t.Fatalf("complete closed status=%+v error=%v", status, err)
	}
}

func TestCrawlerRegistryStatusHTTPContractIsAuthenticatedAndAggregateOnly(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	tokens, _ := token.NewService([]byte("0123456789abcdef0123456789abcdef"), token.NewMemoryNonceStore())
	server := New(fakeEngine{}, tokens, "api-key", slog.Default())
	report := testCrawlerRegistryStatusReport(now, "0123456789abcdef0123456789abcdef", 7, strings.Repeat("a", 64))
	body, _ := json.Marshal(report)

	unauthorized := httptest.NewRecorder()
	server.Handler().ServeHTTP(unauthorized, httptest.NewRequest(http.MethodPost, "/v1/crawler-registry-status", bytes.NewReader(body)))
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized status=%d", unauthorized.Code)
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/crawler-registry-status", bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer api-key")
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusAccepted {
		t.Fatalf("accepted status=%d body=%s", response.Code, response.Body.String())
	}
	summary := server.adminSummary(now).CrawlerRegistry
	if summary.State != "current" || summary.Sources != 1 || summary.MaximumRevision != 7 {
		t.Fatalf("admin registry status=%+v", summary)
	}
	encoded, _ := json.Marshal(summary)
	for _, forbidden := range []string{"192.0.2.10", "ExampleSearchBot", "vendor-search", "/private/registry.json"} {
		if bytes.Contains(encoded, []byte(forbidden)) {
			t.Fatalf("admin registry status exposed %q: %s", forbidden, encoded)
		}
	}
}

func testCrawlerRegistryStatusReport(now time.Time, sourceID string, revision uint64, digest string) crawlerRegistryStatusReport {
	return crawlerRegistryStatusReport{
		SchemaVersion: crawlerRegistryStatusSchemaVersion, SourceID: sourceID, Sequence: 1, ReportedAt: now, ValidUntil: now.Add(5 * time.Minute),
		Status: crawlerRegistryStatus{
			State: "current", Revision: revision, IssuedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour),
			DigestSHA256: digest, IdentityCount: 2, PrefixCount: 4,
		},
	}
}
