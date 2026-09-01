package httpapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/palisade-human-trust/palisade/internal/token"
)

func TestOriginCoverageStoreAcceptsIdempotentMonotonicClosedReports(t *testing.T) {
	now := time.Date(2026, time.August, 28, 12, 0, 0, 0, time.UTC)
	store := newOriginCoverageStore(now.Add(-time.Minute))
	report := testOriginCoverageReport(now, "0123456789abcdef0123456789abcdef")
	report.Endpoints[0].Protected = 10
	report.Endpoints[0].Evaluated = 8
	report.Endpoints[0].Bypassed = 1
	report.Endpoints[0].Rejected = 1
	if err := store.observe(report, now); err != nil {
		t.Fatal(err)
	}
	if err := store.observe(report, now); err != nil {
		t.Fatalf("idempotent report rejected: %v", err)
	}
	snapshot := store.snapshot()
	if snapshot.Sources != 1 || snapshot.Endpoints[0].Protected != 10 || snapshot.Endpoints[0].Evaluated != 8 || snapshot.Endpoints[0].Bypassed != 1 || snapshot.Endpoints[0].Rejected != 1 {
		t.Fatalf("snapshot = %+v", snapshot)
	}

	conflict := report
	conflict.Endpoints = cloneOriginCoverageCounters(report.Endpoints)
	conflict.Endpoints[0].Evaluated = 9
	conflict.Endpoints[0].Rejected = 0
	if err := store.observe(conflict, now); !errors.Is(err, errOriginCoverageConflict) {
		t.Fatalf("same-sequence mutation error = %v", err)
	}

	decreasing := report
	decreasing.Sequence = 2
	decreasing.CompletedAt = now.Add(time.Second)
	decreasing.Endpoints = cloneOriginCoverageCounters(report.Endpoints)
	decreasing.Endpoints[0].Protected = 9
	decreasing.Endpoints[0].Evaluated = 7
	if err := store.observe(decreasing, now.Add(time.Second)); !errors.Is(err, errOriginCoverageConflict) {
		t.Fatalf("decreasing report error = %v", err)
	}
}

func TestOriginCoverageStoreBaselinesSourceThatPredatesServer(t *testing.T) {
	now := time.Date(2026, time.August, 28, 12, 0, 0, 0, time.UTC)
	store := newOriginCoverageStore(now)
	report := testOriginCoverageReport(now.Add(-time.Hour), "abcdef0123456789abcdef0123456789")
	report.CompletedAt = now
	report.Endpoints[2].Protected = 100
	report.Endpoints[2].Evaluated = 100
	if err := store.observe(report, now); err != nil {
		t.Fatal(err)
	}
	if snapshot := store.snapshot(); snapshot.Endpoints[2].Protected != 0 {
		t.Fatalf("pre-server history was counted: %+v", snapshot.Endpoints[2])
	}
	report.Sequence = 2
	report.CompletedAt = now.Add(time.Second)
	report.Endpoints[2].Protected = 103
	report.Endpoints[2].Evaluated = 102
	report.Endpoints[2].Bypassed = 1
	if err := store.observe(report, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if snapshot := store.snapshot(); snapshot.Endpoints[2].Protected != 3 || snapshot.Endpoints[2].Evaluated != 2 || snapshot.Endpoints[2].Bypassed != 1 {
		t.Fatalf("post-restart delta = %+v", snapshot.Endpoints[2])
	}
}

func TestOriginCoverageStoreConservativelyBaselinesAmbiguousStartSecond(t *testing.T) {
	serverStart := time.Date(2026, time.August, 28, 12, 0, 0, 500_000_000, time.UTC)
	store := newOriginCoverageStore(serverStart)
	report := testOriginCoverageReport(serverStart.Truncate(time.Second), "fedcba9876543210fedcba9876543210")
	report.CompletedAt = serverStart.Add(500 * time.Millisecond).Truncate(time.Second)
	report.Endpoints[0].Protected = 7
	report.Endpoints[0].Evaluated = 7
	if err := store.observe(report, serverStart.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if snapshot := store.snapshot(); snapshot.Endpoints[0].Protected != 0 {
		t.Fatalf("same-second pre-restart history was counted: %+v", snapshot.Endpoints[0])
	}
}

func TestOriginCoverageReportRejectsPoisoningAndFreeEndpointData(t *testing.T) {
	now := time.Date(2026, time.August, 28, 12, 0, 0, 0, time.UTC)
	store := newOriginCoverageStore(now.Add(-time.Minute))
	for name, mutate := range map[string]func(*originCoverageReport){
		"free endpoint":  func(report *originCoverageReport) { report.Endpoints[0].EndpointClass = "/private?token=raw" },
		"invalid source": func(report *originCoverageReport) { report.SourceID = "deployment-customer-name" },
		"unbalanced": func(report *originCoverageReport) {
			report.Endpoints[0].Protected = 2
			report.Endpoints[0].Evaluated = 1
		},
		"future": func(report *originCoverageReport) { report.CompletedAt = now.Add(2 * time.Minute) },
	} {
		t.Run(name, func(t *testing.T) {
			report := testOriginCoverageReport(now, "0123456789abcdef0123456789abcdef")
			mutate(&report)
			if err := store.observe(report, now); !errors.Is(err, errInvalidOriginCoverage) {
				t.Fatalf("poisoned report error = %v", err)
			}
		})
	}
}

func TestOriginCoverageHTTPContractIsAuthenticatedAndConflictSafe(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	tokens, _ := token.NewService([]byte("0123456789abcdef0123456789abcdef"), token.NewMemoryNonceStore())
	server := New(fakeEngine{}, tokens, "api-key", slog.Default())
	server.originCoverage = newOriginCoverageStore(now.Add(-time.Minute))
	report := testOriginCoverageReport(now, "0123456789abcdef0123456789abcdef")
	report.Endpoints[6].Protected = 4
	report.Endpoints[6].Evaluated = 3
	report.Endpoints[6].GrantedRetries = 1
	body, _ := json.Marshal(report)

	unauthorized := httptest.NewRecorder()
	server.Handler().ServeHTTP(unauthorized, httptest.NewRequest(http.MethodPost, "/v1/origin-coverage", bytes.NewReader(body)))
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized status = %d", unauthorized.Code)
	}

	request := httptest.NewRequest(http.MethodPost, "/v1/origin-coverage", bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer api-key")
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusAccepted {
		t.Fatalf("coverage status = %d body=%s", response.Code, response.Body.String())
	}

	idempotent := httptest.NewRequest(http.MethodPost, "/v1/origin-coverage", bytes.NewReader(body))
	idempotent.Header.Set("Authorization", "Bearer api-key")
	idempotentResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(idempotentResponse, idempotent)
	if idempotentResponse.Code != http.StatusAccepted {
		t.Fatalf("idempotent status = %d", idempotentResponse.Code)
	}

	report.Endpoints[6].Evaluated = 4
	report.Endpoints[6].GrantedRetries = 0
	conflictingBody, _ := json.Marshal(report)
	conflicting := httptest.NewRequest(http.MethodPost, "/v1/origin-coverage", bytes.NewReader(conflictingBody))
	conflicting.Header.Set("Authorization", "Bearer api-key")
	conflictingResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(conflictingResponse, conflicting)
	if conflictingResponse.Code != http.StatusConflict {
		t.Fatalf("conflicting status = %d body=%s", conflictingResponse.Code, conflictingResponse.Body.String())
	}

	summary := server.originCoverageSummary()
	if summary.State != "collecting" || summary.Scope != "protected_handler_requests" || summary.TrafficDenominator != "authenticated_origin_reports" ||
		summary.ProtectedRequests != 4 || summary.EvaluatedRequests != 3 || summary.GrantedRetries != 1 || summary.DecisionCoverage != 1 || len(summary.Endpoints) != 1 || summary.Endpoints[0].EndpointClass != "login" {
		t.Fatalf("origin coverage summary = %+v", summary)
	}
}

func TestOriginCoverageStoreFailsClosedAtSourceCapacity(t *testing.T) {
	now := time.Date(2026, time.August, 28, 12, 0, 0, 0, time.UTC)
	store := newOriginCoverageStore(now.Add(-time.Minute))
	for index := 0; index < maxOriginCoverageSources; index++ {
		report := testOriginCoverageReport(now, fmt.Sprintf("%032x", index))
		if err := store.observe(report, now); err != nil {
			t.Fatalf("source %d: %v", index, err)
		}
	}
	overflow := testOriginCoverageReport(now, fmt.Sprintf("%032x", maxOriginCoverageSources))
	if err := store.observe(overflow, now); !errors.Is(err, errOriginCoverageCapacity) {
		t.Fatalf("capacity error = %v", err)
	}
}

func testOriginCoverageReport(started time.Time, sourceID string) originCoverageReport {
	return originCoverageReport{
		SchemaVersion: originCoverageSchemaVersion, SourceID: sourceID, SourceStarted: started,
		Sequence: 1, CompletedAt: started, Endpoints: zeroOriginCoverageCounters(),
	}
}
