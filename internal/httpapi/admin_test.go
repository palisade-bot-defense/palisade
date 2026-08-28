package httpapi

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/palisade-bot-defense/palisade/internal/core"
	"github.com/palisade-bot-defense/palisade/internal/token"
)

func TestAdminSurfaceIsSeparateAuthenticatedAndAggregateOnly(t *testing.T) {
	tokens, err := token.NewService([]byte("0123456789abcdef0123456789abcdef"), token.NewMemoryNonceStore())
	if err != nil {
		t.Fatal(err)
	}
	decision := core.Decision{
		DecisionID: "admin-counter-test", Action: core.ActionObserve, ComputedAction: core.ActionDelay,
		Mode: core.RuntimeModeShadow, ExpiresAt: time.Now().UTC().Add(time.Minute),
		ReasonCodes: []string{"STEP_UP_REQUIRED", "HONEYPOT_INTERACTION", "STEP_UP_REQUIRED", "raw invalid"},
	}
	server := New(fixedEngine{decision: decision}, tokens, "api-key", slog.Default()).WithAdmin(AdminConfig{
		Key: "admin-key", StartedAt: time.Now().UTC().Add(-time.Minute), Mode: core.RuntimeModeShadow,
		PolicyVersion: "default-v3", ModelVersion: "transparent-baseline-v6",
	})

	publicRoot := httptest.NewRecorder()
	server.Handler().ServeHTTP(publicRoot, httptest.NewRequest(http.MethodGet, "/", nil))
	if publicRoot.Code != http.StatusNotFound {
		t.Fatalf("public API served admin UI: %d", publicRoot.Code)
	}
	publicSummary := httptest.NewRecorder()
	server.Handler().ServeHTTP(publicSummary, httptest.NewRequest(http.MethodGet, "/v1/admin/summary", nil))
	if publicSummary.Code != http.StatusNotFound {
		t.Fatalf("public API served admin summary: %d", publicSummary.Code)
	}

	unauthorized := httptest.NewRecorder()
	server.AdminHandler().ServeHTTP(unauthorized, httptest.NewRequest(http.MethodGet, "/v1/admin/summary", nil))
	if unauthorized.Code != http.StatusUnauthorized || unauthorized.Header().Get("WWW-Authenticate") == "" {
		t.Fatalf("unauthorized admin response = %d headers=%v", unauthorized.Code, unauthorized.Header())
	}

	requestBody := `{"session_id":"session-12345678","action":"read","endpoint_class":"public_content","sequence":1,"observations":{}}`
	decisionResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(decisionResponse, httptest.NewRequest(http.MethodPost, "/v1/decision", bytes.NewBufferString(requestBody)))
	if decisionResponse.Code != http.StatusOK {
		t.Fatalf("decision response = %d %s", decisionResponse.Code, decisionResponse.Body.String())
	}

	request := httptest.NewRequest(http.MethodGet, "/v1/admin/summary", nil)
	request.Header.Set("Authorization", "Bearer admin-key")
	response := httptest.NewRecorder()
	server.AdminHandler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("admin summary = %d %s", response.Code, response.Body.String())
	}
	var summary AdminSummary
	if err := json.Unmarshal(response.Body.Bytes(), &summary); err != nil {
		t.Fatal(err)
	}
	if summary.SchemaVersion != "palisade.admin-summary.v10" || summary.Traffic.Decisions != 1 || summary.Traffic.Enforced.Observe != 1 || summary.Traffic.Computed.Delay != 1 || summary.Analysis != nil || summary.AnalysisStatus.State != "not_configured" ||
		summary.Collection.State != "disabled" || summary.Collection.TrafficDenominator != "external_total_unavailable" ||
		summary.OriginCoverage.State != "unavailable" || summary.OutcomeFlow.State != "disabled" ||
		summary.Transport.State != "attention" || summary.Transport.Scope != "evaluated_decisions" || summary.Transport.Samples != 1 ||
		summary.Transport.Protocol.Unknown != 1 || summary.Transport.Security.Unknown != 1 || summary.Transport.AddressSource.Unknown != 1 ||
		summary.CrawlerIdentity.State != "no_samples" || summary.CrawlerIdentity.Observations != 0 ||
		summary.CrawlerRegistry.State != "unavailable" || summary.CrawlerRegistry.Sources != 0 ||
		len(summary.Traffic.Reasons) != 2 || summary.Traffic.Reasons[0].Code != "HONEYPOT_INTERACTION" || summary.Traffic.Reasons[0].Count != 1 || summary.Traffic.Reasons[1].Code != "STEP_UP_REQUIRED" || summary.Traffic.Reasons[1].Count != 1 {
		t.Fatalf("unexpected aggregate summary: %+v", summary)
	}
	for _, forbidden := range []string{"session-12345678", "api-key", "admin-key", "proof_token", "decision_id"} {
		if bytes.Contains(response.Body.Bytes(), []byte(forbidden)) {
			t.Fatalf("admin response exposed %q: %s", forbidden, response.Body.String())
		}
	}
}

func TestAdminCrawlerIdentitySeparatesQualifiedAndUnqualifiedWithoutRawIdentity(t *testing.T) {
	var counters crawlerCounters
	counters.increment(core.Observations{
		VerifiedBot: true, CrawlerClass: core.CrawlerClassSearchIndexer,
		CrawlerVerification: core.CrawlerVerificationIPUARegistry,
	}, "public_content")
	counters.increment(core.Observations{
		VerifiedBot: true, CrawlerClass: core.CrawlerClassSearchIndexer,
		CrawlerVerification: core.CrawlerVerificationIPUARegistry,
	}, "login")
	counters.increment(core.Observations{
		VerifiedBot: true, CrawlerClass: core.CrawlerClassTrainingCrawler,
		CrawlerVerification: core.CrawlerVerificationFCrDNSUA,
	}, "public_content")
	counters.increment(core.Observations{VerifiedBot: true}, "public_content")
	counters.increment(core.Observations{}, "public_content")

	summary := counters.snapshot()
	if summary.State != "attention" || summary.Scope != "evaluated_identity_observations" || summary.Observations != 4 ||
		summary.Qualified != 1 || summary.Unqualified != 3 || summary.Classes.SearchIndexer != 2 ||
		summary.Classes.TrainingCrawler != 1 || summary.Classes.Unknown != 1 ||
		summary.Verification.IPUARegistry != 2 || summary.Verification.FCrDNSUA != 1 || summary.Verification.Unknown != 1 {
		t.Fatalf("crawler identity summary = %+v", summary)
	}
	encoded, _ := json.Marshal(summary)
	for _, forbidden := range []string{"Googlebot", "192.0.2.10", "CF-Connecting-IP", "user-agent", "vendor-search"} {
		if bytes.Contains(encoded, []byte(forbidden)) {
			t.Fatalf("crawler summary exposed %q: %s", forbidden, encoded)
		}
	}
}

func TestAdminTransportPostureUsesOnlyClosedAggregateClasses(t *testing.T) {
	tokens, _ := token.NewService([]byte("0123456789abcdef0123456789abcdef"), token.NewMemoryNonceStore())
	server := New(fakeEngine{}, tokens, "api-key", slog.Default())
	server.counters.transport.increment(core.Observations{
		TransportProtocol: "http2", TransportSecurity: "trusted_proxy_tls", ClientAddressSource: "trusted_proxy",
	})
	server.counters.transport.increment(core.Observations{
		TransportProtocol: "http1", TransportSecurity: "plaintext", ClientAddressSource: "invalid_trusted_proxy",
	})
	server.counters.transport.increment(core.Observations{})

	posture := server.transportPostureSummary()
	if posture.State != "attention" || posture.Scope != "evaluated_decisions" || posture.Samples != 3 ||
		posture.Protocol.HTTP1 != 1 || posture.Protocol.HTTP2 != 1 || posture.Protocol.Unknown != 1 ||
		posture.Security.TrustedProxyTLS != 1 || posture.Security.Plaintext != 1 || posture.Security.Unknown != 1 ||
		posture.AddressSource.TrustedProxy != 1 || posture.AddressSource.InvalidTrustedProxy != 1 || posture.AddressSource.Unknown != 1 {
		t.Fatalf("transport posture = %+v", posture)
	}
	encoded, _ := json.Marshal(posture)
	for _, forbidden := range []string{"198.51.100.7", "CF-Connecting-IP", "X-Real-IP", "RemoteAddr", "header_value"} {
		if bytes.Contains(encoded, []byte(forbidden)) {
			t.Fatalf("transport posture exposed %q: %s", forbidden, encoded)
		}
	}
}

func TestAdminOutcomeFlowExposesRejectionsAndDropsWithoutInventingLabels(t *testing.T) {
	tokens, _ := token.NewService([]byte("0123456789abcdef0123456789abcdef"), token.NewMemoryNonceStore())
	server := New(fakeEngine{}, tokens, "api-key", slog.Default()).WithAdmin(AdminConfig{ShadowLogEnabled: true})
	server.counters.recordedOutcomes.Add(3)
	server.counters.outcomeRejected.Add(2)
	server.counters.outcomeDropped.Add(1)

	flow := server.outcomeFlowSummary()
	if flow.State != "degraded" || flow.Accepted != 3 || flow.Rejected != 2 || flow.Dropped != 1 {
		t.Fatalf("outcome flow = %+v", flow)
	}
	encoded, _ := json.Marshal(flow)
	for _, forbidden := range []string{"human", "abuse", "healthy", "decision_id", "session_id"} {
		if bytes.Contains(encoded, []byte(forbidden)) {
			t.Fatalf("outcome flow invented or exposed %q: %s", forbidden, encoded)
		}
	}
}

func TestAdminCollectionFunnelIsBoundedAndDoesNotInventTrafficCoverage(t *testing.T) {
	tokens, _ := token.NewService([]byte("0123456789abcdef0123456789abcdef"), token.NewMemoryNonceStore())
	server := New(fakeEngine{}, tokens, "api-key", slog.Default()).WithAdmin(AdminConfig{
		Key: "admin-key", EventShadowEnabled: true, EventShadowFromProof: true,
	})
	server.counters.contextProofs.Add(3)
	server.counters.endpointContexts.increment("compare_noindex")
	server.counters.endpointContexts.increment("compare_noindex")
	server.counters.endpointContexts.increment("public_content")
	server.counters.endpointContexts.increment("/raw/path")
	server.counters.eventBatches.Add(2)
	server.counters.eventShadowRecorded.Add(1)
	server.counters.eventShadowRejected.Add(1)
	server.eventShadowDrops.Add(1)

	summary := server.adminSummary(time.Now().UTC())
	collection := summary.Collection
	if collection.State != "degraded" || collection.TrafficDenominator != "external_total_unavailable" ||
		collection.ContextProofsIssued != 3 || collection.AcceptedEventBatches != 2 || collection.RecordedShadowDecisions != 1 ||
		collection.RejectedBeforeIngest != 1 || collection.DroppedAfterIngest != 1 || collection.BatchRecordingRate != 0.5 ||
		len(collection.EndpointContextProofs) != 2 || collection.EndpointContextProofs[0].EndpointClass != "public_content" || collection.EndpointContextProofs[0].Count != 1 ||
		collection.EndpointContextProofs[1].EndpointClass != "compare_noindex" || collection.EndpointContextProofs[1].Count != 2 {
		t.Fatalf("collection summary = %+v", collection)
	}
	encoded, err := json.Marshal(summary)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte("/raw/path")) || bytes.Contains(encoded, []byte("healthy")) {
		t.Fatalf("collection summary exposed raw or invented health: %s", encoded)
	}
}

func TestAdminCollectionProofWithoutAcceptedBatchIsNotCollecting(t *testing.T) {
	tokens, _ := token.NewService([]byte("0123456789abcdef0123456789abcdef"), token.NewMemoryNonceStore())
	server := New(fakeEngine{}, tokens, "api-key", slog.Default()).WithAdmin(AdminConfig{
		EventShadowEnabled: true, EventShadowFromProof: true,
	})
	server.counters.contextProofs.Add(1)
	server.counters.endpointContexts.increment("public_content")

	collection := server.collectionSummary()
	if collection.State != "no_samples" || collection.ContextProofsIssued != 1 || collection.AcceptedEventBatches != 0 {
		t.Fatalf("proof-only collection must remain no_samples: %+v", collection)
	}
}

func TestAdminUIIsAvailableOnlyFromAdminHandler(t *testing.T) {
	tokens, _ := token.NewService([]byte("0123456789abcdef0123456789abcdef"), token.NewMemoryNonceStore())
	server := New(fakeEngine{}, tokens, "api-key", slog.Default()).WithAdmin(AdminConfig{Key: "admin-key"})
	response := httptest.NewRecorder()
	server.AdminHandler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))
	if response.Code != http.StatusOK || !bytes.Contains(response.Body.Bytes(), []byte("PALISADE")) {
		t.Fatalf("admin UI response = %d %s", response.Code, response.Body.String())
	}
}
