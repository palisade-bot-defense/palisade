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
	if summary.SchemaVersion != "palisade.admin-summary.v5" || summary.Traffic.Decisions != 1 || summary.Traffic.Enforced.Observe != 1 || summary.Traffic.Computed.Delay != 1 || summary.Analysis != nil || summary.AnalysisStatus.State != "not_configured" ||
		len(summary.Traffic.Reasons) != 2 || summary.Traffic.Reasons[0].Code != "HONEYPOT_INTERACTION" || summary.Traffic.Reasons[0].Count != 1 || summary.Traffic.Reasons[1].Code != "STEP_UP_REQUIRED" || summary.Traffic.Reasons[1].Count != 1 {
		t.Fatalf("unexpected aggregate summary: %+v", summary)
	}
	for _, forbidden := range []string{"session-12345678", "api-key", "admin-key", "proof_token", "decision_id"} {
		if bytes.Contains(response.Body.Bytes(), []byte(forbidden)) {
			t.Fatalf("admin response exposed %q: %s", forbidden, response.Body.String())
		}
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
