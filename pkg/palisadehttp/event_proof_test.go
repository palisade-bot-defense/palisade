package palisadehttp

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync/atomic"
	"testing"
	"time"
)

func TestIssueEventProofSendsOnlyClosedServerClassification(t *testing.T) {
	var calls atomic.Int32
	service := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != http.MethodPost || r.URL.Path != "/v1/token" || r.Header.Get("Authorization") != "Bearer adapter-key" || cookieValue(r, SessionCookieName) != testSessionValue {
			t.Fatalf("unsafe event proof request: %s %s auth=%q cookie=%q", r.Method, r.URL.Path, r.Header.Get("Authorization"), cookieValue(r, SessionCookieName))
		}
		var payload map[string]any
		decodeFakeJSON(t, r, &payload)
		want := map[string]any{"action": "events", "request_action": "compare", "endpoint_class": "compare_noindex", "ttl_seconds": float64(60)}
		if !reflect.DeepEqual(payload, want) {
			t.Fatalf("event proof payload = %#v", payload)
		}
		writeFakeJSON(w, http.StatusCreated, map[string]any{"proof_token": "signed-event-proof", "expires_in": 60})
	}))
	defer service.Close()
	middleware := newTestMiddleware(t, service.URL, testNow(), FailClosed)
	request := httptest.NewRequest(http.MethodPost, "https://origin.example/private?secret=must-not-leave", nil)
	request.Header.Set("Referer", "https://origin.example/raw/private")
	request.Header.Set("User-Agent", "raw-user-agent")
	request.AddCookie(&http.Cookie{Name: SessionCookieName, Value: testSessionValue})
	proof, err := middleware.IssueEventProof(request, Classification{Action: "compare", EndpointClass: "compare_noindex"})
	if err != nil || proof.ProofToken != "signed-event-proof" || proof.ExpiresIn != 60 || calls.Load() != 1 {
		t.Fatalf("event proof = %+v err=%v calls=%d", proof, err, calls.Load())
	}
}

func TestIssueEventProofRejectsUntrustedOrIncompleteInputLocally(t *testing.T) {
	var calls atomic.Int32
	service := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	defer service.Close()
	middleware := newTestMiddleware(t, service.URL, testNow(), FailClosed)
	request := httptest.NewRequest(http.MethodPost, "https://origin.example/proof", nil)
	request.AddCookie(&http.Cookie{Name: SessionCookieName, Value: testSessionValue})
	for _, classification := range []Classification{
		{Action: "/raw/path", EndpointClass: "public_content"},
		{Action: "read", EndpointClass: "/raw/path"},
		{Action: "events", EndpointClass: "public_content"},
		{Action: "read", EndpointClass: "public_content", EvaluationCohort: "standard"},
	} {
		if _, err := middleware.IssueEventProof(request, classification); err != ErrInvalidClassification {
			t.Fatalf("classification %+v error = %v", classification, err)
		}
	}
	missingCookie := httptest.NewRequest(http.MethodPost, "https://origin.example/proof", nil)
	if _, err := middleware.IssueEventProof(missingCookie, Classification{Action: "read", EndpointClass: "public_content"}); err != ErrSessionRequired {
		t.Fatalf("missing session error = %v", err)
	}
	if calls.Load() != 0 {
		t.Fatalf("invalid input made %d backend requests", calls.Load())
	}
}

func testNow() time.Time {
	return time.Unix(1_800_000_000, 0).UTC()
}
