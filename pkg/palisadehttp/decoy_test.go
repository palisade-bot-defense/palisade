package palisadehttp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestReferenceAdapterDecoyLifecycleForwardsOnlyClosedContract(t *testing.T) {
	now := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	capability := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	requests := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Header.Get("Authorization") != "Bearer adapter-key" {
			t.Fatalf("missing backend authorization")
		}
		switch r.URL.Path {
		case "/v1/decoy/issue":
			if cookie, err := r.Cookie(SessionCookieName); err != nil || cookie.Value != "signed-session-cookie" {
				t.Fatalf("session cookie = %+v, err=%v", cookie, err)
			}
			var payload map[string]any
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatal(err)
			}
			if len(payload) != 3 || payload["endpoint_class"] != "login" || payload["surface"] != "form" || payload["ttl_seconds"] != float64(60) {
				t.Fatalf("issue payload = %#v", payload)
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(DecoyCapability{Capability: capability, ExpiresAt: now.Add(time.Minute)})
		case "/v1/decoy/hit":
			var payload map[string]any
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatal(err)
			}
			if len(payload) != 2 || payload["capability"] != capability || payload["interaction"] != "submitted" {
				t.Fatalf("hit payload = %#v", payload)
			}
			w.WriteHeader(http.StatusAccepted)
		default:
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
	}))
	defer upstream.Close()
	middleware, err := New(Config{
		BaseURL: upstream.URL, APIKey: "adapter-key", Classifier: StaticClassification("read", "public_content"), FailureMode: FailOpen,
	})
	if err != nil {
		t.Fatal(err)
	}
	middleware.now = func() time.Time { return now }
	cookie := http.Cookie{Name: SessionCookieName, Value: "signed-session-cookie"}
	issued, err := middleware.IssueDecoy(context.Background(), cookie, "login", DecoySurfaceForm, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if issued.Capability != capability {
		t.Fatalf("capability = %q", issued.Capability)
	}
	if err := middleware.RecordDecoyHit(context.Background(), issued.Capability, DecoySubmitted); err != nil {
		t.Fatal(err)
	}
	if requests != 2 {
		t.Fatalf("requests = %d", requests)
	}
}

func TestReferenceAdapterRejectsRawOrMalformedDecoyValuesLocally(t *testing.T) {
	middleware, err := New(Config{
		BaseURL: "http://127.0.0.1:1", APIKey: "adapter-key", Classifier: StaticClassification("read", "public_content"), FailureMode: FailOpen,
	})
	if err != nil {
		t.Fatal(err)
	}
	cookie := http.Cookie{Name: SessionCookieName, Value: "signed-session-cookie"}
	if _, err := middleware.IssueDecoy(context.Background(), cookie, "/raw/path", DecoySurfaceForm, time.Minute); err != ErrInvalidDecoy {
		t.Fatalf("raw endpoint error = %v", err)
	}
	if _, err := middleware.IssueDecoy(context.Background(), cookie, "login", "raw-html", time.Minute); err != ErrInvalidDecoy {
		t.Fatalf("raw surface error = %v", err)
	}
	if err := middleware.RecordDecoyHit(context.Background(), "https://trap.invalid/raw", DecoyTouched); err != ErrInvalidDecoy {
		t.Fatalf("raw capability error = %v", err)
	}
}
