// Command browser-e2e-fixture serves a synthetic loopback-only origin for the
// real-browser adapter exercise. It is test support, not a deployment binary.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/palisade-human-trust/palisade/pkg/palisadehttp"
)

const (
	adapterKey        = "synthetic-browser-adapter-key"
	sessionID         = "0123456789abcdef0123456789abcdef"
	sessionValue      = "synthetic-browser-session-value"
	challengeID       = "ABCDEFGHIJKLMNOPQRSTUVWX12345678"
	verificationToken = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	redemptionToken   = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
)

type counters struct {
	SessionIssues int `json:"session_issues"`
	TokenIssues   int `json:"token_issues"`
	OriginChecks  int `json:"origin_checks"`
	MetadataGets  int `json:"metadata_gets"`
	Verifications int `json:"verifications"`
	Redemptions   int `json:"redemptions"`
	Fallbacks     int `json:"fallbacks"`
	ProtectedHits int `json:"protected_hits"`
}

type fixture struct {
	mu                   sync.Mutex
	counts               counters
	lastChallengeBinding string
	guarded              http.Handler
}

func main() {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	serviceURL := fmt.Sprintf("http://127.0.0.1:%d", port)
	originURL := fmt.Sprintf("http://localhost:%d", port)

	app := &fixture{}
	guard, err := palisadehttp.New(palisadehttp.Config{
		BaseURL: serviceURL, APIKey: adapterKey, FailureMode: palisadehttp.FailClosed,
		Classifier:   palisadehttp.StaticClassification("read", "public_content"),
		FallbackPath: "/fallback",
	})
	if err != nil {
		log.Fatal(err)
	}
	app.guarded = guard.Handler(http.HandlerFunc(app.protected))

	server := &http.Server{
		Handler:           app,
		ReadHeaderTimeout: 2 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      5 * time.Second,
		IdleTimeout:       10 * time.Second,
	}
	encoded, _ := json.Marshal(map[string]string{"origin": originURL})
	fmt.Println(string(encoded))

	stopped := make(chan os.Signal, 1)
	signal.Notify(stopped, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-stopped
		_ = server.Close()
	}()
	if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

func (f *fixture) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/__fixture/state":
		f.writeState(w)
	case r.URL.Path == "/favicon.ico":
		w.Header().Set("Cache-Control", "public, max-age=3600")
		w.WriteHeader(http.StatusNoContent)
	case r.URL.Path == "/fallback":
		writeHTML(w, http.StatusOK, "Alternative method", `<main><h1>Alternative method available</h1><p>The synthetic fallback path was reached.</p></main>`)
	case strings.HasPrefix(r.URL.Path, "/v1/"):
		f.service(w, r)
	default:
		f.guarded.ServeHTTP(w, r)
	}
}

func (f *fixture) protected(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/protected" {
		http.NotFound(w, r)
		return
	}
	f.mu.Lock()
	f.counts.ProtectedHits++
	f.mu.Unlock()
	writeHTML(w, http.StatusOK, "Protected route", `<main><h1>Protected content reached</h1><p>The one-time browser retry was accepted.</p></main>`)
}

func (f *fixture) service(w http.ResponseWriter, r *http.Request) {
	now := time.Now().UTC()
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/v1/session":
		if r.Header.Get("Authorization") != "Bearer "+adapterKey {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		f.increment(func(value *counters) { value.SessionIssues++ })
		http.SetCookie(w, &http.Cookie{
			Name: palisadehttp.SessionCookieName, Value: sessionValue, Path: "/", Expires: now.Add(time.Hour), MaxAge: 3600,
			Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
		})
		writeJSON(w, http.StatusCreated, map[string]any{"session_id": sessionID, "expires_at": now.Add(time.Hour)})
	case r.Method == http.MethodPost && r.URL.Path == "/v1/token":
		if r.Header.Get("Authorization") != "Bearer "+adapterKey || cookieValue(r, palisadehttp.SessionCookieName) != sessionValue {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		f.increment(func(value *counters) { value.TokenIssues++ })
		writeJSON(w, http.StatusCreated, map[string]any{"proof_token": "synthetic-browser-proof", "expires_in": 60})
	case r.Method == http.MethodPost && r.URL.Path == "/v1/origin-check":
		binding := r.Header.Get("X-Palisade-Challenge-Binding")
		if cookieValue(r, palisadehttp.SessionCookieName) != sessionValue || !stableCapability(binding) {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		f.counts.OriginChecks++
		decision := f.counts.OriginChecks
		f.lastChallengeBinding = binding
		f.mu.Unlock()
		w.Header().Set("X-Palisade-Decision-ID", fmt.Sprintf("browser-decision-%d", decision))
		w.Header().Set("X-Palisade-Mode", "canary")
		w.Header().Set("X-Palisade-Rollout-ID", "browser-rollout")
		w.Header().Set("X-Palisade-Action", "challenge")
		w.Header().Set("X-Palisade-Handling", "challenge")
		w.Header().Set("X-Palisade-Challenge-ID", challengeID)
		w.Header().Set("Location", "/v1/challenge/"+challengeID)
		w.WriteHeader(http.StatusForbidden)
	case r.Method == http.MethodGet && r.URL.Path == "/v1/challenge/"+challengeID:
		if cookieValue(r, palisadehttp.SessionCookieName) != sessionValue {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		f.increment(func(value *counters) { value.MetadataGets++ })
		writeJSON(w, http.StatusOK, map[string]any{
			"challenge_id": challengeID, "family": "timed_confirmation_v2", "ready_at": now.Add(-time.Second),
			"expires_at": now.Add(5 * time.Minute), "attempts_remaining": 5, "verification_token": verificationToken,
			"accessibility": map[string]bool{"non_visual": true, "keyboard_only": true, "fallback_offered": true},
		})
	case r.Method == http.MethodPost && r.URL.Path == "/v1/challenge/verify":
		var payload struct {
			ChallengeID       string `json:"challenge_id"`
			VerificationToken string `json:"verification_token"`
		}
		if cookieValue(r, palisadehttp.SessionCookieName) != sessionValue || !decodeJSON(r, &payload) ||
			payload.ChallengeID != challengeID || payload.VerificationToken != verificationToken {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		f.increment(func(value *counters) { value.Verifications++ })
		writeJSON(w, http.StatusOK, map[string]any{"challenge_id": challengeID, "redemption_token": redemptionToken, "expires_at": now.Add(time.Minute)})
	case r.Method == http.MethodPost && r.URL.Path == "/v1/challenge/redeem":
		var payload struct {
			ChallengeID       string `json:"challenge_id"`
			RedemptionToken   string `json:"redemption_token"`
			RedemptionBinding string `json:"redemption_binding"`
			Action            string `json:"action"`
			EndpointClass     string `json:"endpoint_class"`
		}
		if cookieValue(r, palisadehttp.SessionCookieName) != sessionValue || !decodeJSON(r, &payload) {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		valid := payload.ChallengeID == challengeID && payload.RedemptionToken == redemptionToken &&
			payload.RedemptionBinding == f.lastChallengeBinding && payload.Action == "read" && payload.EndpointClass == "public_content"
		if valid {
			f.counts.Redemptions++
		}
		f.mu.Unlock()
		if !valid {
			w.WriteHeader(http.StatusConflict)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	case r.Method == http.MethodPost && r.URL.Path == "/v1/challenge/fallback":
		var payload struct {
			ChallengeID string `json:"challenge_id"`
		}
		if cookieValue(r, palisadehttp.SessionCookieName) != sessionValue || !decodeJSON(r, &payload) || payload.ChallengeID != challengeID {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		f.increment(func(value *counters) { value.Fallbacks++ })
		w.WriteHeader(http.StatusNoContent)
	default:
		http.NotFound(w, r)
	}
}

func (f *fixture) writeState(w http.ResponseWriter) {
	f.mu.Lock()
	copy := f.counts
	f.mu.Unlock()
	writeJSON(w, http.StatusOK, copy)
}

func (f *fixture) increment(update func(*counters)) {
	f.mu.Lock()
	update(&f.counts)
	f.mu.Unlock()
}

func cookieValue(r *http.Request, name string) string {
	cookie, err := r.Cookie(name)
	if err != nil {
		return ""
	}
	return cookie.Value
}

func stableCapability(value string) bool {
	if len(value) != 43 {
		return false
	}
	for _, character := range value {
		if !((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '_' || character == '-') {
			return false
		}
	}
	return true
}

func decodeJSON(r *http.Request, target any) bool {
	contents, err := io.ReadAll(io.LimitReader(r.Body, (16<<10)+1))
	if err != nil || len(contents) > 16<<10 {
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return false
	}
	return errors.Is(decoder.Decode(&struct{}{}), io.EOF)
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeHTML(w http.ResponseWriter, status int, title, body string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>%s</title></head><body>%s</body></html>", title, body)
}
