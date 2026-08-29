package palisadehttp

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	testSessionID    = "0123456789abcdef0123456789abcdef"
	testSessionValue = "signed-session-cookie-value"
	testChallengeID  = "ABCDEFGHIJKLMNOPQRSTUVWX12345678"
	testVerifyToken  = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	testRedeemToken  = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
)

type fakePalisade struct {
	t                    *testing.T
	now                  time.Time
	challenge            bool
	handling             string
	originUnavailable    bool
	sessionIssues        atomic.Int32
	tokenIssues          atomic.Int32
	originChecks         atomic.Int32
	metadataGets         atomic.Int32
	verifications        atomic.Int32
	redemptions          atomic.Int32
	fallbacks            atomic.Int32
	outcomes             atomic.Int32
	coverages            atomic.Int32
	mu                   sync.Mutex
	originBodies         [][]byte
	outcomeBodies        [][]byte
	sequences            []uint64
	coverageBodies       [][]byte
	coverageReports      chan coverageReport
	lastChallengeBinding string
}

func (f *fakePalisade) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/v1/session":
		f.sessionIssues.Add(1)
		if r.Header.Get("Authorization") != "Bearer adapter-key" {
			f.t.Errorf("session authorization = %q", r.Header.Get("Authorization"))
		}
		http.SetCookie(w, &http.Cookie{
			Name: SessionCookieName, Value: testSessionValue, Path: "/", Expires: f.now.Add(time.Hour), MaxAge: 3600,
			Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
		})
		writeFakeJSON(w, http.StatusCreated, map[string]any{"session_id": testSessionID, "expires_at": f.now.Add(time.Hour)})
	case r.Method == http.MethodPost && r.URL.Path == "/v1/token":
		f.tokenIssues.Add(1)
		if r.Header.Get("Authorization") != "Bearer adapter-key" || cookieValue(r, SessionCookieName) != testSessionValue {
			f.t.Errorf("unsafe proof request: auth=%q cookie=%q", r.Header.Get("Authorization"), cookieValue(r, SessionCookieName))
		}
		var payload map[string]any
		decodeFakeJSON(f.t, r, &payload)
		if _, exists := payload["session_id"]; exists || payload["action"] != "read" {
			f.t.Errorf("proof payload = %v", payload)
		}
		writeFakeJSON(w, http.StatusCreated, map[string]any{"proof_token": "proof-token", "expires_in": 60})
	case r.Method == http.MethodPost && r.URL.Path == "/v1/origin-check":
		f.originChecks.Add(1)
		body, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.originBodies = append(f.originBodies, append([]byte(nil), body...))
		var payload struct {
			SessionID string `json:"session_id"`
			Sequence  uint64 `json:"sequence"`
		}
		if err := json.Unmarshal(body, &payload); err != nil {
			f.t.Errorf("origin JSON: %v", err)
		}
		f.sequences = append(f.sequences, payload.Sequence)
		f.lastChallengeBinding = r.Header.Get("X-Palisade-Challenge-Binding")
		f.mu.Unlock()
		if payload.SessionID != "" || cookieValue(r, SessionCookieName) != testSessionValue {
			f.t.Errorf("origin session payload/cookie = %q/%q", payload.SessionID, cookieValue(r, SessionCookieName))
		}
		if !stableToken(r.Header.Get("X-Palisade-Challenge-Binding"), 43) {
			f.t.Errorf("origin challenge binding = %q", r.Header.Get("X-Palisade-Challenge-Binding"))
		}
		if f.originUnavailable {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("X-Palisade-Decision-ID", "decision-1")
		if f.challenge {
			w.Header().Set("X-Palisade-Mode", "canary")
			w.Header().Set("X-Palisade-Rollout-ID", "test-canary")
			w.Header().Set("X-Palisade-Action", "challenge")
			w.Header().Set("X-Palisade-Handling", "challenge")
			w.Header().Set("X-Palisade-Challenge-ID", testChallengeID)
			w.Header().Set("Location", "/v1/challenge/"+testChallengeID)
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if f.handling == "delay" {
			w.Header().Set("X-Palisade-Mode", "canary")
			w.Header().Set("X-Palisade-Rollout-ID", "test-canary")
			w.Header().Set("X-Palisade-Action", "delay")
			w.Header().Set("X-Palisade-Handling", "delay")
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		if f.handling == "invalid_delay" {
			w.Header().Set("X-Palisade-Mode", "canary")
			w.Header().Set("X-Palisade-Rollout-ID", "test-canary")
			w.Header().Set("X-Palisade-Action", "delay")
			w.Header().Set("X-Palisade-Handling", "delay")
			w.Header().Set("Retry-After", "2")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		if f.handling == "throttle" {
			w.Header().Set("X-Palisade-Mode", "canary")
			w.Header().Set("X-Palisade-Rollout-ID", "test-canary")
			w.Header().Set("X-Palisade-Action", "throttle")
			w.Header().Set("X-Palisade-Handling", "throttle")
			w.Header().Set("Retry-After", "5")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		if f.handling == "block" {
			w.Header().Set("X-Palisade-Mode", "enforce")
			w.Header().Set("X-Palisade-Rollout-ID", "test-enforcement")
			w.Header().Set("X-Palisade-Action", "block")
			w.Header().Set("X-Palisade-Handling", "block")
			w.Header().Set("Retry-After", "300")
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.Header().Set("X-Palisade-Mode", "shadow")
		w.Header().Set("X-Palisade-Action", "observe")
		w.Header().Set("X-Palisade-Handling", "pass")
		w.WriteHeader(http.StatusNoContent)
	case r.Method == http.MethodPost && r.URL.Path == "/v1/outcome":
		f.outcomes.Add(1)
		if r.Header.Get("Authorization") != "Bearer adapter-key" || cookieValue(r, SessionCookieName) != testSessionValue {
			f.t.Errorf("unsafe outcome request: auth=%q cookie=%q", r.Header.Get("Authorization"), cookieValue(r, SessionCookieName))
		}
		body, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.outcomeBodies = append(f.outcomeBodies, append([]byte(nil), body...))
		f.mu.Unlock()
		w.WriteHeader(http.StatusAccepted)
	case r.Method == http.MethodPost && r.URL.Path == "/v1/origin-coverage":
		f.coverages.Add(1)
		if r.Header.Get("Authorization") != "Bearer adapter-key" {
			f.t.Errorf("coverage authorization = %q", r.Header.Get("Authorization"))
		}
		body, _ := io.ReadAll(r.Body)
		var report coverageReport
		if err := json.Unmarshal(body, &report); err != nil {
			f.t.Errorf("coverage JSON: %v", err)
		}
		f.mu.Lock()
		f.coverageBodies = append(f.coverageBodies, append([]byte(nil), body...))
		f.mu.Unlock()
		if f.coverageReports != nil {
			f.coverageReports <- report
		}
		w.WriteHeader(http.StatusAccepted)
	case r.Method == http.MethodGet && r.URL.Path == "/v1/challenge/"+testChallengeID:
		f.metadataGets.Add(1)
		if cookieValue(r, SessionCookieName) != testSessionValue {
			f.t.Errorf("metadata cookie = %q", cookieValue(r, SessionCookieName))
		}
		writeFakeJSON(w, http.StatusOK, map[string]any{
			"challenge_id": testChallengeID, "family": "timed_confirmation_v2", "ready_at": f.now.Add(-time.Second),
			"expires_at": f.now.Add(5 * time.Minute), "attempts_remaining": 5, "verification_token": testVerifyToken,
			"accessibility": map[string]bool{"non_visual": true, "keyboard_only": true, "fallback_offered": true},
		})
	case r.Method == http.MethodPost && r.URL.Path == "/v1/challenge/verify":
		f.verifications.Add(1)
		var payload challengeVerifyRequest
		decodeFakeJSON(f.t, r, &payload)
		if payload.ChallengeID != testChallengeID || payload.VerificationToken != testVerifyToken {
			f.t.Errorf("verification payload = %+v", payload)
		}
		writeFakeJSON(w, http.StatusOK, map[string]any{
			"challenge_id": testChallengeID, "redemption_token": testRedeemToken, "expires_at": f.now.Add(time.Minute),
		})
	case r.Method == http.MethodPost && r.URL.Path == "/v1/challenge/redeem":
		f.redemptions.Add(1)
		var payload challengeServiceRedeemRequest
		decodeFakeJSON(f.t, r, &payload)
		f.mu.Lock()
		binding := f.lastChallengeBinding
		f.mu.Unlock()
		if payload.ChallengeID != testChallengeID || payload.RedemptionToken != testRedeemToken || payload.RedemptionBinding != binding ||
			!stableToken(payload.RedemptionBinding, 43) || payload.Action != "read" || payload.EndpointClass != "public_content" {
			f.t.Errorf("redemption payload = %+v", payload)
		}
		w.WriteHeader(http.StatusNoContent)
	case r.Method == http.MethodPost && r.URL.Path == "/v1/challenge/fallback":
		f.fallbacks.Add(1)
		w.WriteHeader(http.StatusNoContent)
	default:
		f.t.Errorf("unexpected PALISADE request: %s %s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	}
}

func TestMiddlewareReportsOnlyClosedCompletedRequestCoverage(t *testing.T) {
	now := time.Date(2026, time.August, 28, 12, 0, 0, 0, time.UTC)
	fake := &fakePalisade{t: t, now: now, coverageReports: make(chan coverageReport, 2)}
	service := httptest.NewServer(fake)
	defer service.Close()
	middleware, err := New(Config{
		BaseURL: service.URL, APIKey: "adapter-key", FailureMode: FailClosed,
		Classifier: StaticClassification("read", "public_content"), CoverageReporting: true,
		CoverageReportEvery: 1, CoverageReportInterval: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	middleware.now = func() time.Time { return now }
	handler := middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	request := httptest.NewRequest(http.MethodGet, "https://origin.example/private?secret=must-not-leave", nil)
	request.Header.Set("Referer", "https://origin.example/account/private")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("protected response = %d", response.Code)
	}
	var report coverageReport
	select {
	case report = <-fake.coverageReports:
	case <-time.After(2 * time.Second):
		t.Fatal("coverage report was not delivered")
	}
	if report.SchemaVersion != coverageSchemaVersion || len(report.SourceID) != 32 || report.Sequence != 1 || len(report.Endpoints) != len(coverageEndpointClasses) ||
		report.Endpoints[0].EndpointClass != "public_content" || report.Endpoints[0].Protected != 1 || report.Endpoints[0].Evaluated != 1 {
		t.Fatalf("coverage report = %+v", report)
	}
	fake.mu.Lock()
	encoded := append([]byte(nil), fake.coverageBodies[0]...)
	fake.mu.Unlock()
	for _, forbidden := range []string{"must-not-leave", "/private", "Referer", "origin.example", "GET"} {
		if bytes.Contains(encoded, []byte(forbidden)) {
			t.Fatalf("coverage report exposed %q: %s", forbidden, encoded)
		}
	}
}

func TestMiddlewareFlushCoverageSendsLatestBelowThresholdSnapshot(t *testing.T) {
	now := time.Date(2026, time.August, 28, 12, 0, 0, 0, time.UTC)
	fake := &fakePalisade{t: t, now: now, coverageReports: make(chan coverageReport, 3)}
	service := httptest.NewServer(fake)
	defer service.Close()
	middleware, err := New(Config{
		BaseURL: service.URL, APIKey: "adapter-key", FailureMode: FailClosed,
		Classifier: StaticClassification("read", "public_content"), CoverageReporting: true,
		CoverageReportEvery: 100, CoverageReportInterval: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	middleware.now = func() time.Time { return now }
	handler := middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))

	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "https://origin.example/first", nil))
	var first coverageReport
	select {
	case first = <-fake.coverageReports:
	case <-time.After(2 * time.Second):
		t.Fatal("initial coverage report was not delivered")
	}
	if first.Sequence != 1 || first.Endpoints[0].Protected != 1 {
		t.Fatalf("initial report = %+v", first)
	}
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "https://origin.example/second", nil))
	if err := middleware.FlushCoverage(context.Background()); err != nil {
		t.Fatal(err)
	}
	var flushed coverageReport
	select {
	case flushed = <-fake.coverageReports:
	case <-time.After(2 * time.Second):
		t.Fatal("flushed coverage report was not delivered")
	}
	if flushed.Sequence != 2 || flushed.Endpoints[0].Protected != 2 || flushed.Endpoints[0].Evaluated != 2 {
		t.Fatalf("flushed report = %+v", flushed)
	}
	if err := middleware.FlushCoverage(nil); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("nil flush context error = %v", err)
	}
}

func TestMiddlewareCoverageRejectsMisconfiguration(t *testing.T) {
	base := Config{BaseURL: "http://127.0.0.1:8080", APIKey: "adapter-key", Classifier: StaticClassification("read", "public_content"), FailureMode: FailClosed}
	for name, mutate := range map[string]func(*Config){
		"settings while disabled": func(config *Config) { config.CoverageReportEvery = 1 },
		"zero interval":           func(config *Config) { config.CoverageReporting = true; config.CoverageReportInterval = time.Nanosecond },
		"excess count":            func(config *Config) { config.CoverageReporting = true; config.CoverageReportEvery = 100_001 },
	} {
		t.Run(name, func(t *testing.T) {
			config := base
			mutate(&config)
			if _, err := New(config); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("coverage config error = %v", err)
			}
		})
	}
}

func TestMiddlewareCoverageDistinguishesAvailabilityBypassFromRejection(t *testing.T) {
	for _, test := range []struct {
		name         string
		failureMode  FailureMode
		wantStatus   int
		wantNext     int32
		wantBypassed uint64
		wantRejected uint64
	}{
		{name: "fail open bypass", failureMode: FailOpen, wantStatus: http.StatusNoContent, wantNext: 1, wantBypassed: 1},
		{name: "fail closed rejection", failureMode: FailClosed, wantStatus: http.StatusServiceUnavailable, wantRejected: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			now := time.Date(2026, time.August, 28, 12, 0, 0, 0, time.UTC)
			fake := &fakePalisade{t: t, now: now, originUnavailable: true, coverageReports: make(chan coverageReport, 1)}
			service := httptest.NewServer(fake)
			defer service.Close()
			middleware, err := New(Config{
				BaseURL: service.URL, APIKey: "adapter-key", FailureMode: test.failureMode,
				Classifier: StaticClassification("read", "account"), CoverageReporting: true,
				CoverageReportEvery: 1, CoverageReportInterval: time.Second,
			})
			if err != nil {
				t.Fatal(err)
			}
			middleware.now = func() time.Time { return now }
			var nextCalls atomic.Int32
			handler := middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				nextCalls.Add(1)
				w.WriteHeader(http.StatusNoContent)
			}))
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "https://origin.example/account", nil))
			if response.Code != test.wantStatus || nextCalls.Load() != test.wantNext {
				t.Fatalf("response/next = %d/%d", response.Code, nextCalls.Load())
			}
			select {
			case report := <-fake.coverageReports:
				counter := report.Endpoints[5]
				if counter.Protected != 1 || counter.Bypassed != test.wantBypassed || counter.Rejected != test.wantRejected {
					t.Fatalf("coverage disposition = %+v", counter)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("coverage report was not delivered")
			}
		})
	}
}

func TestMiddlewarePassesClosedSignalsWithoutRawRequestData(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	fake := &fakePalisade{t: t, now: now}
	service := httptest.NewServer(fake)
	defer service.Close()
	middleware := newTestMiddleware(t, service.URL, now, FailClosed)
	middleware.classifier = func(*http.Request) (Classification, error) {
		return Classification{Action: "read", EndpointClass: "public_content", EvaluationCohort: "reduced_motion"}, nil
	}
	middleware.signals = func(*http.Request) (Signals, error) {
		return Signals{
			UserAgentPresent: true, TransportProtocol: "provider-spoof", TransportSecurity: "provider-spoof", ClientAddressSource: "provider-spoof",
			EdgeFingerprintClass: "automation_consistent", EdgeFingerprintMethod: "tls_http2",
			NetworkReputation: "elevated_risk", NetworkType: "hosting",
		}, nil
	}
	var nextCalls atomic.Int32
	handler := middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		nextCalls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))

	first := httptest.NewRequest(http.MethodGet, "https://origin.example/private?secret=must-not-leave", nil)
	first.Header.Set("User-Agent", "test-browser")
	first.Header.Set("CF-Connecting-IP", "198.51.100.77")
	first.Header.Set("X-Forwarded-Proto", "https")
	firstResponse := httptest.NewRecorder()
	handler.ServeHTTP(firstResponse, first)
	if firstResponse.Code != http.StatusOK || nextCalls.Load() != 1 || firstResponse.Header().Get("X-Palisade-Adapter") != "pass" {
		t.Fatalf("first response = %d headers=%v next=%d", firstResponse.Code, firstResponse.Header(), nextCalls.Load())
	}
	sessionCookie := findCookie(t, firstResponse.Result().Cookies(), SessionCookieName)

	second := httptest.NewRequest(http.MethodGet, "https://origin.example/another?private=value", nil)
	second.Header.Set("User-Agent", "test-browser")
	second.AddCookie(sessionCookie)
	secondResponse := httptest.NewRecorder()
	handler.ServeHTTP(secondResponse, second)
	if secondResponse.Code != http.StatusOK || nextCalls.Load() != 2 || fake.sessionIssues.Load() != 1 || fake.tokenIssues.Load() != 2 || fake.originChecks.Load() != 2 {
		t.Fatalf("second response/calls = %d/%d session=%d token=%d origin=%d", secondResponse.Code, nextCalls.Load(), fake.sessionIssues.Load(), fake.tokenIssues.Load(), fake.originChecks.Load())
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if len(fake.sequences) != 2 || fake.sequences[0] != 1 || fake.sequences[1] != 2 {
		t.Fatalf("sequences = %v", fake.sequences)
	}
	for _, body := range fake.originBodies {
		if bytes.Contains(body, []byte("must-not-leave")) || bytes.Contains(body, []byte("private")) || bytes.Contains(body, []byte("test-browser")) ||
			bytes.Contains(body, []byte("192.0.2.1")) || bytes.Contains(body, []byte("198.51.100.77")) || bytes.Contains(body, []byte("provider-spoof")) {
			t.Fatalf("raw request data left adapter: %s", body)
		}
		if !bytes.Contains(body, []byte(`"evaluation_cohort":"reduced_motion"`)) {
			t.Fatalf("closed evaluation cohort missing: %s", body)
		}
		for _, expected := range [][]byte{[]byte(`"transport_protocol":"http1"`), []byte(`"transport_security":"direct_tls"`), []byte(`"client_address_source":"direct"`)} {
			if !bytes.Contains(body, expected) {
				t.Fatalf("normalized transport field %s missing: %s", expected, body)
			}
		}
		for _, expected := range [][]byte{[]byte(`"edge_fingerprint_class":"automation_consistent"`), []byte(`"edge_fingerprint_method":"tls_http2"`), []byte(`"network_reputation":"elevated_risk"`), []byte(`"network_type":"hosting"`)} {
			if !bytes.Contains(body, expected) {
				t.Fatalf("closed edge field %s missing: %s", expected, body)
			}
		}
	}
}

func TestEdgeIntelligenceRejectsRawOrUnpairedValues(t *testing.T) {
	valid := Signals{EdgeFingerprintClass: "automation_consistent", EdgeFingerprintMethod: "tls_http2", NetworkReputation: "elevated_risk", NetworkType: "hosting"}
	if !validEdgeIntelligence(valid) {
		t.Fatal("valid closed edge intelligence was rejected")
	}
	invalid := []Signals{
		{EdgeFingerprintClass: "ja4:a1b2c3", EdgeFingerprintMethod: "tls"},
		{EdgeFingerprintClass: "automation_consistent"},
		{EdgeFingerprintMethod: "http2"},
		{NetworkReputation: "provider-score-92"},
		{NetworkType: "AS13335"},
	}
	for _, signals := range invalid {
		if validEdgeIntelligence(signals) {
			t.Fatalf("invalid edge intelligence accepted: %+v", signals)
		}
	}
}

func TestMiddlewareDerivesCrawlerIdentityAndIgnoresDirectForwardingSpoof(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	fake := &fakePalisade{t: t, now: now}
	service := httptest.NewServer(fake)
	defer service.Close()
	registry, err := NewCrawlerRegistry([]CrawlerIdentity{{
		Name: "example-search", Class: CrawlerClassSearchIndexer,
		UserAgentTokens: []string{"ExampleSearchBot"}, CIDRs: []string{"192.0.2.0/24"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	middleware := newTestMiddleware(t, service.URL, now, FailClosed)
	middleware.crawlers = registry
	middleware.signals = func(*http.Request) (Signals, error) {
		return Signals{VerifiedBot: true, CrawlerClass: CrawlerClassSearchIndexer, CrawlerVerification: CrawlerVerificationIPUARegistry}, nil
	}
	handler := middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))

	verified := httptest.NewRequest(http.MethodGet, "https://origin.example/", nil)
	verified.RemoteAddr = "192.0.2.10:443"
	verified.Header.Set("User-Agent", "ExampleSearchBot/1.0")
	verifiedResponse := httptest.NewRecorder()
	handler.ServeHTTP(verifiedResponse, verified)
	if verifiedResponse.Code != http.StatusOK {
		t.Fatalf("verified response=%d", verifiedResponse.Code)
	}
	cookie := findCookie(t, verifiedResponse.Result().Cookies(), SessionCookieName)

	spoofed := httptest.NewRequest(http.MethodGet, "https://origin.example/", nil)
	spoofed.RemoteAddr = "198.51.100.10:443"
	spoofed.Header.Set("User-Agent", "ExampleSearchBot/1.0")
	spoofed.Header.Set("CF-Connecting-IP", "192.0.2.10")
	spoofed.AddCookie(cookie)
	spoofedResponse := httptest.NewRecorder()
	handler.ServeHTTP(spoofedResponse, spoofed)
	if spoofedResponse.Code != http.StatusOK {
		t.Fatalf("spoofed response=%d", spoofedResponse.Code)
	}

	fake.mu.Lock()
	defer fake.mu.Unlock()
	if len(fake.originBodies) != 2 ||
		!bytes.Contains(fake.originBodies[0], []byte(`"verified_bot":true`)) ||
		!bytes.Contains(fake.originBodies[0], []byte(`"crawler_class":"search_indexer"`)) ||
		!bytes.Contains(fake.originBodies[0], []byte(`"crawler_verification":"ip_ua_registry"`)) ||
		!bytes.Contains(fake.originBodies[1], []byte(`"verified_bot":false`)) ||
		!bytes.Contains(fake.originBodies[1], []byte(`"crawler_class":"unknown"`)) {
		t.Fatalf("crawler payloads=%s", fake.originBodies)
	}
	for _, body := range fake.originBodies {
		if bytes.Contains(body, []byte("ExampleSearchBot")) || bytes.Contains(body, []byte("192.0.2.10")) || bytes.Contains(body, []byte("198.51.100.10")) {
			t.Fatalf("raw crawler identity left adapter: %s", body)
		}
	}
}

func TestMiddlewareOutcomeHandleLinksExactDecisionWithoutSessionID(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	fake := &fakePalisade{t: t, now: now}
	service := httptest.NewServer(fake)
	defer service.Close()
	middleware := newTestMiddleware(t, service.URL, now, FailClosed)

	handler := middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handle, ok := OutcomeHandleFromRequest(r)
		if !ok || handle.DecisionID() != "decision-1" {
			t.Fatalf("outcome handle = %+v, %v", handle, ok)
		}
		if err := middleware.RecordOutcome(r, handle, Outcome{
			Kind: "human_confirmed", Provenance: "authenticated_account", Confidence: "confirmed",
		}); err != nil {
			t.Fatal(err)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	request := httptest.NewRequest(http.MethodGet, "https://origin.example/private?must-not-leave=true", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent || fake.outcomes.Load() != 1 {
		t.Fatalf("response/outcomes = %d/%d", response.Code, fake.outcomes.Load())
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if len(fake.outcomeBodies) != 1 || !bytes.Contains(fake.outcomeBodies[0], []byte(`"decision_id":"decision-1"`)) ||
		!bytes.Contains(fake.outcomeBodies[0], []byte(`"endpoint_class":"public_content"`)) || bytes.Contains(fake.outcomeBodies[0], []byte("session_id")) ||
		bytes.Contains(fake.outcomeBodies[0], []byte("must-not-leave")) {
		t.Fatalf("outcome payload = %s", fake.outcomeBodies)
	}
}

func TestMiddlewareRejectsInvalidOutcomeBeforeNetwork(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	fake := &fakePalisade{t: t, now: now}
	service := httptest.NewServer(fake)
	defer service.Close()
	middleware := newTestMiddleware(t, service.URL, now, FailClosed)
	handle := OutcomeHandle{decisionID: "decision-1", endpointClass: "public_content"}
	request := withOutcomeHandle(httptest.NewRequest(http.MethodGet, "https://origin.example/", nil), handle.decisionID, handle.endpointClass, http.Cookie{Name: SessionCookieName, Value: testSessionValue})
	if err := middleware.RecordOutcome(request, handle, Outcome{Kind: "human_confirmed", Provenance: "server_observed", Confidence: "confirmed"}); !errors.Is(err, ErrInvalidOutcome) {
		t.Fatalf("invalid human outcome error = %v", err)
	}
	forged := OutcomeHandle{decisionID: "decision-2", endpointClass: "public_content"}
	if err := middleware.RecordOutcome(request, forged, Outcome{Kind: "successful_action", Provenance: "server_observed", Confidence: "confirmed"}); !errors.Is(err, ErrInvalidOutcome) {
		t.Fatalf("forged outcome handle error = %v", err)
	}
	if fake.outcomes.Load() != 0 {
		t.Fatalf("invalid outcome reached service %d times", fake.outcomes.Load())
	}
}

func TestChallengePageRelayAndOneTimeRetryGrant(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	fake := &fakePalisade{t: t, now: now, challenge: true}
	service := httptest.NewServer(fake)
	defer service.Close()
	middleware := newTestMiddleware(t, service.URL, now, FailClosed)
	var nextCalls atomic.Int32
	handler := middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		nextCalls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))

	initial := httptest.NewRequest(http.MethodGet, "https://origin.example/protected?account=private", nil)
	initialResponse := httptest.NewRecorder()
	handler.ServeHTTP(initialResponse, initial)
	if initialResponse.Code != http.StatusForbidden || !strings.Contains(initialResponse.Body.String(), "Verify this request") ||
		strings.Contains(initialResponse.Body.String(), "account=private") || initialResponse.Header().Get("Content-Security-Policy") == "" {
		t.Fatalf("challenge page = %d headers=%v body=%s", initialResponse.Code, initialResponse.Header(), initialResponse.Body.String())
	}
	sessionCookie := findCookie(t, initialResponse.Result().Cookies(), SessionCookieName)
	pendingCookie := findCookie(t, initialResponse.Result().Cookies(), PendingCookieName)

	metadata := httptest.NewRequest(http.MethodGet, "https://origin.example/__palisade/challenge/"+testChallengeID, nil)
	metadata.AddCookie(sessionCookie)
	metadataResponse := httptest.NewRecorder()
	handler.ServeHTTP(metadataResponse, metadata)
	if metadataResponse.Code != http.StatusOK || !strings.Contains(metadataResponse.Body.String(), testVerifyToken) {
		t.Fatalf("metadata relay = %d %s", metadataResponse.Code, metadataResponse.Body.String())
	}

	verify := httptest.NewRequest(http.MethodPost, "https://origin.example/__palisade/challenge/verify", strings.NewReader(`{"challenge_id":"`+testChallengeID+`","verification_token":"`+testVerifyToken+`"}`))
	verify.AddCookie(sessionCookie)
	verifyResponse := httptest.NewRecorder()
	handler.ServeHTTP(verifyResponse, verify)
	if verifyResponse.Code != http.StatusOK || !strings.Contains(verifyResponse.Body.String(), testRedeemToken) {
		t.Fatalf("verify relay = %d %s", verifyResponse.Code, verifyResponse.Body.String())
	}

	spoofedBinding := httptest.NewRequest(http.MethodPost, "https://origin.example/__palisade/challenge/redeem", strings.NewReader(`{"challenge_id":"`+testChallengeID+`","redemption_token":"`+testRedeemToken+`","redemption_binding":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","action":"read","endpoint_class":"public_content"}`))
	spoofedBinding.AddCookie(sessionCookie)
	spoofedBinding.AddCookie(pendingCookie)
	spoofedBindingResponse := httptest.NewRecorder()
	handler.ServeHTTP(spoofedBindingResponse, spoofedBinding)
	if spoofedBindingResponse.Code != http.StatusBadRequest || fake.redemptions.Load() != 0 {
		t.Fatalf("browser-controlled binding = %d backend_redeems=%d", spoofedBindingResponse.Code, fake.redemptions.Load())
	}

	redeem := httptest.NewRequest(http.MethodPost, "https://origin.example/__palisade/challenge/redeem", strings.NewReader(`{"challenge_id":"`+testChallengeID+`","redemption_token":"`+testRedeemToken+`","action":"read","endpoint_class":"public_content"}`))
	redeem.AddCookie(sessionCookie)
	redeem.AddCookie(pendingCookie)
	redeemResponse := httptest.NewRecorder()
	handler.ServeHTTP(redeemResponse, redeem)
	if redeemResponse.Code != http.StatusNoContent || redeemResponse.Header().Get("X-Palisade-Challenge") != "redeemed" {
		t.Fatalf("redeem relay = %d %s", redeemResponse.Code, redeemResponse.Body.String())
	}
	grantCookie := findCookie(t, redeemResponse.Result().Cookies(), RedemptionCookieName)

	mismatch := httptest.NewRequest(http.MethodGet, "https://origin.example/protected?account=different", nil)
	mismatch.AddCookie(sessionCookie)
	mismatch.AddCookie(grantCookie)
	mismatchResponse := httptest.NewRecorder()
	handler.ServeHTTP(mismatchResponse, mismatch)
	if mismatchResponse.Code != http.StatusForbidden || nextCalls.Load() != 0 || fake.originChecks.Load() != 2 {
		t.Fatalf("mismatched retry = %d next=%d origin=%d", mismatchResponse.Code, nextCalls.Load(), fake.originChecks.Load())
	}

	retry := httptest.NewRequest(http.MethodGet, "https://origin.example/protected?account=private", nil)
	retry.AddCookie(sessionCookie)
	retry.AddCookie(grantCookie)
	retryResponse := httptest.NewRecorder()
	handler.ServeHTTP(retryResponse, retry)
	if retryResponse.Code != http.StatusOK || nextCalls.Load() != 1 || fake.originChecks.Load() != 2 || retryResponse.Header().Get("X-Palisade-Adapter") != "redeemed" {
		t.Fatalf("authorized retry = %d next=%d origin=%d headers=%v", retryResponse.Code, nextCalls.Load(), fake.originChecks.Load(), retryResponse.Header())
	}

	replay := httptest.NewRequest(http.MethodGet, "https://origin.example/protected?account=private", nil)
	replay.AddCookie(sessionCookie)
	replay.AddCookie(grantCookie)
	replayResponse := httptest.NewRecorder()
	handler.ServeHTTP(replayResponse, replay)
	if replayResponse.Code != http.StatusForbidden || nextCalls.Load() != 1 || fake.originChecks.Load() != 3 {
		t.Fatalf("grant replay = %d next=%d origin=%d", replayResponse.Code, nextCalls.Load(), fake.originChecks.Load())
	}
	if fake.metadataGets.Load() != 1 || fake.verifications.Load() != 1 || fake.redemptions.Load() != 1 {
		t.Fatalf("challenge calls metadata=%d verify=%d redeem=%d", fake.metadataGets.Load(), fake.verifications.Load(), fake.redemptions.Load())
	}
}

func TestFailureModeIsExplicitAndEnforced(t *testing.T) {
	service := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer service.Close()
	now := time.Unix(1_800_000_000, 0).UTC()
	for _, test := range []struct {
		mode       FailureMode
		wantStatus int
		wantNext   int32
	}{
		{mode: FailOpen, wantStatus: http.StatusOK, wantNext: 1},
		{mode: FailClosed, wantStatus: http.StatusServiceUnavailable, wantNext: 0},
	} {
		t.Run(string(test.mode), func(t *testing.T) {
			middleware := newTestMiddleware(t, service.URL, now, test.mode)
			var nextCalls atomic.Int32
			handler := middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				nextCalls.Add(1)
				w.WriteHeader(http.StatusOK)
			}))
			request := httptest.NewRequest(http.MethodGet, "https://origin.example/", nil)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.wantStatus || nextCalls.Load() != test.wantNext {
				t.Fatalf("status/next = %d/%d", response.Code, nextCalls.Load())
			}
		})
	}
	if _, err := New(Config{BaseURL: service.URL, APIKey: "adapter-key", Classifier: StaticClassification("read", "public_content")}); err == nil {
		t.Fatal("missing explicit failure mode was accepted")
	}
}

func TestMiddlewareAppliesProgressiveDelayThrottleAndBlock(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	for _, test := range []struct {
		handling   string
		wantStatus int
		wantRetry  string
	}{
		{handling: "delay", wantStatus: http.StatusTooManyRequests, wantRetry: "1"},
		{handling: "throttle", wantStatus: http.StatusTooManyRequests, wantRetry: "5"},
		{handling: "block", wantStatus: http.StatusForbidden, wantRetry: "300"},
	} {
		t.Run(test.handling, func(t *testing.T) {
			fake := &fakePalisade{t: t, now: now, handling: test.handling}
			service := httptest.NewServer(fake)
			defer service.Close()
			guard := newTestMiddleware(t, service.URL, now, FailClosed)
			var nextCalls atomic.Int32
			response := httptest.NewRecorder()
			guard.Handler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				nextCalls.Add(1)
			})).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "https://origin.example/protected", nil))
			if response.Code != test.wantStatus || response.Header().Get("Retry-After") != test.wantRetry ||
				response.Header().Get("X-Palisade-Action") != test.handling || nextCalls.Load() != 0 {
				t.Fatalf("response = %d headers=%v next=%d", response.Code, response.Header(), nextCalls.Load())
			}
		})
	}
}

func TestMiddlewareRejectsMalformedDelayContract(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	fake := &fakePalisade{t: t, now: now, handling: "invalid_delay"}
	service := httptest.NewServer(fake)
	defer service.Close()
	guard := newTestMiddleware(t, service.URL, now, FailClosed)
	response := httptest.NewRecorder()
	guard.Handler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("malformed delay reached the protected application")
	})).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "https://origin.example/protected", nil))
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("malformed delay response = %d", response.Code)
	}
}

func TestNonGETChallengeDoesNotReplayRequestBody(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	fake := &fakePalisade{t: t, now: now, challenge: true}
	service := httptest.NewServer(fake)
	defer service.Close()
	guard := newTestMiddleware(t, service.URL, now, FailClosed)
	var nextCalls atomic.Int32
	request := httptest.NewRequest(http.MethodPost, "https://origin.example/protected?secret=query", strings.NewReader("secret-body"))
	response := httptest.NewRecorder()
	guard.Handler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		nextCalls.Add(1)
	})).ServeHTTP(response, request)
	if response.Code != http.StatusForbidden || response.Header().Get("Location") != DefaultPrefix+"/challenge/"+testChallengeID ||
		response.Header().Get("X-Palisade-Action") != "challenge" || response.Body.Len() != 0 || nextCalls.Load() != 0 {
		t.Fatalf("non-GET challenge = %d headers=%v body=%q next=%d", response.Code, response.Header(), response.Body.String(), nextCalls.Load())
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if len(fake.originBodies) != 1 || bytes.Contains(fake.originBodies[0], []byte("secret")) {
		t.Fatalf("raw write request left adapter: %q", fake.originBodies)
	}
}

func TestFallbackClosesMatchingLocalPendingState(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	fake := &fakePalisade{t: t, now: now, challenge: true}
	service := httptest.NewServer(fake)
	defer service.Close()
	guard := newTestMiddleware(t, service.URL, now, FailClosed)
	handler := guard.Handler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("challenged request reached application")
	}))

	initialResponse := httptest.NewRecorder()
	handler.ServeHTTP(initialResponse, httptest.NewRequest(http.MethodGet, "https://origin.example/protected", nil))
	session := findCookie(t, initialResponse.Result().Cookies(), SessionCookieName)
	pending := findCookie(t, initialResponse.Result().Cookies(), PendingCookieName)
	fallback := httptest.NewRequest(http.MethodPost, "https://origin.example/__palisade/challenge/fallback", strings.NewReader(`{"challenge_id":"`+testChallengeID+`"}`))
	fallback.AddCookie(session)
	fallback.AddCookie(pending)
	fallbackResponse := httptest.NewRecorder()
	handler.ServeHTTP(fallbackResponse, fallback)
	cleared := findCookie(t, fallbackResponse.Result().Cookies(), PendingCookieName)
	if fallbackResponse.Code != http.StatusNoContent || cleared.MaxAge != -1 || fake.fallbacks.Load() != 1 {
		t.Fatalf("fallback = %d cookies=%v calls=%d", fallbackResponse.Code, fallbackResponse.Result().Cookies(), fake.fallbacks.Load())
	}
	if _, _, err := guard.state.reserveGrant(pending.Value, testChallengeID, session.Value, "read", "public_content", now); !errors.Is(err, ErrInvalidPending) {
		t.Fatalf("fallback left pending grant usable: %v", err)
	}
}

func TestGrantIsConsumedExactlyOnceConcurrently(t *testing.T) {
	state, err := newBoundedState(10, 10, time.Minute, time.Minute, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0).UTC()
	request := httptest.NewRequest(http.MethodGet, "https://origin.example/protected?secret=bound", nil)
	classification := Classification{Action: "read", EndpointClass: "public_content"}
	binding := state.challengeBinding(request, classification, testSessionValue, 1)
	pending, err := state.issuePending(request, classification, testChallengeID, testSessionValue, binding, now)
	if err != nil {
		t.Fatal(err)
	}
	cookie, encodedBinding, err := state.reserveGrant(pending.Value, testChallengeID, testSessionValue, classification.Action, classification.EndpointClass, now)
	if err != nil {
		t.Fatal(err)
	}
	if encodedBinding != base64.RawURLEncoding.EncodeToString(binding[:]) {
		t.Fatalf("reserved flow binding = %q", encodedBinding)
	}
	state.commitPending(pending.Value)
	wrongSession := httptest.NewRequest(http.MethodGet, "https://origin.example/protected?secret=bound", nil)
	wrongSession.AddCookie(&cookie)
	wrongSession.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "different-session"})
	if state.consumeGrant(wrongSession, classification, now) {
		t.Fatal("grant accepted with a different session")
	}
	var successes atomic.Int32
	var wait sync.WaitGroup
	for range 32 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			candidate := httptest.NewRequest(http.MethodGet, "https://origin.example/protected?secret=bound", nil)
			candidate.AddCookie(&cookie)
			candidate.AddCookie(&http.Cookie{Name: SessionCookieName, Value: testSessionValue})
			if state.consumeGrant(candidate, classification, now) {
				successes.Add(1)
			}
		}()
	}
	wait.Wait()
	if successes.Load() != 1 {
		t.Fatalf("successful grant consumptions = %d", successes.Load())
	}
}

func TestPendingBindingRejectsDifferentChallengeAndSession(t *testing.T) {
	state, err := newBoundedState(10, 10, time.Minute, time.Minute, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0).UTC()
	request := httptest.NewRequest(http.MethodGet, "https://origin.example/protected?secret=bound", nil)
	classification := Classification{Action: "read", EndpointClass: "public_content"}
	binding := state.challengeBinding(request, classification, testSessionValue, 1)
	pending, err := state.issuePending(request, classification, testChallengeID, testSessionValue, binding, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := state.reserveGrant(pending.Value, "ZYXWVUTSRQPONMLKJIHGFEDC12345678", testSessionValue, classification.Action, classification.EndpointClass, now); !errors.Is(err, ErrInvalidPending) {
		t.Fatalf("different challenge error = %v", err)
	}
	if _, _, err := state.reserveGrant(pending.Value, testChallengeID, "different-session", classification.Action, classification.EndpointClass, now); !errors.Is(err, ErrInvalidPending) {
		t.Fatalf("different session error = %v", err)
	}
	if _, _, err := state.reserveGrant(pending.Value, testChallengeID, testSessionValue, classification.Action, classification.EndpointClass, now); err != nil {
		t.Fatalf("correct binding rejected: %v", err)
	}
}

func TestOriginChallengeBindingIsTargetSequenceAndInstanceBound(t *testing.T) {
	state, err := newBoundedState(10, 10, time.Minute, time.Minute, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	classification := Classification{Action: "read", EndpointClass: "public_content"}
	request := httptest.NewRequest(http.MethodGet, "https://origin.example/protected?account=one", nil)
	baseline := state.challengeBinding(request, classification, testSessionValue, 7)
	if repeated := state.challengeBinding(request, classification, testSessionValue, 7); baseline != repeated {
		t.Fatal("same origin flow did not produce a stable binding")
	}
	if encoded := base64.RawURLEncoding.EncodeToString(baseline[:]); !stableToken(encoded, 43) {
		t.Fatalf("encoded binding = %q", encoded)
	}
	queryChanged := httptest.NewRequest(http.MethodGet, "https://origin.example/protected?account=two", nil)
	if baseline == state.challengeBinding(queryChanged, classification, testSessionValue, 7) {
		t.Fatal("binding was reusable across query targets")
	}
	methodChanged := httptest.NewRequest(http.MethodPost, "https://origin.example/protected?account=one", nil)
	if baseline == state.challengeBinding(methodChanged, classification, testSessionValue, 7) {
		t.Fatal("binding was reusable across request methods")
	}
	if baseline == state.challengeBinding(request, classification, "different-session", 7) {
		t.Fatal("binding was reusable across sessions")
	}
	if baseline == state.challengeBinding(request, classification, testSessionValue, 8) {
		t.Fatal("binding was reusable across decision sequences")
	}
	otherAction := Classification{Action: "write", EndpointClass: "public_content"}
	if baseline == state.challengeBinding(request, otherAction, testSessionValue, 7) {
		t.Fatal("binding was reusable across actions")
	}
	otherClass := Classification{Action: "read", EndpointClass: "account"}
	if baseline == state.challengeBinding(request, otherClass, testSessionValue, 7) {
		t.Fatal("binding was reusable across endpoint classes")
	}
	otherState, err := newBoundedState(10, 10, time.Minute, time.Minute, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if baseline == otherState.challengeBinding(request, classification, testSessionValue, 7) {
		t.Fatal("binding was reusable across adapter instances")
	}
}

func TestPendingCanBeReservedOnlyOnceConcurrently(t *testing.T) {
	state, err := newBoundedState(10, 64, time.Minute, time.Minute, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0).UTC()
	request := httptest.NewRequest(http.MethodGet, "https://origin.example/protected", nil)
	classification := Classification{Action: "read", EndpointClass: "public_content"}
	binding := state.challengeBinding(request, classification, testSessionValue, 1)
	pending, err := state.issuePending(request, classification, testChallengeID, testSessionValue, binding, now)
	if err != nil {
		t.Fatal(err)
	}
	var successes atomic.Int32
	var wait sync.WaitGroup
	for range 32 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			if _, _, reserveErr := state.reserveGrant(pending.Value, testChallengeID, testSessionValue, classification.Action, classification.EndpointClass, now); reserveErr == nil {
				successes.Add(1)
			}
		}()
	}
	wait.Wait()
	if successes.Load() != 1 {
		t.Fatalf("successful pending reservations = %d", successes.Load())
	}
}

func TestPendingAndGrantExpireAtExactBoundary(t *testing.T) {
	state, err := newBoundedState(10, 10, time.Minute, time.Minute, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0).UTC()
	request := httptest.NewRequest(http.MethodGet, "https://origin.example/protected", nil)
	classification := Classification{Action: "read", EndpointClass: "public_content"}
	binding := state.challengeBinding(request, classification, testSessionValue, 1)
	expiredPending, err := state.issuePending(request, classification, testChallengeID, testSessionValue, binding, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := state.reserveGrant(expiredPending.Value, testChallengeID, testSessionValue, classification.Action, classification.EndpointClass, now.Add(time.Minute)); !errors.Is(err, ErrInvalidPending) {
		t.Fatalf("pending exact-boundary expiry = %v", err)
	}
	pending, err := state.issuePending(request, classification, testChallengeID, testSessionValue, binding, now)
	if err != nil {
		t.Fatal(err)
	}
	grant, _, err := state.reserveGrant(pending.Value, testChallengeID, testSessionValue, classification.Action, classification.EndpointClass, now)
	if err != nil {
		t.Fatal(err)
	}
	state.commitPending(pending.Value)
	retry := httptest.NewRequest(http.MethodGet, "https://origin.example/protected", nil)
	retry.AddCookie(&grant)
	retry.AddCookie(&http.Cookie{Name: SessionCookieName, Value: testSessionValue})
	if state.consumeGrant(retry, classification, now.Add(time.Minute)) {
		t.Fatal("grant remained valid at its exact expiry boundary")
	}
}

func TestNewRejectsPlaintextRemoteService(t *testing.T) {
	config := Config{
		BaseURL: "http://service.example", APIKey: "adapter-key", FailureMode: FailClosed,
		Classifier: StaticClassification("read", "public_content"),
	}
	if _, err := New(config); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("plaintext remote URL error = %v", err)
	}
	config.BaseURL = "https://service.example"
	if _, err := New(config); err != nil {
		t.Fatalf("HTTPS service URL rejected: %v", err)
	}
}

func TestNewDisablesSharedHTTPClientCookieJar(t *testing.T) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Jar: jar}
	guard, err := New(Config{
		BaseURL: "https://service.example", APIKey: "adapter-key", HTTPClient: client, FailureMode: FailClosed,
		Classifier: StaticClassification("read", "public_content"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if guard.client.Jar != nil {
		t.Fatal("adapter retained a shared cookie jar")
	}
	if client.Jar == nil {
		t.Fatal("adapter mutated the caller's HTTP client")
	}
}

func TestInvalidSignalsAndRiskyShadowResponseFailClosed(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	invalidSignals, err := New(Config{
		BaseURL: "https://service.example", APIKey: "adapter-key", FailureMode: FailOpen,
		Classifier: StaticClassification("read", "public_content"),
		Signals:    func(*http.Request) (Signals, error) { return Signals{ExternalRiskScore: math.NaN()}, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	invalidSignals.now = func() time.Time { return now }
	response := httptest.NewRecorder()
	invalidSignals.Handler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("invalid local signals reached application under fail-open")
	})).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "https://origin.example/", nil))
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("invalid signal response = %d", response.Code)
	}

	service := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/session":
			http.SetCookie(w, &http.Cookie{Name: SessionCookieName, Value: testSessionValue, Path: "/", Expires: now.Add(time.Hour), Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
			writeFakeJSON(w, http.StatusCreated, map[string]any{"session_id": testSessionID, "expires_at": now.Add(time.Hour)})
		case "/v1/token":
			writeFakeJSON(w, http.StatusCreated, map[string]any{"proof_token": "proof-token", "expires_in": 60})
		case "/v1/origin-check":
			w.Header().Set("X-Palisade-Decision-ID", "decision-invalid")
			w.Header().Set("X-Palisade-Mode", "shadow")
			w.Header().Set("X-Palisade-Action", "challenge")
			w.Header().Set("X-Palisade-Handling", "challenge")
			w.Header().Set("X-Palisade-Challenge-ID", testChallengeID)
			w.Header().Set("Location", "/v1/challenge/"+testChallengeID)
			w.WriteHeader(http.StatusForbidden)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer service.Close()
	guard := newTestMiddleware(t, service.URL, now, FailClosed)
	response = httptest.NewRecorder()
	guard.Handler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("risky shadow response reached application")
	})).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "https://origin.example/", nil))
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("risky shadow response = %d %s", response.Code, response.Body.String())
	}
}

func newTestMiddleware(t *testing.T, baseURL string, now time.Time, failureMode FailureMode) *Middleware {
	t.Helper()
	middleware, err := New(Config{
		BaseURL: baseURL, APIKey: "adapter-key", Classifier: StaticClassification("read", "public_content"),
		FailureMode: failureMode,
	})
	if err != nil {
		t.Fatal(err)
	}
	middleware.now = func() time.Time { return now }
	return middleware
}

func findCookie(t *testing.T, cookies []*http.Cookie, name string) *http.Cookie {
	t.Helper()
	for _, cookie := range cookies {
		if cookie.Name == name {
			return cookie
		}
	}
	t.Fatalf("cookie %s missing: %+v", name, cookies)
	return nil
}

func cookieValue(r *http.Request, name string) string {
	cookie, err := r.Cookie(name)
	if err != nil {
		return ""
	}
	return cookie.Value
}

func decodeFakeJSON(t *testing.T, r *http.Request, target any) {
	t.Helper()
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(target); err != nil {
		t.Errorf("decode fake JSON: %v", err)
	}
}

func writeFakeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
