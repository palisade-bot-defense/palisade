package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/palisade-bot-defense/palisade/internal/challenge"
	"github.com/palisade-bot-defense/palisade/internal/core"
	"github.com/palisade-bot-defense/palisade/internal/events"
	"github.com/palisade-bot-defense/palisade/internal/sessioncookie"
	"github.com/palisade-bot-defense/palisade/internal/shadowlog"
	"github.com/palisade-bot-defense/palisade/internal/token"
)

type fakeEngine struct{}

func (fakeEngine) Decide(context.Context, core.DecisionRequest) (core.Decision, error) {
	return core.Decision{DecisionID: "test", Action: core.ActionAllow, ExpiresAt: time.Now()}, nil
}

type recordingEngine struct{ request core.DecisionRequest }

func (e *recordingEngine) Decide(_ context.Context, request core.DecisionRequest) (core.Decision, error) {
	e.request = request
	return core.Decision{DecisionID: "test", Action: core.ActionAllow, ExpiresAt: time.Now()}, nil
}

type contractEngine struct{}

func (contractEngine) Decide(context.Context, core.DecisionRequest) (core.Decision, error) {
	return core.Decision{
		DecisionID:     "decision-contract",
		Action:         core.ActionObserve,
		ComputedAction: core.ActionBlock,
		Mode:           core.RuntimeModeShadow,
		ExpiresAt:      time.Unix(1_800_000_000, 0).UTC(),
	}, nil
}

type fixedEngine struct{ decision core.Decision }

func (e fixedEngine) Decide(context.Context, core.DecisionRequest) (core.Decision, error) {
	return e.decision, nil
}

type capturingEngine struct {
	request  core.DecisionRequest
	requests []core.DecisionRequest
	decision core.Decision
}

func (e *capturingEngine) Decide(_ context.Context, request core.DecisionRequest) (core.Decision, error) {
	e.request = request
	e.requests = append(e.requests, request)
	return e.decision, nil
}

type recordingShadow struct {
	decisions        int
	decisionRequests []core.DecisionRequest
	decisionValues   []core.Decision
	decisionErr      error
	outcomes         []shadowlog.OutcomeRequest
	outcomeErr       error
}

func (r *recordingShadow) RecordDecision(request core.DecisionRequest, decision core.Decision, _ time.Time) error {
	r.decisions++
	r.decisionRequests = append(r.decisionRequests, request)
	r.decisionValues = append(r.decisionValues, decision)
	return r.decisionErr
}

func (r *recordingShadow) RecordOutcome(request shadowlog.OutcomeRequest, _ time.Time) error {
	r.outcomes = append(r.outcomes, request)
	return r.outcomeErr
}

func TestDecisionRejectsUnknownFields(t *testing.T) {
	tokens, _ := token.NewService([]byte("0123456789abcdef0123456789abcdef"), token.NewMemoryNonceStore())
	server := New(fakeEngine{}, tokens, "key", slog.Default())
	request := httptest.NewRequest(http.MethodPost, "/v1/decision", bytes.NewBufferString(`{"session_id":"abcdefgh","action":"read","endpoint_class":"public_content","sequence":1,"observations":{},"unknown":true}`))
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", response.Code)
	}
}

func TestDecisionAcceptsClosedCrawlerIdentityTuple(t *testing.T) {
	tokens, _ := token.NewService([]byte("0123456789abcdef0123456789abcdef"), token.NewMemoryNonceStore())
	engine := &recordingEngine{}
	server := New(engine, tokens, "key", slog.Default())
	request := httptest.NewRequest(http.MethodPost, "/v1/decision", bytes.NewBufferString(`{"session_id":"abcdefgh","action":"read","endpoint_class":"public_content","sequence":1,"observations":{"verified_bot":true,"crawler_class":"search_indexer","crawler_verification":"ip_ua_registry"}}`))
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("decision status=%d body=%s", response.Code, response.Body.String())
	}
	if !engine.request.Observations.VerifiedBot || engine.request.Observations.CrawlerClass != core.CrawlerClassSearchIndexer ||
		engine.request.Observations.CrawlerVerification != core.CrawlerVerificationIPUARegistry {
		t.Fatalf("crawler tuple=%+v", engine.request.Observations)
	}
}

func TestServerIssuedSessionCookieBindsDecisionContinuity(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	tokens, _ := token.NewService(secret, token.NewMemoryNonceStore())
	cookies, err := sessioncookie.New(secret, sessioncookie.DefaultTTL)
	if err != nil {
		t.Fatal(err)
	}
	engine := &recordingEngine{}
	server := New(engine, tokens, "key", slog.Default()).WithSessionCookies(cookies, true)

	unauthorized := httptest.NewRequest(http.MethodPost, "/v1/session", nil)
	unauthorizedResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(unauthorizedResponse, unauthorized)
	if unauthorizedResponse.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized session issuance status = %d", unauthorizedResponse.Code)
	}
	withBody := httptest.NewRequest(http.MethodPost, "/v1/session", bytes.NewBufferString(`{}`))
	withBody.Header.Set("Authorization", "Bearer key")
	withBodyResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(withBodyResponse, withBody)
	if withBodyResponse.Code != http.StatusBadRequest {
		t.Fatalf("session issuance accepted a body: %d", withBodyResponse.Code)
	}

	issue := httptest.NewRequest(http.MethodPost, "/v1/session", nil)
	issue.Header.Set("Authorization", "Bearer key")
	issueResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(issueResponse, issue)
	if issueResponse.Code != http.StatusCreated {
		t.Fatalf("session issuance status = %d: %s", issueResponse.Code, issueResponse.Body.String())
	}
	issuedCookies := issueResponse.Result().Cookies()
	if len(issuedCookies) != 1 || issuedCookies[0].Name != sessioncookie.CookieName || !issuedCookies[0].Secure || !issuedCookies[0].HttpOnly {
		t.Fatalf("unsafe issued cookies: %+v", issuedCookies)
	}
	var issued struct {
		SessionID string `json:"session_id"`
	}
	if err := json.Unmarshal(issueResponse.Body.Bytes(), &issued); err != nil {
		t.Fatal(err)
	}
	decision := httptest.NewRequest(http.MethodPost, "/v1/decision", bytes.NewBufferString(`{"session_id":"`+issued.SessionID+`","action":"read","endpoint_class":"public_content","sequence":1,"observations":{}}`))
	decision.AddCookie(issuedCookies[0])
	decisionResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(decisionResponse, decision)
	if decisionResponse.Code != http.StatusOK || !engine.request.Observations.ServerSessionVerified {
		t.Fatalf("verified session was not attached: status=%d request=%+v", decisionResponse.Code, engine.request)
	}

	mismatch := httptest.NewRequest(http.MethodPost, "/v1/decision", bytes.NewBufferString(`{"session_id":"different-session-id","action":"read","endpoint_class":"public_content","sequence":1,"observations":{}}`))
	mismatch.AddCookie(issuedCookies[0])
	mismatchResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(mismatchResponse, mismatch)
	if mismatchResponse.Code != http.StatusUnauthorized {
		t.Fatalf("cookie/session mismatch status = %d", mismatchResponse.Code)
	}

	missing := httptest.NewRequest(http.MethodPost, "/v1/decision", bytes.NewBufferString(`{"session_id":"missing-cookie-session","action":"read","endpoint_class":"public_content","sequence":1,"observations":{}}`))
	missingResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(missingResponse, missing)
	if missingResponse.Code != http.StatusUnauthorized {
		t.Fatalf("required cookie missing status = %d", missingResponse.Code)
	}
}

func TestSignedCookieCanResolveSessionForTokenAndDecision(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	tokens, _ := token.NewService(secret, token.NewMemoryNonceStore())
	cookies, err := sessioncookie.New(secret, sessioncookie.DefaultTTL)
	if err != nil {
		t.Fatal(err)
	}
	issuedCookie, claims, err := cookies.Issue(time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	engine := &recordingEngine{}
	server := New(engine, tokens, "key", slog.Default()).WithSessionCookies(cookies, true)

	issueProof := httptest.NewRequest(http.MethodPost, "/v1/token", bytes.NewBufferString(`{"action":"read","ttl_seconds":60}`))
	issueProof.Header.Set("Authorization", "Bearer key")
	issueProof.AddCookie(&issuedCookie)
	proofResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(proofResponse, issueProof)
	var proof struct {
		Token string `json:"proof_token"`
	}
	if proofResponse.Code != http.StatusCreated || json.Unmarshal(proofResponse.Body.Bytes(), &proof) != nil || proof.Token == "" {
		t.Fatalf("cookie-derived proof = %d %s", proofResponse.Code, proofResponse.Body.String())
	}
	if _, err := tokens.VerifyAndConsume(proof.Token, claims.SessionID, "read", time.Now().UTC()); err != nil {
		t.Fatalf("proof was not bound to cookie session: %v", err)
	}

	decision := httptest.NewRequest(http.MethodPost, "/v1/decision", bytes.NewBufferString(`{"action":"read","endpoint_class":"public_content","sequence":1,"observations":{}}`))
	decision.AddCookie(&issuedCookie)
	decisionResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(decisionResponse, decision)
	if decisionResponse.Code != http.StatusOK || engine.request.SessionID != claims.SessionID || !engine.request.Observations.ServerSessionVerified {
		t.Fatalf("cookie-derived decision = %d request=%+v", decisionResponse.Code, engine.request)
	}

	missing := New(engine, tokens, "key", slog.Default()).WithSessionCookies(cookies, false)
	missingRequest := httptest.NewRequest(http.MethodPost, "/v1/decision", bytes.NewBufferString(`{"action":"read","endpoint_class":"public_content","sequence":1,"observations":{}}`))
	missingResponse := httptest.NewRecorder()
	missing.Handler().ServeHTTP(missingResponse, missingRequest)
	if missingResponse.Code != http.StatusUnauthorized {
		t.Fatalf("empty session without cookie = %d", missingResponse.Code)
	}
}

func TestClientCannotClaimInternalTrustMarkers(t *testing.T) {
	tokens, _ := token.NewService([]byte("0123456789abcdef0123456789abcdef"), token.NewMemoryNonceStore())
	server := New(fakeEngine{}, tokens, "key", slog.Default())
	for _, field := range []string{"server_session_verified", "browser_events_verified"} {
		t.Run(field, func(t *testing.T) {
			body := fmt.Sprintf(`{"session_id":"abcdefgh","action":"read","endpoint_class":"public_content","sequence":1,"observations":{"%s":true}}`, field)
			request := httptest.NewRequest(http.MethodPost, "/v1/decision", bytes.NewBufferString(body))
			response := httptest.NewRecorder()
			server.Handler().ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("client-supplied trust marker = %d", response.Code)
			}
		})
	}
}

func TestEventProofIsOneTimeAndFeedsDecision(t *testing.T) {
	tokens, _ := token.NewService([]byte("0123456789abcdef0123456789abcdef"), token.NewMemoryNonceStore())
	engine := &recordingEngine{}
	server := New(engine, tokens, "key", slog.Default()).WithEventStore(events.NewStore(time.Minute)).RequireEventProof(true)
	proof, err := tokens.Issue("session-12345678", "events", time.Minute, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	batch := `{"sessionId":"session-12345678","sensorVersion":"0.1.0","events":[{"sequence":1,"elapsedBucketMs":25,"kind":"navigation","valueBucket":1}]}`
	wrongProof, err := tokens.Issue("session-12345678", "read", time.Minute, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	wrong := httptest.NewRequest(http.MethodPost, "/v1/events", bytes.NewBufferString(batch))
	wrong.Header.Set("X-Palisade-Proof", wrongProof)
	wrongResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(wrongResponse, wrong)
	if wrongResponse.Code != http.StatusUnauthorized {
		t.Fatalf("read proof accepted for events: %d", wrongResponse.Code)
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/events", bytes.NewBufferString(batch))
	request.Header.Set("X-Palisade-Proof", proof)
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d", response.Code)
	}

	replay := httptest.NewRequest(http.MethodPost, "/v1/events", bytes.NewBufferString(batch))
	replay.Header.Set("X-Palisade-Proof", proof)
	replayResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(replayResponse, replay)
	if replayResponse.Code != http.StatusUnauthorized {
		t.Fatalf("expected replay rejection, got %d", replayResponse.Code)
	}

	decision := httptest.NewRequest(http.MethodPost, "/v1/decision", bytes.NewBufferString(`{"session_id":"session-12345678","action":"read","endpoint_class":"public_content","sequence":1,"observations":{"browser_event_count":9999}}`))
	decisionResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(decisionResponse, decision)
	if decisionResponse.Code != http.StatusOK || engine.request.Observations.BrowserEventCount != 1 || !engine.request.Observations.BrowserEventsVerified {
		t.Fatalf("server event count was not authoritative: status=%d observations=%+v", decisionResponse.Code, engine.request.Observations)
	}
}

func TestAcceptedEventBatchRecordsServerClassifiedShadowDecision(t *testing.T) {
	now := time.Now().UTC()
	secret := []byte("0123456789abcdef0123456789abcdef")
	tokens, _ := token.NewService(secret, token.NewMemoryNonceStore())
	cookies, err := sessioncookie.New(secret, sessioncookie.DefaultTTL)
	if err != nil {
		t.Fatal(err)
	}
	issuedCookie, claims, err := cookies.Issue(now)
	if err != nil {
		t.Fatal(err)
	}
	profile, err := NewEventShadowProfile("read", "public_content")
	if err != nil {
		t.Fatal(err)
	}
	engine := &capturingEngine{decision: core.Decision{
		DecisionID: "event-shadow-decision", Action: core.ActionBlock, ComputedAction: core.ActionBlock,
		Mode: core.RuntimeModeEnforce, RolloutID: "must-not-survive", ReasonCodes: []string{"HIGH_RISK"},
	}}
	recorder := &recordingShadow{}
	server := New(engine, tokens, "key", slog.Default()).
		WithEventStore(events.NewStore(time.Minute)).
		RequireEventProof(true).
		WithSessionCookies(cookies, true).
		WithShadowRecorder(recorder).
		WithEventShadowEvaluation(profile)
	eventProof, err := tokens.Issue(claims.SessionID, "events", time.Minute, now)
	if err != nil {
		t.Fatal(err)
	}
	batch := `{"sensorVersion":"0.2.0","events":[{"sequence":7,"elapsedBucketMs":25,"kind":"navigation","valueBucket":1}]}`
	request := httptest.NewRequest(http.MethodPost, "/v1/events", bytes.NewBufferString(batch))
	request.Header.Set("User-Agent", "synthetic-browser")
	request.Header.Set("X-Palisade-Proof", eventProof)
	request.AddCookie(&issuedCookie)
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusAccepted || response.Header().Get("X-Palisade-Shadow-Evaluation") != "recorded" {
		t.Fatalf("event shadow response = %d headers=%v body=%s", response.Code, response.Header(), response.Body.String())
	}
	if engine.request.SessionID != claims.SessionID || engine.request.Action != "read" || engine.request.EndpointClass != "public_content" ||
		engine.request.Sequence != 1 || engine.request.ProofToken == "" || !engine.request.Observations.ServerSessionVerified ||
		!engine.request.Observations.UserAgentPresent || engine.request.Observations.BrowserEventCount != 1 || !engine.request.Observations.BrowserEventsVerified {
		t.Fatalf("internal event decision request = %+v", engine.request)
	}
	if _, err := tokens.VerifyAndConsume(engine.request.ProofToken, claims.SessionID, "read", time.Now().UTC()); err != nil {
		t.Fatalf("internal event decision proof was not action-bound: %v", err)
	}
	if recorder.decisions != 1 || len(recorder.decisionRequests) != 1 || recorder.decisionRequests[0].ProofToken != "" {
		t.Fatalf("recorded requests = %+v", recorder.decisionRequests)
	}
	decision := recorder.decisionValues[0]
	if decision.Action != core.ActionObserve || decision.ComputedAction != core.ActionBlock || decision.Mode != core.RuntimeModeShadow ||
		decision.RolloutID != "" || decision.Directive.Handling != "pass" || !strings.Contains(strings.Join(decision.ReasonCodes, ","), core.ReasonShadowActionOverridden) {
		t.Fatalf("recorded event shadow decision = %+v", decision)
	}
}

func TestBackendIssuedEventContextClassifiesDynamicShadowDecision(t *testing.T) {
	now := time.Now().UTC()
	secret := []byte("0123456789abcdef0123456789abcdef")
	tokens, _ := token.NewService(secret, token.NewMemoryNonceStore())
	cookies, err := sessioncookie.New(secret, sessioncookie.DefaultTTL)
	if err != nil {
		t.Fatal(err)
	}
	issuedCookie, claims, err := cookies.Issue(now)
	if err != nil {
		t.Fatal(err)
	}
	engine := &capturingEngine{decision: core.Decision{
		DecisionID: "dynamic-event-shadow", Action: core.ActionAllow, ComputedAction: core.ActionAllow, Mode: core.RuntimeModeShadow,
	}}
	recorder := &recordingShadow{}
	server := New(engine, tokens, "key", slog.Default()).
		WithEventStore(events.NewStore(time.Minute)).
		RequireEventProof(true).
		WithSessionCookies(cookies, true).
		WithShadowRecorder(recorder).
		WithEventShadowEvaluation(NewEventShadowProofProfile())

	issue := httptest.NewRequest(http.MethodPost, "/v1/token", bytes.NewBufferString(`{"action":"events","request_action":"compare","endpoint_class":"compare_noindex","ttl_seconds":60}`))
	issue.Header.Set("Authorization", "Bearer key")
	issue.AddCookie(&issuedCookie)
	issueResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(issueResponse, issue)
	var proof struct {
		Token string `json:"proof_token"`
	}
	if issueResponse.Code != http.StatusCreated || json.Unmarshal(issueResponse.Body.Bytes(), &proof) != nil || proof.Token == "" {
		t.Fatalf("dynamic event proof = %d %s", issueResponse.Code, issueResponse.Body.String())
	}

	batch := `{"sensorVersion":"0.2.0","events":[{"sequence":1,"elapsedBucketMs":25,"kind":"navigation","valueBucket":1}]}`
	request := httptest.NewRequest(http.MethodPost, "/v1/events", bytes.NewBufferString(batch))
	request.Header.Set("X-Palisade-Proof", proof.Token)
	request.AddCookie(&issuedCookie)
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusAccepted || response.Header().Get("X-Palisade-Shadow-Evaluation") != "recorded" {
		t.Fatalf("dynamic event response = %d headers=%v body=%s", response.Code, response.Header(), response.Body.String())
	}
	if engine.request.SessionID != claims.SessionID || engine.request.Action != "compare" || engine.request.EndpointClass != "compare_noindex" || recorder.decisions != 1 {
		t.Fatalf("dynamic event classification request=%+v decisions=%d", engine.request, recorder.decisions)
	}
	collection := server.collectionSummary()
	if collection.ContextProofsIssued != 1 || collection.AcceptedEventBatches != 1 || collection.RecordedShadowDecisions != 1 ||
		collection.RejectedBeforeIngest != 0 || collection.DroppedAfterIngest != 0 || collection.BatchRecordingRate != 1 ||
		len(collection.EndpointContextProofs) != 1 || collection.EndpointContextProofs[0].EndpointClass != "compare_noindex" {
		t.Fatalf("dynamic event collection = %+v", collection)
	}
}

func TestDynamicEventContextFailsClosedWithoutTrustedClassification(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	tokens, _ := token.NewService(secret, token.NewMemoryNonceStore())
	cookies, _ := sessioncookie.New(secret, sessioncookie.DefaultTTL)
	issuedCookie, claims, _ := cookies.Issue(time.Now().UTC())
	engine := &capturingEngine{decision: core.Decision{DecisionID: "must-not-run", Action: core.ActionAllow, ComputedAction: core.ActionAllow, Mode: core.RuntimeModeShadow}}
	server := New(engine, tokens, "key", slog.Default()).
		WithEventStore(events.NewStore(time.Minute)).
		RequireEventProof(true).
		WithSessionCookies(cookies, true).
		WithShadowRecorder(&recordingShadow{}).
		WithEventShadowEvaluation(NewEventShadowProofProfile())

	for _, body := range []string{
		`{"action":"events","request_action":"read","ttl_seconds":60}`,
		`{"action":"events","request_action":"read","endpoint_class":"/raw/path","ttl_seconds":60}`,
		`{"action":"read","request_action":"read","endpoint_class":"public_content","ttl_seconds":60}`,
	} {
		request := httptest.NewRequest(http.MethodPost, "/v1/token", bytes.NewBufferString(body))
		request.Header.Set("Authorization", "Bearer key")
		request.AddCookie(&issuedCookie)
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("invalid context %s status = %d", body, response.Code)
		}
	}

	plainProof, err := tokens.Issue(claims.SessionID, "events", time.Minute, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	batch := `{"sensorVersion":"0.2.0","events":[{"sequence":1,"elapsedBucketMs":25,"kind":"navigation","valueBucket":1}]}`
	request := httptest.NewRequest(http.MethodPost, "/v1/events", bytes.NewBufferString(batch))
	request.Header.Set("X-Palisade-Proof", plainProof)
	request.AddCookie(&issuedCookie)
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized || len(engine.requests) != 0 {
		t.Fatalf("unclassified event response=%d headers=%v requests=%d", response.Code, response.Header(), len(engine.requests))
	}
	if collection := server.collectionSummary(); collection.RejectedBeforeIngest != 1 || collection.AcceptedEventBatches != 0 {
		t.Fatalf("unclassified event collection = %+v", collection)
	}

	clientContext := httptest.NewRequest(http.MethodPost, "/v1/events", bytes.NewBufferString(`{"sensorVersion":"0.2.0","request_action":"read","endpoint_class":"public_content","events":[{"sequence":2,"elapsedBucketMs":50,"kind":"navigation","valueBucket":1}]}`))
	clientContextResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(clientContextResponse, clientContext)
	if clientContextResponse.Code != http.StatusBadRequest {
		t.Fatalf("client event context status = %d", clientContextResponse.Code)
	}
}

func TestStaticEventShadowRejectsContextBearingProofBeforeIngest(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	tokens, _ := token.NewService(secret, token.NewMemoryNonceStore())
	profile, err := NewEventShadowProfile("read", "public_content")
	if err != nil {
		t.Fatal(err)
	}
	store := events.NewStore(time.Minute)
	engine := &capturingEngine{decision: core.Decision{DecisionID: "must-not-run", Action: core.ActionAllow, ComputedAction: core.ActionAllow, Mode: core.RuntimeModeShadow}}
	server := New(engine, tokens, "key", slog.Default()).
		WithEventStore(store).
		RequireEventProof(true).
		WithShadowRecorder(&recordingShadow{}).
		WithEventShadowEvaluation(profile)
	proof, err := tokens.IssueEventContext("session-12345678", "compare", "compare_noindex", time.Minute, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	batch := `{"sessionId":"session-12345678","sensorVersion":"0.2.0","events":[{"sequence":1,"elapsedBucketMs":25,"kind":"navigation","valueBucket":1}]}`
	request := httptest.NewRequest(http.MethodPost, "/v1/events", bytes.NewBufferString(batch))
	request.Header.Set("X-Palisade-Proof", proof)
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized || store.Count("session-12345678", time.Now().UTC()) != 0 || len(engine.requests) != 0 {
		t.Fatalf("cross-mode context status=%d events=%d requests=%d", response.Code, store.Count("session-12345678", time.Now().UTC()), len(engine.requests))
	}
	if collection := server.collectionSummary(); collection.RejectedBeforeIngest != 1 || collection.AcceptedEventBatches != 0 {
		t.Fatalf("cross-mode collection = %+v", collection)
	}
}

func TestEventShadowUsesBatchSequenceNotBrowserEventSequence(t *testing.T) {
	now := time.Now().UTC()
	secret := []byte("0123456789abcdef0123456789abcdef")
	tokens, _ := token.NewService(secret, token.NewMemoryNonceStore())
	cookies, err := sessioncookie.New(secret, sessioncookie.DefaultTTL)
	if err != nil {
		t.Fatal(err)
	}
	issuedCookie, claims, err := cookies.Issue(now)
	if err != nil {
		t.Fatal(err)
	}
	profile, err := NewEventShadowProfile("read", "public_content")
	if err != nil {
		t.Fatal(err)
	}
	engine := &capturingEngine{decision: core.Decision{
		DecisionID: "event-shadow-decision", Action: core.ActionAllow, ComputedAction: core.ActionAllow, Mode: core.RuntimeModeShadow,
	}}
	server := New(engine, tokens, "key", slog.Default()).
		WithEventStore(events.NewStore(5*time.Minute)).
		RequireEventProof(true).
		WithSessionCookies(cookies, true).
		WithShadowRecorder(&recordingShadow{}).
		WithEventShadowEvaluation(profile)

	for index, body := range []string{
		`{"sensorVersion":"0.2.0","events":[{"sequence":1,"elapsedBucketMs":25,"kind":"navigation","valueBucket":1}]}`,
		`{"sensorVersion":"0.2.0","events":[{"sequence":64,"elapsedBucketMs":15000,"kind":"pointer","valueBucket":16}]}`,
	} {
		proof, proofErr := tokens.Issue(claims.SessionID, "events", time.Minute, now)
		if proofErr != nil {
			t.Fatal(proofErr)
		}
		request := httptest.NewRequest(http.MethodPost, "/v1/events", bytes.NewBufferString(body))
		request.Header.Set("X-Palisade-Proof", proof)
		request.AddCookie(&issuedCookie)
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusAccepted {
			t.Fatalf("batch %d status = %d: %s", index+1, response.Code, response.Body.String())
		}
	}
	if len(engine.requests) != 2 || engine.requests[0].Sequence != 1 || engine.requests[1].Sequence != 2 {
		t.Fatalf("event shadow decision sequences = %+v, want contiguous 1,2", engine.requests)
	}
	if engine.requests[1].Observations.BrowserEventCount != 2 {
		t.Fatalf("second event count = %d, want 2", engine.requests[1].Observations.BrowserEventCount)
	}
}

func TestAcceptedEventsRemainAcceptedWhenShadowRecordDrops(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	tokens, _ := token.NewService(secret, token.NewMemoryNonceStore())
	profile, err := NewEventShadowProfile("read", "public_content")
	if err != nil {
		t.Fatal(err)
	}
	recorder := &recordingShadow{decisionErr: errors.New("synthetic recorder failure")}
	server := New(contractEngine{}, tokens, "key", slog.Default()).
		WithEventStore(events.NewStore(time.Minute)).
		WithShadowRecorder(recorder).
		WithEventShadowEvaluation(profile)
	batch := `{"sessionId":"session-12345678","sensorVersion":"0.2.0","events":[{"sequence":1,"elapsedBucketMs":25,"kind":"navigation","valueBucket":1}]}`
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/v1/events", bytes.NewBufferString(batch)))
	if response.Code != http.StatusAccepted || response.Header().Get("X-Palisade-Shadow-Evaluation") != "dropped" || recorder.decisions != 1 {
		t.Fatalf("accepted event/drop response = %d headers=%v decisions=%d", response.Code, response.Header(), recorder.decisions)
	}
}

func TestDecisionJSONDistinguishesEnforcedAndComputedActions(t *testing.T) {
	tokens, _ := token.NewService([]byte("0123456789abcdef0123456789abcdef"), token.NewMemoryNonceStore())
	server := New(contractEngine{}, tokens, "key", slog.Default())
	request := httptest.NewRequest(http.MethodPost, "/v1/decision", bytes.NewBufferString(`{"session_id":"abcdefgh","action":"read","endpoint_class":"public_content","sequence":1,"observations":{}}`))
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["action"] != "observe" || body["computed_action"] != "block" || body["mode"] != "shadow" {
		t.Fatalf("unexpected decision contract: %v", body)
	}
}

func TestOriginCheckAppliesOnlyValidatedDirectiveStatus(t *testing.T) {
	now := time.Now().UTC().Add(5 * time.Minute)
	tests := []struct {
		name      string
		action    core.Action
		directive core.EnforcementDirective
		status    int
		retry     string
	}{
		{name: "shadow pass", action: core.ActionObserve, directive: core.EnforcementDirective{Handling: "pass", HTTPStatus: 200, ExpiresAt: now}, status: http.StatusNoContent},
		{name: "delay", action: core.ActionDelay, directive: core.EnforcementDirective{Handling: "delay", HTTPStatus: 429, RetryAfterSeconds: 1, ExpiresAt: now}, status: http.StatusTooManyRequests, retry: "1"},
		{name: "throttle", action: core.ActionThrottle, directive: core.EnforcementDirective{Handling: "throttle", HTTPStatus: 429, RetryAfterSeconds: 5, ExpiresAt: now}, status: http.StatusTooManyRequests, retry: "5"},
		{name: "challenge", action: core.ActionChallenge, directive: core.EnforcementDirective{Handling: "challenge", HTTPStatus: 403, ExpiresAt: now}, status: http.StatusForbidden},
		{name: "block", action: core.ActionBlock, directive: core.EnforcementDirective{Handling: "block", HTTPStatus: 403, RetryAfterSeconds: 300, ExpiresAt: now}, status: http.StatusForbidden, retry: "300"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			secret := []byte("0123456789abcdef0123456789abcdef")
			tokens, _ := token.NewService(secret, token.NewMemoryNonceStore())
			cookies, _ := sessioncookie.New(secret, sessioncookie.DefaultTTL)
			issuedCookie, claims, err := cookies.Issue(time.Now().UTC())
			if err != nil {
				t.Fatal(err)
			}
			challengeService, err := challenge.New(challenge.Config{Secret: secret, Delay: time.Nanosecond})
			if err != nil {
				t.Fatal(err)
			}
			decision := core.Decision{
				DecisionID: "origin-decision", Action: test.action, ComputedAction: test.action, Mode: core.RuntimeModeCanary,
				RolloutID: "canary-20260827", Directive: test.directive, ExpiresAt: now,
			}
			server := New(fixedEngine{decision: decision}, tokens, "key", slog.Default()).WithSessionCookies(cookies, true).WithChallenges(challengeService)
			request := httptest.NewRequest(http.MethodPost, "/v1/origin-check", bytes.NewBufferString(`{"session_id":"`+claims.SessionID+`","action":"read","endpoint_class":"public_content","sequence":1,"observations":{}}`))
			request.AddCookie(&issuedCookie)
			response := httptest.NewRecorder()
			server.Handler().ServeHTTP(response, request)
			if response.Code != test.status || response.Body.Len() != 0 {
				t.Fatalf("status/body = %d/%q, want %d/empty", response.Code, response.Body.String(), test.status)
			}
			if response.Header().Get("X-Palisade-Action") != string(test.action) || response.Header().Get("X-Palisade-Handling") != test.directive.Handling ||
				response.Header().Get("X-Palisade-Mode") != "canary" || response.Header().Get("X-Palisade-Rollout-ID") != "canary-20260827" || response.Header().Get("Retry-After") != test.retry {
				t.Fatalf("unexpected origin headers: %v", response.Header())
			}
			if test.action == core.ActionChallenge && (response.Header().Get("X-Palisade-Challenge-ID") == "" || response.Header().Get("Location") == "") {
				t.Fatalf("challenge reference missing: %v", response.Header())
			}
		})
	}
}

func TestNativeChallengeHTTPFlowRecordsOutcomeAndRejectsReplay(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	tokens, _ := token.NewService(secret, token.NewMemoryNonceStore())
	cookies, err := sessioncookie.New(secret, sessioncookie.DefaultTTL)
	if err != nil {
		t.Fatal(err)
	}
	issuedCookie, claims, err := cookies.Issue(time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	challengeService, err := challenge.New(challenge.Config{Secret: secret, Delay: time.Nanosecond})
	if err != nil {
		t.Fatal(err)
	}
	recorder := &recordingShadow{}
	decision := core.Decision{
		DecisionID: "native-challenge", Action: core.ActionChallenge, ComputedAction: core.ActionChallenge,
		Mode: core.RuntimeModeCanary, RolloutID: "canary-native", ExpiresAt: time.Now().UTC().Add(30 * time.Second),
		Directive: core.EnforcementDirective{Handling: "challenge", HTTPStatus: http.StatusForbidden, ExpiresAt: time.Now().UTC().Add(5 * time.Minute)},
	}
	server := New(fixedEngine{decision: decision}, tokens, "key", slog.Default()).
		WithSessionCookies(cookies, true).
		WithShadowRecorder(recorder).
		WithChallenges(challengeService)
	handler := server.Handler()

	origin := httptest.NewRequest(http.MethodPost, "/v1/origin-check", bytes.NewBufferString(`{"session_id":"`+claims.SessionID+`","action":"read","endpoint_class":"public_content","sequence":1,"observations":{}}`))
	origin.AddCookie(&issuedCookie)
	originResponse := httptest.NewRecorder()
	handler.ServeHTTP(originResponse, origin)
	challengeID := originResponse.Header().Get("X-Palisade-Challenge-ID")
	if originResponse.Code != http.StatusForbidden || challengeID == "" || originResponse.Header().Get("Location") != "/v1/challenge/"+challengeID {
		t.Fatalf("origin challenge = %d %v", originResponse.Code, originResponse.Header())
	}
	otherCookie, _, err := cookies.Issue(time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	wrongSessionView := httptest.NewRequest(http.MethodGet, "/v1/challenge/"+challengeID, nil)
	wrongSessionView.AddCookie(&otherCookie)
	wrongSessionResponse := httptest.NewRecorder()
	handler.ServeHTTP(wrongSessionResponse, wrongSessionView)
	if wrongSessionResponse.Code != http.StatusNotFound {
		t.Fatalf("cross-session challenge disclosure = %d", wrongSessionResponse.Code)
	}

	view := httptest.NewRequest(http.MethodGet, "/v1/challenge/"+challengeID, nil)
	view.AddCookie(&issuedCookie)
	viewResponse := httptest.NewRecorder()
	handler.ServeHTTP(viewResponse, view)
	var metadata challenge.Metadata
	if viewResponse.Code != http.StatusOK || json.Unmarshal(viewResponse.Body.Bytes(), &metadata) != nil || metadata.VerificationToken == "" {
		t.Fatalf("challenge metadata = %d %s", viewResponse.Code, viewResponse.Body.String())
	}
	if wait := time.Until(metadata.ReadyAt); wait > 0 {
		time.Sleep(wait + time.Millisecond)
	}

	verifyBody, _ := json.Marshal(map[string]string{"challenge_id": challengeID, "verification_token": metadata.VerificationToken})
	verify := httptest.NewRequest(http.MethodPost, "/v1/challenge/verify", bytes.NewReader(verifyBody))
	verify.AddCookie(&issuedCookie)
	verifyResponse := httptest.NewRecorder()
	handler.ServeHTTP(verifyResponse, verify)
	var verification challenge.Verification
	if verifyResponse.Code != http.StatusOK || json.Unmarshal(verifyResponse.Body.Bytes(), &verification) != nil || verification.RedemptionToken == "" {
		t.Fatalf("challenge verification = %d %s", verifyResponse.Code, verifyResponse.Body.String())
	}

	redeemBody, _ := json.Marshal(map[string]string{
		"challenge_id": challengeID, "redemption_token": verification.RedemptionToken, "action": "read", "endpoint_class": "public_content",
	})
	redeem := httptest.NewRequest(http.MethodPost, "/v1/challenge/redeem", bytes.NewReader(redeemBody))
	redeem.AddCookie(&issuedCookie)
	redeemResponse := httptest.NewRecorder()
	handler.ServeHTTP(redeemResponse, redeem)
	if redeemResponse.Code != http.StatusNoContent || redeemResponse.Header().Get("X-Palisade-Challenge") != "redeemed" {
		t.Fatalf("challenge redemption = %d %s", redeemResponse.Code, redeemResponse.Body.String())
	}
	if len(recorder.outcomes) != 1 || recorder.outcomes[0].Outcome != "challenge_passed" || recorder.outcomes[0].DecisionID != "native-challenge" || recorder.outcomes[0].Provenance != "server_observed" {
		t.Fatalf("recorded outcomes = %+v", recorder.outcomes)
	}

	replay := httptest.NewRequest(http.MethodPost, "/v1/challenge/redeem", bytes.NewReader(redeemBody))
	replay.AddCookie(&issuedCookie)
	replayResponse := httptest.NewRecorder()
	handler.ServeHTTP(replayResponse, replay)
	if replayResponse.Code != http.StatusConflict || len(recorder.outcomes) != 1 {
		t.Fatalf("redemption replay = %d outcomes=%+v", replayResponse.Code, recorder.outcomes)
	}
}

func TestFailedChallengeIssuanceIsNotRecordedAsApplied(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	tokens, _ := token.NewService(secret, token.NewMemoryNonceStore())
	cookies, err := sessioncookie.New(secret, sessioncookie.DefaultTTL)
	if err != nil {
		t.Fatal(err)
	}
	issuedCookie, claims, err := cookies.Issue(time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	challengeService, err := challenge.New(challenge.Config{Secret: secret, MaxEntries: 1})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	directive := core.EnforcementDirective{Handling: "challenge", HTTPStatus: http.StatusForbidden, ExpiresAt: now.Add(5 * time.Minute)}
	if _, err := challengeService.Issue(core.DecisionRequest{
		SessionID: claims.SessionID, Action: "read", EndpointClass: "public_content", Sequence: 1,
		Observations: core.Observations{ServerSessionVerified: true},
	}, core.Decision{
		DecisionID: "capacity-holder", Action: core.ActionChallenge, Mode: core.RuntimeModeCanary,
		RolloutID: "canary-capacity", Directive: directive,
	}, now); err != nil {
		t.Fatal(err)
	}
	recorder := &recordingShadow{}
	decision := core.Decision{
		DecisionID: "capacity-rejected", Action: core.ActionChallenge, ComputedAction: core.ActionChallenge,
		Mode: core.RuntimeModeCanary, RolloutID: "canary-capacity", Directive: directive, ExpiresAt: now.Add(30 * time.Second),
	}
	server := New(fixedEngine{decision: decision}, tokens, "key", slog.Default()).
		WithSessionCookies(cookies, true).
		WithShadowRecorder(recorder).
		WithChallenges(challengeService)
	request := httptest.NewRequest(http.MethodPost, "/v1/origin-check", bytes.NewBufferString(`{"session_id":"`+claims.SessionID+`","action":"read","endpoint_class":"public_content","sequence":2,"observations":{}}`))
	request.AddCookie(&issuedCookie)
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable || recorder.decisions != 0 {
		t.Fatalf("failed issuance status/recorded = %d/%d", response.Code, recorder.decisions)
	}
}

func TestOriginCheckRejectsInconsistentDirective(t *testing.T) {
	tokens, _ := token.NewService([]byte("0123456789abcdef0123456789abcdef"), token.NewMemoryNonceStore())
	decision := core.Decision{
		DecisionID: "invalid-directive", Action: core.ActionBlock, ComputedAction: core.ActionBlock, Mode: core.RuntimeModeEnforce,
		Directive: core.EnforcementDirective{Handling: "pass", HTTPStatus: 200, ExpiresAt: time.Now().Add(time.Minute)},
	}
	server := New(fixedEngine{decision: decision}, tokens, "key", slog.Default())
	request := httptest.NewRequest(http.MethodPost, "/v1/origin-check", bytes.NewBufferString(`{"session_id":"session-12345678","action":"read","endpoint_class":"public_content","sequence":1,"observations":{}}`))
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), "invalid_enforcement_directive") {
		t.Fatalf("unexpected invalid-directive response: %d %s", response.Code, response.Body.String())
	}
}

func TestOriginStatusRejectsMalformedDelay(t *testing.T) {
	now := time.Now().UTC()
	base := core.Decision{
		DecisionID: "delay-contract", Action: core.ActionDelay, ComputedAction: core.ActionDelay,
		Mode: core.RuntimeModeCanary, RolloutID: "delay-canary",
	}
	for _, directive := range []core.EnforcementDirective{
		{Handling: "delay", HTTPStatus: 429, RetryAfterSeconds: 2, ExpiresAt: now.Add(time.Minute)},
		{Handling: "throttle", HTTPStatus: 429, RetryAfterSeconds: 1, ExpiresAt: now.Add(time.Minute)},
		{Handling: "delay", HTTPStatus: 200, RetryAfterSeconds: 1, ExpiresAt: now.Add(time.Minute)},
	} {
		decision := base
		decision.Directive = directive
		if status, ok := originStatus(decision, now); ok {
			t.Fatalf("malformed delay accepted: status=%d directive=%+v", status, directive)
		}
	}
}

func TestDecisionAndOutcomeReachShadowRecorder(t *testing.T) {
	tokens, _ := token.NewService([]byte("0123456789abcdef0123456789abcdef"), token.NewMemoryNonceStore())
	recorder := &recordingShadow{}
	server := New(contractEngine{}, tokens, "key", slog.Default()).WithShadowRecorder(recorder)
	decision := httptest.NewRequest(http.MethodPost, "/v1/decision", bytes.NewBufferString(`{"session_id":"session-12345678","action":"read","endpoint_class":"compare_noindex","sequence":1,"observations":{}}`))
	decisionResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(decisionResponse, decision)
	if decisionResponse.Code != http.StatusOK || recorder.decisions != 1 {
		t.Fatalf("decision was not recorded: status=%d records=%d", decisionResponse.Code, recorder.decisions)
	}

	outcome := httptest.NewRequest(http.MethodPost, "/v1/outcome", bytes.NewBufferString(`{"session_id":"session-12345678","decision_id":"decision-contract","endpoint_class":"compare_noindex","outcome":"challenge_passed","provenance":"server_observed","confidence":"confirmed"}`))
	outcome.Header.Set("Authorization", "Bearer key")
	outcomeResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(outcomeResponse, outcome)
	if outcomeResponse.Code != http.StatusAccepted || len(recorder.outcomes) != 1 || recorder.outcomes[0].Outcome != "challenge_passed" {
		t.Fatalf("outcome was not recorded: status=%d records=%+v", outcomeResponse.Code, recorder.outcomes)
	}

	invalid := httptest.NewRequest(http.MethodPost, "/v1/outcome", bytes.NewBufferString(`{"session_id":"session-12345678","endpoint_class":"compare_noindex","outcome":"human_likely","provenance":"unknown","confidence":"unknown"}`))
	invalid.Header.Set("Authorization", "Bearer key")
	invalidResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(invalidResponse, invalid)
	if invalidResponse.Code != http.StatusBadRequest {
		t.Fatalf("unsupported outcome status = %d", invalidResponse.Code)
	}

	unlinked := httptest.NewRequest(http.MethodPost, "/v1/outcome", bytes.NewBufferString(`{"session_id":"session-12345678","endpoint_class":"compare_noindex","outcome":"challenge_passed","provenance":"server_observed","confidence":"confirmed"}`))
	unlinked.Header.Set("Authorization", "Bearer key")
	unlinkedResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(unlinkedResponse, unlinked)
	if unlinkedResponse.Code != http.StatusBadRequest {
		t.Fatalf("unlinked outcome status = %d", unlinkedResponse.Code)
	}
	recorder.outcomeErr = errors.New("synthetic recorder failure")
	dropped := httptest.NewRequest(http.MethodPost, "/v1/outcome", bytes.NewBufferString(`{"session_id":"session-12345678","decision_id":"decision-dropped","endpoint_class":"compare_noindex","outcome":"unknown","provenance":"unknown","confidence":"unknown"}`))
	dropped.Header.Set("Authorization", "Bearer key")
	droppedResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(droppedResponse, dropped)
	if droppedResponse.Code != http.StatusServiceUnavailable {
		t.Fatalf("dropped outcome status = %d", droppedResponse.Code)
	}
	if flow := server.outcomeFlowSummary(); flow.Accepted != 1 || flow.Rejected != 2 || flow.Dropped != 1 {
		t.Fatalf("outcome flow = %+v", flow)
	}
}

func TestOutcomeDerivesSessionFromSignedCookie(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	tokens, _ := token.NewService(secret, token.NewMemoryNonceStore())
	cookies, err := sessioncookie.New(secret, sessioncookie.DefaultTTL)
	if err != nil {
		t.Fatal(err)
	}
	issuedCookie, claims, err := cookies.Issue(time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	recorder := &recordingShadow{}
	server := New(contractEngine{}, tokens, "key", slog.Default()).
		WithSessionCookies(cookies, true).
		WithShadowRecorder(recorder)
	request := httptest.NewRequest(http.MethodPost, "/v1/outcome", bytes.NewBufferString(`{"decision_id":"decision-contract","endpoint_class":"compare_noindex","outcome":"human_confirmed","provenance":"authenticated_account","confidence":"confirmed"}`))
	request.Header.Set("Authorization", "Bearer key")
	request.AddCookie(&issuedCookie)
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusAccepted || len(recorder.outcomes) != 1 || recorder.outcomes[0].SessionID != claims.SessionID {
		t.Fatalf("cookie-bound outcome status/records = %d/%+v", response.Code, recorder.outcomes)
	}
	mismatch := httptest.NewRequest(http.MethodPost, "/v1/outcome", bytes.NewBufferString(`{"session_id":"different-session","decision_id":"decision-contract","endpoint_class":"compare_noindex","outcome":"human_confirmed","provenance":"authenticated_account","confidence":"confirmed"}`))
	mismatch.Header.Set("Authorization", "Bearer key")
	mismatch.AddCookie(&issuedCookie)
	mismatchResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(mismatchResponse, mismatch)
	if mismatchResponse.Code != http.StatusUnauthorized || len(recorder.outcomes) != 1 {
		t.Fatalf("mismatched session status/records = %d/%+v", mismatchResponse.Code, recorder.outcomes)
	}
}
