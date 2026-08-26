package httpapi

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/palisade-bot-defense/palisade/internal/core"
	"github.com/palisade-bot-defense/palisade/internal/events"
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

func TestEventProofIsOneTimeAndFeedsDecision(t *testing.T) {
	tokens, _ := token.NewService([]byte("0123456789abcdef0123456789abcdef"), token.NewMemoryNonceStore())
	engine := &recordingEngine{}
	server := New(engine, tokens, "key", slog.Default()).WithEventStore(events.NewStore(time.Minute)).RequireEventProof(true)
	proof, err := tokens.Issue("session-12345678", "events", time.Minute, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	batch := `{"sessionId":"session-12345678","sensorVersion":"0.1.0","events":[{"sequence":1,"elapsedBucketMs":25,"kind":"navigation","valueBucket":1}]}`
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

	decision := httptest.NewRequest(http.MethodPost, "/v1/decision", bytes.NewBufferString(`{"session_id":"session-12345678","action":"read","endpoint_class":"public_content","sequence":1,"observations":{}}`))
	decisionResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(decisionResponse, decision)
	if decisionResponse.Code != http.StatusOK || engine.request.Observations.BrowserEventCount != 1 {
		t.Fatalf("event count was not attached to decision: status=%d count=%d", decisionResponse.Code, engine.request.Observations.BrowserEventCount)
	}
}
