package httpapi

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"runtime/debug"
	"sync/atomic"
	"time"

	"github.com/palisade-bot-defense/palisade/internal/adminui"
	"github.com/palisade-bot-defense/palisade/internal/core"
	decisionengine "github.com/palisade-bot-defense/palisade/internal/engine"
	"github.com/palisade-bot-defense/palisade/internal/events"
	"github.com/palisade-bot-defense/palisade/internal/sessioncookie"
	"github.com/palisade-bot-defense/palisade/internal/shadowlog"
	"github.com/palisade-bot-defense/palisade/internal/token"
)

const maxBodyBytes = 64 << 10

type DecisionEngine interface {
	Decide(context.Context, core.DecisionRequest) (core.Decision, error)
}

type ShadowRecorder interface {
	RecordDecision(core.DecisionRequest, core.Decision, time.Time) error
	RecordOutcome(shadowlog.OutcomeRequest, time.Time) error
}

type Server struct {
	engine            DecisionEngine
	tokens            *token.Service
	apiKey            string
	logger            *slog.Logger
	events            *events.Store
	requireEventProof bool
	sessionCookies    *sessioncookie.Service
	requireSession    bool
	shadowRecorder    ShadowRecorder
	shadowDrops       atomic.Uint64
}

func New(engine DecisionEngine, tokens *token.Service, apiKey string, logger *slog.Logger) *Server {
	return &Server{engine: engine, tokens: tokens, apiKey: apiKey, logger: logger}
}

func (s *Server) WithEventStore(store *events.Store) *Server {
	s.events = store
	return s
}

func (s *Server) RequireEventProof(required bool) *Server {
	s.requireEventProof = required
	return s
}

func (s *Server) WithSessionCookies(service *sessioncookie.Service, required bool) *Server {
	s.sessionCookies = service
	s.requireSession = required
	return s
}

func (s *Server) WithShadowRecorder(recorder ShadowRecorder) *Server {
	s.shadowRecorder = recorder
	return s
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health/live", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /health/ready", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
	})
	mux.HandleFunc("POST /v1/token", s.handleToken)
	mux.HandleFunc("POST /v1/session", s.handleSession)
	mux.HandleFunc("POST /v1/events", s.handleEvents)
	mux.HandleFunc("POST /v1/decision", s.handleDecision)
	mux.HandleFunc("POST /v1/origin-check", s.handleOriginCheck)
	mux.HandleFunc("POST /v1/outcome", s.handleOutcome)
	mux.Handle("GET /", adminui.Handler())
	return s.recover(s.securityHeaders(mux))
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	if s.events == nil {
		writeError(w, http.StatusServiceUnavailable, "event_store_unavailable")
		return
	}
	var batch events.Batch
	if err := decodeJSON(w, r, &batch); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json")
		return
	}
	if _, err := s.verifySession(r, batch.SessionID, time.Now().UTC()); err != nil {
		writeError(w, http.StatusUnauthorized, "invalid_session")
		return
	}
	if s.requireEventProof {
		proof := r.Header.Get("X-Palisade-Proof")
		if proof == "" {
			writeError(w, http.StatusUnauthorized, "event_proof_required")
			return
		}
		if _, err := s.tokens.VerifyAndConsume(proof, batch.SessionID, "events", time.Now().UTC()); err != nil {
			writeError(w, http.StatusUnauthorized, "invalid_event_proof")
			return
		}
	}
	if err := s.events.Ingest(batch, time.Now().UTC()); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_event_batch")
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	if !s.authorized(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if err := requireEmptyBody(w, r); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_session_request")
		return
	}
	if s.sessionCookies == nil {
		writeError(w, http.StatusServiceUnavailable, "session_service_unavailable")
		return
	}
	cookie, claims, err := s.sessionCookies.Issue(time.Now().UTC())
	if err != nil {
		s.logger.Error("session issuance failed", "error", err)
		writeError(w, http.StatusInternalServerError, "session_issue_failed")
		return
	}
	http.SetCookie(w, &cookie)
	writeJSON(w, http.StatusCreated, map[string]any{
		"session_id": claims.SessionID,
		"expires_at": time.Unix(claims.ExpiresAt, 0).UTC(),
	})
}

func requireEmptyBody(w http.ResponseWriter, r *http.Request) error {
	r.Body = http.MaxBytesReader(w, r.Body, 1)
	contents, err := io.ReadAll(r.Body)
	if err != nil || len(contents) != 0 {
		return errors.New("request body must be empty")
	}
	return nil
}

func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	if !s.authorized(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	var request struct {
		SessionID  string `json:"session_id"`
		Action     string `json:"action"`
		TTLSeconds int    `json:"ttl_seconds"`
	}
	if err := decodeJSON(w, r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json")
		return
	}
	if request.TTLSeconds == 0 {
		request.TTLSeconds = 60
	}
	if request.TTLSeconds < 1 || request.TTLSeconds > 300 {
		writeError(w, http.StatusBadRequest, "invalid_token_request")
		return
	}
	if _, err := s.verifySession(r, request.SessionID, time.Now().UTC()); err != nil {
		writeError(w, http.StatusUnauthorized, "invalid_session")
		return
	}
	raw, err := s.tokens.Issue(request.SessionID, request.Action, time.Duration(request.TTLSeconds)*time.Second, time.Now().UTC())
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_token_request")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"proof_token": raw, "expires_in": request.TTLSeconds})
}

func (s *Server) handleDecision(w http.ResponseWriter, r *http.Request) {
	decision, ok := s.evaluateDecision(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, decision)
}

// handleOriginCheck is an alternative to /v1/decision for reverse proxies and
// origin middleware. It returns only the bounded enforcement result as HTTP
// status and headers, so detailed scores and evidence are not reflected to the
// requesting client. Without an applicable signed rollout, the result is 204.
func (s *Server) handleOriginCheck(w http.ResponseWriter, r *http.Request) {
	decision, ok := s.evaluateDecision(w, r)
	if !ok {
		return
	}
	status, ok := originStatus(decision, time.Now().UTC())
	if !ok {
		s.logger.Error("invalid origin directive", "decision_id", decision.DecisionID)
		writeError(w, http.StatusServiceUnavailable, "invalid_enforcement_directive")
		return
	}
	w.Header().Set("X-Palisade-Decision-ID", decision.DecisionID)
	w.Header().Set("X-Palisade-Action", string(decision.Action))
	w.Header().Set("X-Palisade-Handling", decision.Directive.Handling)
	w.Header().Set("X-Palisade-Mode", string(decision.Mode))
	if decision.RolloutID != "" {
		w.Header().Set("X-Palisade-Rollout-ID", decision.RolloutID)
	}
	if decision.Directive.RetryAfterSeconds > 0 {
		w.Header().Set("Retry-After", fmt.Sprintf("%d", decision.Directive.RetryAfterSeconds))
	}
	w.WriteHeader(status)
}

func (s *Server) evaluateDecision(w http.ResponseWriter, r *http.Request) (core.Decision, bool) {
	now := time.Now().UTC()
	var request core.DecisionRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json")
		return core.Decision{}, false
	}
	verifiedSession, err := s.verifySession(r, request.SessionID, now)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid_session")
		return core.Decision{}, false
	}
	request.Observations.ServerSessionVerified = verifiedSession
	if s.events != nil {
		if observed := s.events.Count(request.SessionID, now); observed > request.Observations.BrowserEventCount {
			request.Observations.BrowserEventCount = observed
		}
	}
	decision, err := s.engine.Decide(r.Context(), request)
	if err != nil {
		switch {
		case errors.Is(err, decisionengine.ErrInvalidRequest):
			writeError(w, http.StatusBadRequest, "invalid_request")
		case errors.Is(err, decisionengine.ErrProofRequired):
			writeError(w, http.StatusUnauthorized, "proof_required")
		case errors.Is(err, token.ErrInvalidToken), errors.Is(err, token.ErrExpiredToken), errors.Is(err, token.ErrReplayToken):
			writeError(w, http.StatusUnauthorized, "invalid_proof")
		default:
			s.logger.Error("decision failed", "error", err)
			writeError(w, http.StatusInternalServerError, "decision_failed")
		}
		return core.Decision{}, false
	}
	if s.shadowRecorder != nil {
		if err := s.shadowRecorder.RecordDecision(request, decision, now); err != nil {
			dropped := s.shadowDrops.Add(1)
			if dropped == 1 || dropped%1024 == 0 {
				s.logger.Warn("shadow record dropped", "dropped_total", dropped)
			}
		}
	}
	return decision, true
}

func originStatus(decision core.Decision, now time.Time) (int, bool) {
	if !stableHeaderValue(decision.DecisionID) || !decision.Directive.ExpiresAt.After(now) ||
		(decision.Mode != core.RuntimeModeShadow && decision.Mode != core.RuntimeModeCanary && decision.Mode != core.RuntimeModeEnforce) ||
		((decision.Mode == core.RuntimeModeCanary || decision.Mode == core.RuntimeModeEnforce) && !stableHeaderValue(decision.RolloutID)) {
		return 0, false
	}
	switch decision.Directive.Handling {
	case "pass":
		return http.StatusNoContent, decision.Directive.HTTPStatus == http.StatusOK &&
			(decision.Action == core.ActionAllow || decision.Action == core.ActionObserve) && decision.Directive.RetryAfterSeconds == 0
	case "throttle":
		return http.StatusTooManyRequests, decision.Directive.HTTPStatus == http.StatusTooManyRequests &&
			decision.Action == core.ActionThrottle && decision.Directive.RetryAfterSeconds > 0
	case "challenge":
		return http.StatusForbidden, decision.Directive.HTTPStatus == http.StatusForbidden &&
			decision.Action == core.ActionChallenge && decision.Directive.RetryAfterSeconds == 0
	case "block":
		return http.StatusForbidden, decision.Directive.HTTPStatus == http.StatusForbidden &&
			decision.Action == core.ActionBlock && decision.Directive.RetryAfterSeconds > 0
	default:
		return 0, false
	}
}

func stableHeaderValue(value string) bool {
	if len(value) < 1 || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if !((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') ||
			character == '_' || character == '.' || character == ':' || character == '-') {
			return false
		}
	}
	return true
}

func (s *Server) handleOutcome(w http.ResponseWriter, r *http.Request) {
	if !s.authorized(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if s.shadowRecorder == nil {
		writeError(w, http.StatusServiceUnavailable, "shadow_log_unavailable")
		return
	}
	var request shadowlog.OutcomeRequest
	if err := decodeJSON(w, r, &request); err != nil || request.Validate() != nil {
		writeError(w, http.StatusBadRequest, "invalid_outcome")
		return
	}
	if _, err := s.verifySession(r, request.SessionID, time.Now().UTC()); err != nil {
		writeError(w, http.StatusUnauthorized, "invalid_session")
		return
	}
	if err := s.shadowRecorder.RecordOutcome(request, time.Now().UTC()); err != nil {
		writeError(w, http.StatusServiceUnavailable, "shadow_log_unavailable")
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

func (s *Server) verifySession(r *http.Request, expectedSessionID string, now time.Time) (bool, error) {
	cookie, err := r.Cookie(sessioncookie.CookieName)
	if errors.Is(err, http.ErrNoCookie) {
		if s.requireSession {
			return false, sessioncookie.ErrInvalidCookie
		}
		return false, nil
	}
	if err != nil || s.sessionCookies == nil {
		return false, sessioncookie.ErrInvalidCookie
	}
	claims, err := s.sessionCookies.Verify(cookie.Value, now)
	if err != nil || claims.SessionID != expectedSessionID {
		return false, sessioncookie.ErrInvalidCookie
	}
	return true, nil
}

func (s *Server) authorized(r *http.Request) bool {
	if s.apiKey == "" {
		return false
	}
	provided := r.Header.Get("Authorization")
	expected := "Bearer " + s.apiKey
	if len(provided) != len(expected) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(provided), []byte(expected)) == 1
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) recover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if recovered := recover(); recovered != nil {
				s.logger.Error("panic recovered", "panic", recovered, "stack", string(debug.Stack()))
				writeError(w, http.StatusInternalServerError, "internal_error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func decodeJSON(w http.ResponseWriter, r *http.Request, target any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("multiple JSON values")
	}
	return nil
}

func writeError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]string{"error": code})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
