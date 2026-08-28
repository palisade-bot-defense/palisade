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

	"github.com/palisade-bot-defense/palisade/internal/challenge"
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
	challenges        *challenge.Service
	shadowDrops       atomic.Uint64
	eventShadow       *EventShadowProfile
	eventShadowDrops  atomic.Uint64
	originCoverage    *originCoverageStore
	crawlerRegistry   *crawlerRegistryStatusStore
	admin             AdminConfig
	counters          runtimeCounters
}

func New(engine DecisionEngine, tokens *token.Service, apiKey string, logger *slog.Logger) *Server {
	return &Server{
		engine: engine, tokens: tokens, apiKey: apiKey, logger: logger,
		originCoverage: newOriginCoverageStore(time.Now().UTC()), crawlerRegistry: newCrawlerRegistryStatusStore(),
	}
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

func (s *Server) WithEventShadowEvaluation(profile EventShadowProfile) *Server {
	s.eventShadow = &profile
	return s
}

func (s *Server) WithChallenges(service *challenge.Service) *Server {
	s.challenges = service
	if service != nil {
		service.SetOutcomeHandler(s.recordChallengeOutcome)
	}
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
	mux.HandleFunc("POST /v1/origin-coverage", s.handleOriginCoverage)
	mux.HandleFunc("POST /v1/crawler-registry-status", s.handleCrawlerRegistryStatus)
	mux.HandleFunc("POST /v1/outcome", s.handleOutcome)
	mux.HandleFunc("GET /v1/challenge/{challenge_id}", s.handleChallengeView)
	mux.HandleFunc("POST /v1/challenge/verify", s.handleChallengeVerify)
	mux.HandleFunc("POST /v1/challenge/redeem", s.handleChallengeRedeem)
	mux.HandleFunc("POST /v1/challenge/fallback", s.handleChallengeFallback)
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
	now := time.Now().UTC()
	var eventProofClaims token.Claims
	sessionID, verifiedSession, err := s.resolveSession(r, batch.SessionID, now)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid_session")
		return
	}
	batch.SessionID = sessionID
	if s.requireEventProof {
		proof := r.Header.Get("X-Palisade-Proof")
		if proof == "" {
			if s.eventShadow != nil {
				s.counters.eventShadowRejected.Add(1)
			}
			writeError(w, http.StatusUnauthorized, "event_proof_required")
			return
		}
		eventProofClaims, err = s.tokens.VerifyAndConsume(proof, batch.SessionID, "events", now)
		if err != nil {
			if s.eventShadow != nil {
				s.counters.eventShadowRejected.Add(1)
			}
			writeError(w, http.StatusUnauthorized, "invalid_event_proof")
			return
		}
	}
	if s.eventShadow != nil {
		if _, _, err := s.eventShadow.classification(eventProofClaims); err != nil {
			s.counters.eventShadowRejected.Add(1)
			writeError(w, http.StatusUnauthorized, "invalid_event_proof")
			return
		}
	}
	receipt, err := s.events.IngestWithReceipt(batch, now)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_event_batch")
		return
	}
	s.counters.eventBatches.Add(1)
	s.counters.events.Add(uint64(len(batch.Events)))
	if s.eventShadow != nil {
		if err := s.recordEventShadowDecision(r.Context(), batch, receipt, eventProofClaims, verifiedSession, r.UserAgent() != "", now); err != nil {
			s.recordEventShadowDrop(err)
			w.Header().Set("X-Palisade-Shadow-Evaluation", "dropped")
		} else {
			w.Header().Set("X-Palisade-Shadow-Evaluation", "recorded")
		}
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
		SessionID     string `json:"session_id"`
		Action        string `json:"action"`
		RequestAction string `json:"request_action"`
		EndpointClass string `json:"endpoint_class"`
		TTLSeconds    int    `json:"ttl_seconds"`
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
	now := time.Now().UTC()
	sessionID, verifiedSession, err := s.resolveSession(r, request.SessionID, now)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid_session")
		return
	}
	contextRequested := request.RequestAction != "" || request.EndpointClass != ""
	if contextRequested && (s.eventShadow == nil || !s.eventShadow.fromProof || !s.requireEventProof || !verifiedSession || request.Action != "events" ||
		!validEventShadowAction(request.RequestAction) || !validEventShadowEndpoint(request.EndpointClass)) {
		writeError(w, http.StatusBadRequest, "invalid_token_request")
		return
	}
	var raw string
	if contextRequested {
		raw, err = s.tokens.IssueEventContext(sessionID, request.RequestAction, request.EndpointClass, time.Duration(request.TTLSeconds)*time.Second, now)
	} else {
		raw, err = s.tokens.Issue(sessionID, request.Action, time.Duration(request.TTLSeconds)*time.Second, now)
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_token_request")
		return
	}
	if contextRequested {
		s.counters.contextProofs.Add(1)
		s.counters.endpointContexts.increment(request.EndpointClass)
	}
	writeJSON(w, http.StatusCreated, map[string]any{"proof_token": raw, "expires_in": request.TTLSeconds})
}

func (s *Server) handleDecision(w http.ResponseWriter, r *http.Request) {
	request, decision, ok := s.evaluateDecision(w, r)
	if !ok {
		return
	}
	s.recordDecision(request, decision)
	writeJSON(w, http.StatusOK, decision)
}

// handleOriginCheck is an alternative to /v1/decision for reverse proxies and
// origin middleware. It returns only the bounded enforcement result as HTTP
// status and headers, so detailed scores and evidence are not reflected to the
// requesting client. Without an applicable signed rollout, the result is 204.
func (s *Server) handleOriginCheck(w http.ResponseWriter, r *http.Request) {
	request, decision, ok := s.evaluateDecision(w, r)
	if !ok {
		return
	}
	status, ok := originStatus(decision, time.Now().UTC())
	if !ok {
		s.logger.Error("invalid origin directive", "decision_id", decision.DecisionID)
		writeError(w, http.StatusServiceUnavailable, "invalid_enforcement_directive")
		return
	}
	s.counters.originChecks.Add(1)
	challengeID := ""
	if decision.Directive.Handling == "challenge" {
		if s.challenges == nil {
			writeError(w, http.StatusServiceUnavailable, "challenge_service_unavailable")
			return
		}
		metadata, err := s.challenges.Issue(request, decision, time.Now().UTC())
		if err != nil {
			s.logger.Error("challenge issuance failed", "decision_id", decision.DecisionID, "error", err)
			writeError(w, http.StatusServiceUnavailable, "challenge_issue_failed")
			return
		}
		challengeID = metadata.ChallengeID
	}
	s.recordDecision(request, decision)
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
	if challengeID != "" {
		w.Header().Set("X-Palisade-Challenge-ID", challengeID)
		w.Header().Set("Location", "/v1/challenge/"+challengeID)
	}
	w.WriteHeader(status)
}

func (s *Server) handleOriginCoverage(w http.ResponseWriter, r *http.Request) {
	if !s.authorized(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	var report originCoverageReport
	if err := decodeJSON(w, r, &report); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_origin_coverage")
		return
	}
	if err := s.originCoverage.observe(report, time.Now().UTC()); err != nil {
		switch {
		case errors.Is(err, errOriginCoverageConflict):
			writeError(w, http.StatusConflict, "origin_coverage_conflict")
		case errors.Is(err, errOriginCoverageCapacity):
			writeError(w, http.StatusServiceUnavailable, "origin_coverage_capacity")
		default:
			writeError(w, http.StatusBadRequest, "invalid_origin_coverage")
		}
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

func (s *Server) handleCrawlerRegistryStatus(w http.ResponseWriter, r *http.Request) {
	if !s.authorized(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	var report crawlerRegistryStatusReport
	if err := decodeJSON(w, r, &report); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_crawler_registry_status")
		return
	}
	if err := s.crawlerRegistry.observe(report, time.Now().UTC()); err != nil {
		switch {
		case errors.Is(err, errCrawlerRegistryStatusConflict):
			writeError(w, http.StatusConflict, "crawler_registry_status_conflict")
		case errors.Is(err, errCrawlerRegistryStatusCapacity):
			writeError(w, http.StatusServiceUnavailable, "crawler_registry_status_capacity")
		default:
			writeError(w, http.StatusBadRequest, "invalid_crawler_registry_status")
		}
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

func (s *Server) handleChallengeView(w http.ResponseWriter, r *http.Request) {
	sessionID, ok := s.challengeSession(w, r)
	if !ok {
		return
	}
	metadata, err := s.challenges.View(r.PathValue("challenge_id"), sessionID, time.Now().UTC())
	if err != nil {
		s.writeChallengeError(w, err, "", sessionID)
		return
	}
	writeJSON(w, http.StatusOK, metadata)
}

func (s *Server) handleChallengeVerify(w http.ResponseWriter, r *http.Request) {
	sessionID, ok := s.challengeSession(w, r)
	if !ok {
		return
	}
	var request struct {
		ChallengeID       string `json:"challenge_id"`
		VerificationToken string `json:"verification_token"`
	}
	if err := decodeJSON(w, r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json")
		return
	}
	result, err := s.challenges.Verify(request.ChallengeID, sessionID, request.VerificationToken, time.Now().UTC())
	if err != nil {
		s.writeChallengeError(w, err, request.ChallengeID, sessionID)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleChallengeRedeem(w http.ResponseWriter, r *http.Request) {
	sessionID, ok := s.challengeSession(w, r)
	if !ok {
		return
	}
	var request struct {
		ChallengeID     string `json:"challenge_id"`
		RedemptionToken string `json:"redemption_token"`
		Action          string `json:"action"`
		EndpointClass   string `json:"endpoint_class"`
	}
	if err := decodeJSON(w, r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json")
		return
	}
	if err := s.challenges.Redeem(request.ChallengeID, sessionID, request.RedemptionToken, request.Action, request.EndpointClass, time.Now().UTC()); err != nil {
		s.writeChallengeError(w, err, request.ChallengeID, sessionID)
		return
	}
	w.Header().Set("X-Palisade-Challenge", "redeemed")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleChallengeFallback(w http.ResponseWriter, r *http.Request) {
	sessionID, ok := s.challengeSession(w, r)
	if !ok {
		return
	}
	var request struct {
		ChallengeID string `json:"challenge_id"`
	}
	if err := decodeJSON(w, r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json")
		return
	}
	if err := s.challenges.Fallback(request.ChallengeID, sessionID, time.Now().UTC()); err != nil {
		s.writeChallengeError(w, err, request.ChallengeID, sessionID)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) challengeSession(w http.ResponseWriter, r *http.Request) (string, bool) {
	if s.challenges == nil || s.sessionCookies == nil {
		writeError(w, http.StatusServiceUnavailable, "challenge_service_unavailable")
		return "", false
	}
	cookie, err := r.Cookie(sessioncookie.CookieName)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid_session")
		return "", false
	}
	claims, err := s.sessionCookies.Verify(cookie.Value, time.Now().UTC())
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid_session")
		return "", false
	}
	return claims.SessionID, true
}

func (s *Server) writeChallengeError(w http.ResponseWriter, err error, challengeID, sessionID string) {
	switch {
	case errors.Is(err, challenge.ErrNotFound), errors.Is(err, challenge.ErrSessionMismatch):
		writeError(w, http.StatusNotFound, "challenge_not_found")
	case errors.Is(err, challenge.ErrExpired):
		writeError(w, http.StatusGone, "challenge_expired")
	case errors.Is(err, challenge.ErrNotReady):
		if retry := s.challenges.RetryAfter(challengeID, sessionID, time.Now().UTC()); retry > 0 {
			w.Header().Set("Retry-After", fmt.Sprintf("%d", int((retry+time.Second-1)/time.Second)))
		}
		writeError(w, http.StatusTooEarly, "challenge_not_ready")
	case errors.Is(err, challenge.ErrAttemptsExceeded):
		writeError(w, http.StatusTooManyRequests, "challenge_attempts_exceeded")
	case errors.Is(err, challenge.ErrInvalidState):
		writeError(w, http.StatusConflict, "challenge_invalid_state")
	case errors.Is(err, challenge.ErrInvalidVerification), errors.Is(err, challenge.ErrInvalidRedemption), errors.Is(err, challenge.ErrInvalidChallenge):
		writeError(w, http.StatusBadRequest, "challenge_invalid")
	default:
		writeError(w, http.StatusServiceUnavailable, "challenge_unavailable")
	}
}

func (s *Server) recordChallengeOutcome(outcome challenge.Outcome) {
	if s.shadowRecorder == nil {
		s.counters.outcomeDropped.Add(1)
		s.recordShadowDrop()
		return
	}
	request := shadowlog.OutcomeRequest{
		SessionID: outcome.SessionID, DecisionID: outcome.DecisionID, EndpointClass: outcome.EndpointClass,
		Outcome: outcome.Kind, Provenance: "server_observed", Confidence: "confirmed",
	}
	if err := s.shadowRecorder.RecordOutcome(request, time.Now().UTC()); err != nil {
		s.counters.outcomeDropped.Add(1)
		s.recordShadowDrop()
		return
	}
	s.counters.recordedOutcomes.Add(1)
}

func (s *Server) recordShadowDrop() {
	dropped := s.shadowDrops.Add(1)
	if dropped == 1 || dropped%1024 == 0 {
		s.logger.Warn("shadow record dropped", "dropped_total", dropped)
	}
}

func (s *Server) evaluateDecision(w http.ResponseWriter, r *http.Request) (core.DecisionRequest, core.Decision, bool) {
	now := time.Now().UTC()
	var request core.DecisionRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json")
		return core.DecisionRequest{}, core.Decision{}, false
	}
	sessionID, verifiedSession, err := s.resolveSession(r, request.SessionID, now)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid_session")
		return core.DecisionRequest{}, core.Decision{}, false
	}
	request.SessionID = sessionID
	request.Observations.ServerSessionVerified = verifiedSession
	if s.events != nil {
		// The live service owns browser-event provenance. Never let a request
		// inflate its own count and obtain benign continuity evidence.
		request.Observations.BrowserEventCount = s.events.Count(request.SessionID, now)
		request.Observations.BrowserEventsVerified = true
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
		return core.DecisionRequest{}, core.Decision{}, false
	}
	s.counters.transport.increment(request.Observations)
	s.counters.crawlers.increment(request.Observations, request.EndpointClass)
	s.recordRuntimeDecision(decision)
	return request, decision, true
}

func (s *Server) recordDecision(request core.DecisionRequest, decision core.Decision) {
	if s.shadowRecorder != nil {
		if err := s.shadowRecorder.RecordDecision(request, decision, time.Now().UTC()); err != nil {
			s.recordShadowDrop()
			return
		}
		s.counters.recordedDecisions.Add(1)
	}
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
	case "delay":
		return http.StatusTooManyRequests, decision.Directive.HTTPStatus == http.StatusTooManyRequests &&
			decision.Action == core.ActionDelay && decision.Directive.RetryAfterSeconds == 1
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
		s.counters.outcomeDropped.Add(1)
		writeError(w, http.StatusServiceUnavailable, "shadow_log_unavailable")
		return
	}
	var request shadowlog.OutcomeRequest
	if err := decodeJSON(w, r, &request); err != nil {
		s.counters.outcomeRejected.Add(1)
		writeError(w, http.StatusBadRequest, "invalid_outcome")
		return
	}
	now := time.Now().UTC()
	sessionID, _, err := s.resolveSession(r, request.SessionID, now)
	if err != nil {
		s.counters.outcomeRejected.Add(1)
		writeError(w, http.StatusUnauthorized, "invalid_session")
		return
	}
	request.SessionID = sessionID
	if request.Validate() != nil {
		s.counters.outcomeRejected.Add(1)
		writeError(w, http.StatusBadRequest, "invalid_outcome")
		return
	}
	if err := s.shadowRecorder.RecordOutcome(request, now); err != nil {
		s.counters.outcomeDropped.Add(1)
		writeError(w, http.StatusServiceUnavailable, "shadow_log_unavailable")
		return
	}
	s.counters.recordedOutcomes.Add(1)
	w.WriteHeader(http.StatusAccepted)
}

func (s *Server) verifySession(r *http.Request, expectedSessionID string, now time.Time) (bool, error) {
	_, verified, err := s.resolveSession(r, expectedSessionID, now)
	return verified, err
}

func (s *Server) resolveSession(r *http.Request, expectedSessionID string, now time.Time) (string, bool, error) {
	cookie, err := r.Cookie(sessioncookie.CookieName)
	if errors.Is(err, http.ErrNoCookie) {
		if s.requireSession || expectedSessionID == "" {
			return "", false, sessioncookie.ErrInvalidCookie
		}
		return expectedSessionID, false, nil
	}
	if err != nil || s.sessionCookies == nil {
		return "", false, sessioncookie.ErrInvalidCookie
	}
	claims, err := s.sessionCookies.Verify(cookie.Value, now)
	if err != nil || (expectedSessionID != "" && claims.SessionID != expectedSessionID) {
		return "", false, sessioncookie.ErrInvalidCookie
	}
	return claims.SessionID, true, nil
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
