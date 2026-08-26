package httpapi

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"runtime/debug"
	"time"

	"github.com/palisade-bot-defense/palisade/internal/adminui"
	"github.com/palisade-bot-defense/palisade/internal/core"
	decisionengine "github.com/palisade-bot-defense/palisade/internal/engine"
	"github.com/palisade-bot-defense/palisade/internal/events"
	"github.com/palisade-bot-defense/palisade/internal/token"
)

const maxBodyBytes = 64 << 10

type DecisionEngine interface {
	Decide(context.Context, core.DecisionRequest) (core.Decision, error)
}

type Server struct {
	engine            DecisionEngine
	tokens            *token.Service
	apiKey            string
	logger            *slog.Logger
	events            *events.Store
	requireEventProof bool
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

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health/live", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /health/ready", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
	})
	mux.HandleFunc("POST /v1/token", s.handleToken)
	mux.HandleFunc("POST /v1/events", s.handleEvents)
	mux.HandleFunc("POST /v1/decision", s.handleDecision)
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
	raw, err := s.tokens.Issue(request.SessionID, request.Action, time.Duration(request.TTLSeconds)*time.Second, time.Now().UTC())
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_token_request")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"proof_token": raw, "expires_in": request.TTLSeconds})
}

func (s *Server) handleDecision(w http.ResponseWriter, r *http.Request) {
	var request core.DecisionRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json")
		return
	}
	if s.events != nil {
		if observed := s.events.Count(request.SessionID, time.Now().UTC()); observed > request.Observations.BrowserEventCount {
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
		return
	}
	writeJSON(w, http.StatusOK, decision)
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
