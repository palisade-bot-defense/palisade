package palisadehttp

import (
	"errors"
	"math"
	"net/http"
	"strings"
	"time"
)

func (m *Middleware) Handler(next http.Handler) http.Handler {
	if next == nil {
		panic("palisadehttp: nil next handler")
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if m.handleAdapterRoute(w, r) {
			return
		}
		classification, err := m.classifier(r)
		if err != nil || !validClassification(classification) {
			m.logger.Error("PALISADE request classification failed")
			writeAdapterError(w, http.StatusInternalServerError, "palisade_classification_failed")
			return
		}
		now := m.now().UTC()
		if m.state.consumeGrant(r, classification, now) {
			clearRedemptionCookie(w)
			w.Header().Set("X-Palisade-Adapter", "redeemed")
			next.ServeHTTP(w, r)
			return
		}
		signals := Signals{UserAgentPresent: strings.TrimSpace(r.UserAgent()) != ""}
		if m.signals != nil {
			signals, err = m.signals(r)
			if err != nil || !validSignals(signals) {
				m.logger.Error("PALISADE normalized signal provider failed")
				writeAdapterError(w, http.StatusInternalServerError, "palisade_signals_failed")
				return
			}
		}

		cookie, incoming, err := m.sessionCookie(r)
		if err != nil {
			m.handleUnavailable(w, r, next, "session", err)
			return
		}
		if !incoming {
			cookie, err = m.issueSession(r.Context())
			if err != nil {
				m.handleUnavailable(w, r, next, "session", err)
				return
			}
			http.SetCookie(w, &cookie)
		}
		proof, err := m.issueProof(r.Context(), cookie, classification.Action)
		var statusError apiStatusError
		if incoming && errors.As(err, &statusError) && statusError.status == http.StatusUnauthorized {
			cookie, err = m.issueSession(r.Context())
			if err == nil {
				http.SetCookie(w, &cookie)
				proof, err = m.issueProof(r.Context(), cookie, classification.Action)
			}
		}
		if err != nil {
			m.handleUnavailable(w, r, next, "proof", err)
			return
		}
		sequence, err := m.state.nextSequence(cookie.Value, now)
		if err != nil {
			m.handleUnavailable(w, r, next, "sequence", err)
			return
		}
		result, err := m.checkOrigin(r.Context(), cookie, classification, signals, sequence, proof)
		if err != nil {
			m.handleUnavailable(w, r, next, "origin_check", err)
			return
		}
		switch result.status {
		case http.StatusNoContent:
			w.Header().Set("X-Palisade-Adapter", "pass")
			next.ServeHTTP(w, r)
		case http.StatusTooManyRequests:
			w.Header().Set("Retry-After", integerString(result.retryAfter))
			w.Header().Set("X-Palisade-Action", "throttle")
			w.WriteHeader(http.StatusTooManyRequests)
		case http.StatusForbidden:
			if result.handling == "block" {
				w.Header().Set("Retry-After", integerString(result.retryAfter))
				w.Header().Set("X-Palisade-Action", "block")
				w.WriteHeader(http.StatusForbidden)
				return
			}
			if r.Method == http.MethodGet {
				m.writeChallengePage(w, r, result.challengeID, cookie.Value, classification)
				return
			}
			w.Header().Set("X-Palisade-Action", "challenge")
			w.Header().Set("X-Palisade-Challenge-ID", result.challengeID)
			w.Header().Set("Location", m.prefix+"/challenge/"+result.challengeID)
			w.WriteHeader(http.StatusForbidden)
		}
	})
}

func (m *Middleware) sessionCookie(request *http.Request) (http.Cookie, bool, error) {
	cookie, err := request.Cookie(SessionCookieName)
	if errors.Is(err, http.ErrNoCookie) {
		return http.Cookie{}, false, nil
	}
	if err != nil || cookie.Value == "" || len(cookie.Value) > 4096 {
		return http.Cookie{}, false, ErrInvalidResponse
	}
	return *cookie, true, nil
}

func (m *Middleware) handleUnavailable(w http.ResponseWriter, r *http.Request, next http.Handler, operation string, err error) {
	m.logger.Warn("PALISADE adapter dependency unavailable", "operation", operation, "error", err)
	if m.failureMode == FailOpen {
		w.Header().Set("X-Palisade-Adapter", "bypass_unavailable")
		next.ServeHTTP(w, r)
		return
	}
	writeAdapterError(w, http.StatusServiceUnavailable, "palisade_unavailable")
}

func validClassification(classification Classification) bool {
	switch classification.Action {
	case "read", "write", "create", "update", "delete", "search", "compare", "login", "logout", "register", "checkout", "purchase", "events", "other":
	default:
		return false
	}
	switch classification.EndpointClass {
	case "public_content", "compare_index", "compare_noindex", "challenge_worker", "other_public", "account", "login", "checkout", "other":
		switch classification.EvaluationCohort {
		case "", "standard", "reduced_motion", "keyboard_only", "fallback_path", "sensor_missing", "unknown":
			return true
		default:
			return false
		}
	default:
		return false
	}
}

func validSignals(signals Signals) bool {
	if signals.BrowserEventCount < 0 || signals.BrowserEventCount > 10_000 || signals.HoneypotHits < 0 || signals.HoneypotHits > 100 ||
		math.IsNaN(signals.ExternalRiskScore) || math.IsInf(signals.ExternalRiskScore, 0) || signals.ExternalRiskScore < 0 || signals.ExternalRiskScore > 1 {
		return false
	}
	switch signals.ChallengeVerdict {
	case "", "suspicious", "failed", "blocked", "allowed", "passed", "unknown":
		return true
	default:
		return false
	}
}

func integerString(value int) string {
	if value <= 0 {
		return "0"
	}
	var buffer [20]byte
	index := len(buffer)
	for value > 0 {
		index--
		buffer[index] = byte('0' + value%10)
		value /= 10
	}
	return string(buffer[index:])
}

func writeAdapterError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(`{"error":"` + code + `"}` + "\n"))
}

func (m *Middleware) nowUTC() time.Time { return m.now().UTC() }
