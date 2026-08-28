package palisadehttp

import (
	"context"
	"net/http"
)

// Outcome is a closed delayed result linked to the exact PALISADE decision
// that allowed the application request to proceed.
type Outcome struct {
	Kind       string
	Provenance string
	Confidence string
}

// OutcomeHandle is an opaque, request-scoped link to a PALISADE decision. It
// contains no credential, application URL, body, account identifier or client
// address. It is valid only together with the protected request that carried
// it and should not be serialized.
type OutcomeHandle struct {
	decisionID    string
	endpointClass string
}

type outcomeContextKey struct{}

type outcomeContext struct {
	handle OutcomeHandle
	cookie http.Cookie
}

// OutcomeHandleFromRequest returns a handle only after PALISADE validated a
// pass decision and the protected request reached the application.
func OutcomeHandleFromRequest(request *http.Request) (OutcomeHandle, bool) {
	if request == nil {
		return OutcomeHandle{}, false
	}
	linked, ok := request.Context().Value(outcomeContextKey{}).(outcomeContext)
	return linked.handle, ok && validOutcomeHandle(linked.handle) && validOutcomeCookie(linked.cookie)
}

// DecisionID returns the stable PALISADE decision identifier. It is safe for
// private operational linkage but must not be exposed to the browser or used
// as an authentication credential.
func (h OutcomeHandle) DecisionID() string { return h.decisionID }

// RecordOutcome sends one normalized result to PALISADE while the protected
// request is being handled. The signed session cookie captured in the private
// request context binds the outcome server-side, so applications never need to
// read or forward a raw PALISADE session ID.
func (m *Middleware) RecordOutcome(request *http.Request, handle OutcomeHandle, outcome Outcome) error {
	if request == nil || !validOutcomeHandle(handle) || !validOutcome(outcome) {
		return ErrInvalidOutcome
	}
	linked, ok := request.Context().Value(outcomeContextKey{}).(outcomeContext)
	if !ok || linked.handle != handle || !validOutcomeCookie(linked.cookie) {
		return ErrInvalidOutcome
	}
	payload := struct {
		DecisionID    string `json:"decision_id"`
		EndpointClass string `json:"endpoint_class"`
		Outcome       string `json:"outcome"`
		Provenance    string `json:"provenance"`
		Confidence    string `json:"confidence"`
	}{
		DecisionID: handle.decisionID, EndpointClass: handle.endpointClass,
		Outcome: outcome.Kind, Provenance: outcome.Provenance, Confidence: outcome.Confidence,
	}
	status, err := m.postJSON(request.Context(), "/v1/outcome", payload, &linked.cookie, true, nil)
	if err != nil {
		return err
	}
	if status != http.StatusAccepted {
		return apiStatusError{status: status, op: "outcome recording"}
	}
	return nil
}

func withOutcomeHandle(request *http.Request, decisionID, endpointClass string, cookie http.Cookie) *http.Request {
	handle := OutcomeHandle{decisionID: decisionID, endpointClass: endpointClass}
	if !validOutcomeHandle(handle) || !validOutcomeCookie(cookie) {
		return request
	}
	return request.WithContext(context.WithValue(request.Context(), outcomeContextKey{}, outcomeContext{handle: handle, cookie: cookie}))
}

func validOutcomeHandle(handle OutcomeHandle) bool {
	return stableValue(handle.decisionID) && validEndpointClass(handle.endpointClass)
}

func validOutcomeCookie(cookie http.Cookie) bool {
	return cookie.Name == SessionCookieName && cookie.Value != "" && len(cookie.Value) <= 4096
}

func validOutcome(outcome Outcome) bool {
	switch outcome.Kind {
	case "human_confirmed":
		return (outcome.Provenance == "authenticated_account" || outcome.Provenance == "operator_review") && outcome.Confidence == "confirmed"
	case "operator_confirmed_abuse":
		return outcome.Provenance == "operator_review" && outcome.Confidence == "confirmed"
	case "successful_action", "challenge_passed", "challenge_failed", "challenge_abandoned":
		return outcome.Provenance == "server_observed" && outcome.Confidence == "confirmed"
	case "appeal_requested", "fallback_used":
		return (outcome.Provenance == "server_observed" || outcome.Provenance == "user_feedback") && outcome.Confidence == "confirmed"
	case "unknown":
		return outcome.Provenance == "unknown" && outcome.Confidence == "unknown"
	default:
		return false
	}
}

func validEndpointClass(value string) bool {
	switch value {
	case "public_content", "compare_index", "compare_noindex", "challenge_worker", "other_public", "account", "login", "checkout", "other":
		return true
	default:
		return false
	}
}
