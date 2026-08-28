package palisadehttp

import "net/http"

// EventProof is a short-lived one-time capability intended for the sensor's
// X-Palisade-Proof header. It is a credential and must not be logged.
type EventProof struct {
	ProofToken string `json:"proof_token"`
	ExpiresIn  int    `json:"expires_in"`
}

// IssueEventProof lets a trusted origin mint a route-classified sensor proof
// without exposing its PALISADE bearer credential to browser code. The method
// reads only the PALISADE session cookie from request; it never forwards the
// request target, headers, body or application cookies.
func (m *Middleware) IssueEventProof(request *http.Request, classification Classification) (EventProof, error) {
	if request == nil || !validClassification(classification) || classification.Action == "events" || classification.EvaluationCohort != "" {
		return EventProof{}, ErrInvalidClassification
	}
	cookie, err := request.Cookie(SessionCookieName)
	if err != nil || cookie.Value == "" || len(cookie.Value) > 4096 {
		return EventProof{}, ErrSessionRequired
	}
	payload := struct {
		Action        string `json:"action"`
		RequestAction string `json:"request_action"`
		EndpointClass string `json:"endpoint_class"`
		TTLSeconds    int    `json:"ttl_seconds"`
	}{Action: "events", RequestAction: classification.Action, EndpointClass: classification.EndpointClass, TTLSeconds: 60}
	var result EventProof
	status, err := m.postJSON(request.Context(), "/v1/token", payload, cookie, true, &result)
	if err != nil {
		return EventProof{}, err
	}
	if status != http.StatusCreated {
		return EventProof{}, apiStatusError{status: status, op: "event proof issuance"}
	}
	if result.ProofToken == "" || len(result.ProofToken) > 8192 || result.ExpiresIn < 1 || result.ExpiresIn > 300 {
		return EventProof{}, ErrInvalidResponse
	}
	return result, nil
}
