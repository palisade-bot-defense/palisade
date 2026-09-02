package httpapi

import (
	"net/http"
	"time"

	"github.com/palisade-human-trust/palisade/internal/liveness"
	"github.com/palisade-human-trust/palisade/pkg/palisadecontract"
)

// The liveness endpoints belong to the assurance contract, not to the frozen
// decision or challenge contracts. Completing a liveness challenge never
// changes an enforcement action; it only contributes evidence to an assurance
// assertion.

// LivenessAttestationHeader carries a completed attempt to /v1/assurance. It is
// bound to one session, action and endpoint class, so presenting it for
// anything else fails.
const LivenessAttestationHeader = "X-Palisade-Liveness-Attestation"

type livenessBeginRequest struct {
	SessionID     string `json:"session_id"`
	Action        string `json:"action"`
	EndpointClass string `json:"endpoint_class"`
}

type livenessAnswerRequest struct {
	ChallengeID string `json:"challenge_id"`
	SessionID   string `json:"session_id"`
	Round       int    `json:"round"`
	Answer      string `json:"answer"`
}

// publicPrompt is the client's view of a round. It carries the instruction,
// which names the option to select: without it the round is unanswerable by
// anyone, and withholding it would not disadvantage a script. The mechanism
// rests on each round being revealed only at its own moment and answered inside
// a narrow window, not on secrecy.
//
// The raw target field is still not sent. A client reads the instruction, the
// same sentence a person reads or hears.
type publicPrompt struct {
	Round       int       `json:"round"`
	Options     []string  `json:"options"`
	Instruction string    `json:"instruction"`
	DeadlineAt  time.Time `json:"deadline_at"`
}

type livenessBeginResponse struct {
	ChallengeID string       `json:"challenge_id"`
	Family      string       `json:"family"`
	Prompt      publicPrompt `json:"prompt"`
}

type livenessAnswerResponse struct {
	Completed   bool          `json:"completed"`
	Next        *publicPrompt `json:"next,omitempty"`
	Attestation string        `json:"attestation,omitempty"`
}

// WithLiveness enables the interactive liveness endpoints. Without it they
// report that the deployment does not offer liveness rather than failing open.
func (s *Server) WithLiveness(service *liveness.Service) *Server {
	s.liveness = service
	return s
}

func toPublicPrompt(prompt liveness.Prompt) publicPrompt {
	return publicPrompt{
		Round: prompt.Round, Options: prompt.Options,
		Instruction: prompt.Instruction, DeadlineAt: prompt.DeadlineAt,
	}
}

func (s *Server) handleLivenessBegin(w http.ResponseWriter, r *http.Request) {
	if s.liveness == nil {
		writeError(w, http.StatusNotImplemented, "liveness_not_enabled")
		return
	}
	var request livenessBeginRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json")
		return
	}
	if !palisadecontract.ValidRequestAction(request.Action) ||
		!palisadecontract.ValidEndpointClass(request.EndpointClass) {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	sessionID, _, err := s.resolveSession(r, request.SessionID, time.Now().UTC())
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid_session")
		return
	}

	id, prompt, err := s.liveness.Begin(sessionID, request.Action, request.EndpointClass, time.Now().UTC())
	switch err {
	case nil:
	case liveness.ErrCapacity:
		writeError(w, http.StatusServiceUnavailable, "liveness_capacity")
		return
	default:
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	writeJSON(w, http.StatusOK, livenessBeginResponse{
		ChallengeID: id, Family: liveness.Family, Prompt: toPublicPrompt(prompt),
	})
}

func (s *Server) handleLivenessAnswer(w http.ResponseWriter, r *http.Request) {
	if s.liveness == nil {
		writeError(w, http.StatusNotImplemented, "liveness_not_enabled")
		return
	}
	var request livenessAnswerRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json")
		return
	}
	sessionID, _, err := s.resolveSession(r, request.SessionID, time.Now().UTC())
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid_session")
		return
	}

	progress, err := s.liveness.Answer(request.ChallengeID, sessionID, request.Answer, request.Round, time.Now().UTC())
	if err != nil {
		// Every failure ends the attempt, and the client is told only that it
		// ended. Distinguishing "too fast" from "wrong answer" would tell an
		// attacker which constraint to tune.
		s.counters.livenessFailed.Add(1)
		writeError(w, http.StatusConflict, "liveness_attempt_ended")
		return
	}
	response := livenessAnswerResponse{Completed: progress.Completed, Attestation: progress.Attestation}
	if progress.Next != nil {
		next := toPublicPrompt(*progress.Next)
		response.Next = &next
	}
	if progress.Completed {
		s.counters.livenessCompleted.Add(1)
	}
	writeJSON(w, http.StatusOK, response)
}

// verifiedLiveness reports whether the request carries a liveness attestation
// earned for exactly this session, action and endpoint class.
func (s *Server) verifiedLiveness(r *http.Request, sessionID, action, endpointClass string) bool {
	attestation := r.Header.Get(LivenessAttestationHeader)
	if s.liveness == nil || attestation == "" {
		return false
	}
	return s.liveness.VerifyAttestation(attestation, sessionID, action, endpointClass, time.Now().UTC()) == nil
}
