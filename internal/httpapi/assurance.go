package httpapi

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"time"

	"github.com/palisade-human-trust/palisade/internal/agentprovenance"
	"github.com/palisade-human-trust/palisade/internal/assurance"
	"github.com/palisade-human-trust/palisade/internal/core"
	"github.com/palisade-human-trust/palisade/internal/shadowlog"
	"github.com/palisade-human-trust/palisade/pkg/palisadeassurance"
)

// The assurance surface is deliberately separate from /v1/decision. It has its
// own contract file, api/openapi-assurance-v1.yaml, so the frozen decision
// contract and every existing adapter stay byte-identical, and a deployment
// that wants no assurance carries no new data class. See ADR 0005.

// AudienceHeader names the relying-party scope an assertion is minted for. The
// session commitment is derived per audience, so the same visitor is
// unlinkable across relying services and the caller must always name one.
const AudienceHeader = "X-Palisade-Assurance-Audience"

// assertionTTL bounds how long a relying service may rely on one
// request-profile assertion.
const assertionTTL = time.Minute

// defaultContentAssertionTTL is how long a content-profile assertion stays
// verifiable when the deployment does not choose otherwise. A message is read
// later than it is sent, so this is hours rather than minutes; the profile's
// hard bound is a week.
const defaultContentAssertionTTL = 24 * time.Hour

var audiencePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._:-]{0,127}$`)

// AssuranceConfig carries the keys the assurance surface needs. Both are
// deployment secrets: the binding secret never leaves the process, and only the
// public half of the signing key is given to relying services.
type AssuranceConfig struct {
	// SigningKey signs assertions.
	SigningKey ed25519.PrivateKey
	// BindingSecret derives the per-audience session commitment. It must not be
	// the proof-token secret: reusing one secret across two purposes would let
	// one construction's output be replayed into the other.
	BindingSecret []byte
	// AllowedAudiences restricts which relying parties a deployment mints
	// assertions for. An empty list disables the surface rather than allowing
	// every audience, so a misconfiguration cannot silently mint assertions for
	// an attacker-chosen scope.
	AllowedAudiences []string
	// ContentAssertionTTL is the validity of a content-profile assertion. Zero
	// selects the default; a value above the profile's bound disables the
	// surface rather than being clamped, because a deployment that asked for
	// more than the contract allows should find out.
	ContentAssertionTTL time.Duration
}

func (c AssuranceConfig) contentTTL() time.Duration {
	if c.ContentAssertionTTL == 0 {
		return defaultContentAssertionTTL
	}
	return c.ContentAssertionTTL
}

func (c AssuranceConfig) valid() bool {
	return len(c.SigningKey) == ed25519.PrivateKeySize &&
		len(c.BindingSecret) >= 32 &&
		len(c.AllowedAudiences) > 0 &&
		c.contentTTL() > 0 && c.contentTTL() <= palisadeassurance.MaximumContentLifetime
}

// contentAssuranceRequest is the body of the content surface: the same closed
// decision request, plus the commitment the sender computed over the message.
// PALISADE receives the commitment and never the message.
type contentAssuranceRequest struct {
	core.DecisionRequest
	ContentCommitment string `json:"content_commitment"`
}

// handleContentAssurance mints a content-profile assertion: the evidence is
// evaluated exactly as on the request surface, but the binding names the
// message rather than the action, and the validity is long enough for the
// message to be read later. A recipient verifies it with a client-side
// verifier and checks the commitment against the message it received, so a
// forwarded assertion fails on the forwarded message.
func (s *Server) handleContentAssurance(w http.ResponseWriter, r *http.Request) {
	if s.assurance == nil {
		writeError(w, http.StatusNotImplemented, "assurance_not_enabled")
		return
	}
	audience := r.Header.Get(AudienceHeader)
	if !audiencePattern.MatchString(audience) || !s.assurance.permits(audience) {
		writeError(w, http.StatusBadRequest, "invalid_audience")
		return
	}
	var body contentAssuranceRequest
	if err := decodeJSON(w, r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json")
		return
	}
	if !validCommitment(body.ContentCommitment) {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	request, decision, ok := s.evaluateRequest(w, r, body.DecisionRequest)
	if !ok {
		return
	}
	live := s.verifiedLiveness(r, request.SessionID, request.Action, request.EndpointClass)
	derived := assurance.Derive(decision, assurance.Evidence{LivenessVerified: live})
	s.recordDecisionWithAssurance(request, decision, &shadowlog.Assurance{
		Level:    derived.Level,
		Withheld: derived.Withheld(),
	})
	sessionBinding, err := palisadeassurance.SessionBinding(s.assurance.BindingSecret, request.SessionID, audience)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	s.respondWithAssertion(w, request, decision, derived, palisadeassurance.Binding{
		Profile:           palisadeassurance.ProfileContent,
		SessionBinding:    sessionBinding,
		ContentCommitment: body.ContentCommitment,
		Audience:          audience,
	}, s.assurance.contentTTL())
}

// validCommitment accepts exactly the shape ContentCommitment produces: a
// base64url SHA-256 without padding.
func validCommitment(value string) bool {
	if len(value) != 43 {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == 32
}

func (c AssuranceConfig) permits(audience string) bool {
	for _, allowed := range c.AllowedAudiences {
		if allowed == audience {
			return true
		}
	}
	return false
}

// WithAssurance enables the assurance surface. Without it the endpoint reports
// that the deployment does not offer assurance, rather than failing open.
func (s *Server) WithAssurance(config AssuranceConfig) *Server {
	if !config.valid() {
		s.assurance = nil
		return s
	}
	copied := config
	copied.SigningKey = append(ed25519.PrivateKey(nil), config.SigningKey...)
	copied.BindingSecret = append([]byte(nil), config.BindingSecret...)
	copied.AllowedAudiences = append([]string(nil), config.AllowedAudiences...)
	s.assurance = &copied
	return s
}

// AssuranceVerificationKey returns the public half a relying service needs, or
// nil when the surface is disabled.
func (s *Server) AssuranceVerificationKey() ed25519.PublicKey {
	if s.assurance == nil {
		return nil
	}
	return s.assurance.SigningKey.Public().(ed25519.PublicKey)
}

// handleAssurance evaluates the same decision the risk surface would and
// returns only a signed assurance assertion. Scores, evidence, enforcement
// actions and the decision identifier are deliberately not reflected: a relying
// service asking about human presence has no need for the risk decision, and
// the assertion is the whole answer.
func (s *Server) handleAssurance(w http.ResponseWriter, r *http.Request) {
	if s.assurance == nil {
		writeError(w, http.StatusNotImplemented, "assurance_not_enabled")
		return
	}
	audience := r.Header.Get(AudienceHeader)
	if !audiencePattern.MatchString(audience) || !s.assurance.permits(audience) {
		writeError(w, http.StatusBadRequest, "invalid_audience")
		return
	}

	request, decision, ok := s.evaluateDecision(w, r)
	if !ok {
		return
	}
	// The derived level is recorded with the decision so the confirmed-human
	// false-positive and abandonment interval can later be reported per level.
	// Deriving it again here rather than inside mintAssertion keeps one source
	// of truth for what was recorded and what was asserted.
	live := s.verifiedLiveness(r, request.SessionID, request.Action, request.EndpointClass)
	derived := assurance.Derive(decision, assurance.Evidence{LivenessVerified: live})
	s.recordDecisionWithAssurance(request, decision, &shadowlog.Assurance{
		Level:    derived.Level,
		Withheld: derived.Withheld(),
	})

	sessionBinding, err := palisadeassurance.SessionBinding(s.assurance.BindingSecret, request.SessionID, audience)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	s.respondWithAssertion(w, request, decision, derived, palisadeassurance.Binding{
		Profile:        palisadeassurance.ProfileRequest,
		SessionBinding: sessionBinding,
		RequestAction:  request.Action,
		EndpointClass:  request.EndpointClass,
		Audience:       audience,
	}, assertionTTL)
}

// respondWithAssertion signs one binding and writes the assertion. Every
// profile goes through here, so the response shape and the error mapping are
// the same on every surface.
func (s *Server) respondWithAssertion(
	w http.ResponseWriter,
	request core.DecisionRequest,
	decision core.Decision,
	derived assurance.Result,
	binding palisadeassurance.Binding,
	ttl time.Duration,
) {
	encoded, err := s.mintAssertion(request, decision, derived, binding, ttl, time.Now().UTC())
	if err != nil {
		// A payload this deployment cannot describe means the request itself was
		// not expressible in the closed vocabulary. Reporting that as a service
		// failure would send an operator looking for an outage that is not
		// there, so it is separated from a genuine signing failure.
		if errors.Is(err, palisadeassurance.ErrInvalid) {
			writeError(w, http.StatusBadRequest, "invalid_request")
			return
		}
		s.logger.Error("assurance assertion could not be minted", "error", err)
		writeError(w, http.StatusServiceUnavailable, "assurance_unavailable")
		return
	}
	s.counters.assuranceAssertions.Add(1)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(encoded); err != nil {
		s.logger.Error("assurance response could not be written", "error", err)
	}
}

func (s *Server) mintAssertion(
	request core.DecisionRequest,
	decision core.Decision,
	derived assurance.Result,
	binding palisadeassurance.Binding,
	ttl time.Duration,
	now time.Time,
) ([]byte, error) {
	if s.assurance == nil {
		return nil, errors.New("assurance surface disabled")
	}
	provenance := agentprovenance.Derive(request.Observations, request.EndpointClass)
	payload := derived.Payload(binding, provenance, decision.PolicyVersion, decision.ModelVersion)
	return palisadeassurance.Sign(payload, ttl, now, s.assurance.SigningKey)
}

// assuranceResponseIsClosed exists so the encoder cannot be changed to emit an
// open object without a test noticing.
func assuranceResponseIsClosed(encoded []byte) bool {
	var document map[string]json.RawMessage
	return json.Unmarshal(encoded, &document) == nil && len(document) == 3
}
