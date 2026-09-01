package httpapi

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"time"

	"github.com/palisade-human-trust/palisade/internal/agentprovenance"
	"github.com/palisade-human-trust/palisade/internal/assurance"
	"github.com/palisade-human-trust/palisade/internal/core"
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

// assertionTTL bounds how long a relying service may rely on one assertion.
const assertionTTL = time.Minute

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
}

func (c AssuranceConfig) valid() bool {
	return len(c.SigningKey) == ed25519.PrivateKeySize &&
		len(c.BindingSecret) >= 32 &&
		len(c.AllowedAudiences) > 0
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
	s.recordDecision(request, decision)

	encoded, err := s.mintAssertion(request, decision, audience, time.Now().UTC())
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
	audience string,
	now time.Time,
) ([]byte, error) {
	if s.assurance == nil {
		return nil, errors.New("assurance surface disabled")
	}
	binding, err := palisadeassurance.SessionBinding(s.assurance.BindingSecret, request.SessionID, audience)
	if err != nil {
		return nil, err
	}
	provenance := agentprovenance.Derive(request.Observations, request.EndpointClass)
	payload := assurance.Derive(decision).Payload(
		palisadeassurance.Binding{
			SessionBinding: binding,
			RequestAction:  request.Action,
			EndpointClass:  request.EndpointClass,
			Audience:       audience,
		},
		provenance,
		decision.PolicyVersion,
		decision.ModelVersion,
	)
	return palisadeassurance.Sign(payload, assertionTTL, now, s.assurance.SigningKey)
}

// assuranceResponseIsClosed exists so the encoder cannot be changed to emit an
// open object without a test noticing.
func assuranceResponseIsClosed(encoded []byte) bool {
	var document map[string]json.RawMessage
	return json.Unmarshal(encoded, &document) == nil && len(document) == 3
}
