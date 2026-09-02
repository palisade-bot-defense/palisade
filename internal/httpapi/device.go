package httpapi

import (
	"encoding/base64"
	"net/http"
	"time"

	"github.com/palisade-human-trust/palisade/internal/deviceattest"
	"github.com/palisade-human-trust/palisade/pkg/palisadecontract"
)

// The device endpoints belong to the assurance contract, like liveness. A
// verified device credential is evidence for an assurance assertion; it never
// changes an enforcement action.

// DeviceAttestationHeader carries a completed ceremony to an assurance surface.
// It is bound to one session, action and endpoint class.
const DeviceAttestationHeader = "X-Palisade-Device-Attestation"

type deviceChallengeRequest struct {
	SessionID     string `json:"session_id"`
	Action        string `json:"action"`
	EndpointClass string `json:"endpoint_class"`
}

type deviceChallengeResponse struct {
	ChallengeID string `json:"challenge_id"`
	// Challenge is base64url, the encoding a WebAuthn client expects to find in
	// clientDataJSON after the ceremony.
	Challenge      string `json:"challenge"`
	RelyingPartyID string `json:"relying_party_id"`
	ExpiresAt      string `json:"expires_at"`
}

type deviceCompleteRequest struct {
	ChallengeID       string `json:"challenge_id"`
	SessionID         string `json:"session_id"`
	CredentialID      string `json:"credential_id"`
	AuthenticatorData string `json:"authenticator_data"`
	ClientDataJSON    string `json:"client_data_json"`
	Signature         string `json:"signature"`
}

type deviceCompleteResponse struct {
	Attestation string `json:"attestation"`
}

// WithDeviceAttestation enables the device endpoints. Without it they report
// that the deployment does not offer device attestation rather than failing
// open.
func (s *Server) WithDeviceAttestation(service *deviceattest.Service) *Server {
	s.devices = service
	return s
}

func (s *Server) handleDeviceChallenge(w http.ResponseWriter, r *http.Request) {
	if s.devices == nil {
		writeError(w, http.StatusNotImplemented, "device_attestation_not_enabled")
		return
	}
	var request deviceChallengeRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json")
		return
	}
	if !palisadecontract.ValidRequestAction(request.Action) ||
		!palisadecontract.ValidEndpointClass(request.EndpointClass) {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	now := time.Now().UTC()
	sessionID, _, err := s.resolveSession(r, request.SessionID, now)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid_session")
		return
	}
	id, value, err := s.devices.Challenge(sessionID, request.Action, request.EndpointClass, now)
	switch err {
	case nil:
	case deviceattest.ErrCapacityExceeded:
		writeError(w, http.StatusServiceUnavailable, "device_challenge_capacity")
		return
	default:
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	writeJSON(w, http.StatusOK, deviceChallengeResponse{
		ChallengeID:    id,
		Challenge:      base64.RawURLEncoding.EncodeToString(value),
		RelyingPartyID: s.devices.RelyingPartyID(),
		ExpiresAt:      now.Add(deviceattest.ChallengeTTL).Format(time.RFC3339),
	})
}

func (s *Server) handleDeviceComplete(w http.ResponseWriter, r *http.Request) {
	if s.devices == nil {
		writeError(w, http.StatusNotImplemented, "device_attestation_not_enabled")
		return
	}
	var request deviceCompleteRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json")
		return
	}
	now := time.Now().UTC()
	sessionID, _, err := s.resolveSession(r, request.SessionID, now)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid_session")
		return
	}
	authenticatorData, dataErr := base64.RawURLEncoding.DecodeString(request.AuthenticatorData)
	clientDataJSON, clientErr := base64.RawURLEncoding.DecodeString(request.ClientDataJSON)
	signature, signatureErr := base64.RawURLEncoding.DecodeString(request.Signature)
	if dataErr != nil || clientErr != nil || signatureErr != nil {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	attestation, err := s.devices.Complete(request.ChallengeID, sessionID, deviceattest.Assertion{
		CredentialID:      request.CredentialID,
		AuthenticatorData: authenticatorData,
		ClientDataJSON:    clientDataJSON,
		Signature:         signature,
	}, now)
	if err != nil {
		// Every failure returns one status and one code. Telling a client
		// whether the credential was unknown, the signature wrong, the
		// authenticator untouched or the counter stale would say which
		// constraint to work on, and would also reveal whether a credential
		// identifier is registered here.
		s.counters.deviceCeremoniesFailed.Add(1)
		writeError(w, http.StatusConflict, "device_ceremony_failed")
		return
	}
	s.counters.deviceCeremoniesCompleted.Add(1)
	writeJSON(w, http.StatusOK, deviceCompleteResponse{Attestation: attestation})
}

// verifiedDevice reports whether the request carries a device attestation
// earned for exactly this session, action and endpoint class.
func (s *Server) verifiedDevice(r *http.Request, sessionID, action, endpointClass string) bool {
	attestation := r.Header.Get(DeviceAttestationHeader)
	if s.devices == nil || attestation == "" {
		return false
	}
	return s.devices.VerifyAttestation(attestation, sessionID, action, endpointClass, time.Now().UTC()) == nil
}
