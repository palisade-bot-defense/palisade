package deviceattest

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"io"
	"sync"
	"time"
)

// The transport side of device attestation: PALISADE issues a challenge, the
// client answers it with a registered credential, and a completed ceremony
// becomes a short-lived attestation the client presents on any assurance
// surface. It mirrors the liveness lifecycle so both kinds of evidence are
// carried the same way.
//
// PALISADE still registers nothing. Credentials are supplied by the deployment
// through a Registry it implements, which is where whatever attestation policy
// the deployment chose was already applied.

const (
	// ChallengeTTL bounds how long an issued challenge may be answered. It is
	// short because the challenge is the only thing making the assertion fresh.
	ChallengeTTL = 2 * time.Minute
	// AttestationTTL bounds how long a completed ceremony may be presented.
	AttestationTTL = 2 * time.Minute
	// MaximumChallenges bounds outstanding challenges.
	MaximumChallenges = 50_000

	// ChallengeBytes is the challenge length. It must be long enough that an
	// attacker cannot pre-sign one.
	ChallengeBytes = 32

	attestationContext = "PALISADE\x00DEVICE-ATTESTATION\x00V1\x00"
)

var (
	// ErrNotFound reports a challenge that was never issued, already used, or
	// has expired.
	ErrNotFound = errors.New("device challenge not found")
	// ErrUnknownCredential reports a credential the deployment did not register.
	ErrUnknownCredential = errors.New("device credential is not registered")
	// ErrAttestationInvalid reports an attestation that does not verify for the
	// session, action and endpoint class it is presented with.
	ErrAttestationInvalid = errors.New("invalid device attestation")
	// ErrCapacityExceeded reports too many outstanding challenges.
	ErrCapacityExceeded = errors.New("device challenge capacity exceeded")
)

// Registry supplies registered credentials. A deployment implements it over
// whatever store its registration ceremony writes to; PALISADE never writes a
// credential of its own.
type Registry interface {
	// Credential returns the registered credential for one identifier and the
	// session presenting it. Returning false must mean "not registered here",
	// which is refused rather than treated as an error to retry.
	Credential(credentialID, sessionID string) (Credential, bool)
	// RecordSignCount persists the counter a verified assertion carried, so a
	// cloned credential is detected on its next use. A registry that cannot
	// persist may ignore it, which weakens clone detection to nothing and
	// should be a deliberate choice.
	RecordSignCount(credentialID string, signCount uint32)
}

// Config configures the service.
type Config struct {
	// Secret authenticates attestations. It never leaves the process and must
	// not be the liveness secret: the two are separated by domain anyway, but
	// distinct secrets keep one compromise from producing both kinds of
	// evidence.
	Secret []byte
	// Registry supplies registered credentials.
	Registry Registry
	// Policy is what every ceremony must satisfy.
	Policy Policy
	// MaxChallenges bounds outstanding challenges; zero selects the default.
	MaxChallenges int
	// Random sources challenges; nil selects crypto/rand.
	Random io.Reader
}

type challenge struct {
	sessionID     string
	action        string
	endpointClass string
	value         []byte
	expiresAt     time.Time
}

// Service issues device challenges and turns completed ceremonies into
// attestations. It performs no I/O and no network call.
type Service struct {
	mu         sync.Mutex
	secret     []byte
	registry   Registry
	policy     Policy
	maximum    int
	random     io.Reader
	challenges map[string]*challenge
}

// NewService builds a service. A short secret, an absent registry or an
// incomplete policy is refused rather than accepted with a weakened ceremony.
func NewService(config Config) (*Service, error) {
	if len(config.Secret) < 32 || config.Registry == nil ||
		config.Policy.RelyingPartyID == "" || config.Policy.Origin == "" {
		return nil, ErrInvalid
	}
	maximum := config.MaxChallenges
	if maximum <= 0 {
		maximum = MaximumChallenges
	}
	source := config.Random
	if source == nil {
		source = rand.Reader
	}
	return &Service{
		secret:     append([]byte(nil), config.Secret...),
		registry:   config.Registry,
		policy:     config.Policy,
		maximum:    maximum,
		random:     source,
		challenges: map[string]*challenge{},
	}, nil
}

// Challenge issues a fresh challenge bound to one session, action and endpoint
// class. The binding is what stops an assertion earned for a low-value action
// from being presented for a high-value one.
func (s *Service) Challenge(sessionID, action, endpointClass string, now time.Time) (string, []byte, error) {
	if len(sessionID) < 8 || len(sessionID) > 128 || action == "" || endpointClass == "" {
		return "", nil, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked(now)
	if len(s.challenges) >= s.maximum {
		return "", nil, ErrCapacityExceeded
	}
	raw := make([]byte, ChallengeBytes)
	if _, err := io.ReadFull(s.random, raw); err != nil {
		return "", nil, ErrInvalid
	}
	identifier := make([]byte, 16)
	if _, err := io.ReadFull(s.random, identifier); err != nil {
		return "", nil, ErrInvalid
	}
	id := base64.RawURLEncoding.EncodeToString(identifier)
	s.challenges[id] = &challenge{
		sessionID: sessionID, action: action, endpointClass: endpointClass,
		value: raw, expiresAt: now.UTC().Add(ChallengeTTL),
	}
	return id, raw, nil
}

// Complete verifies one ceremony against the issued challenge and returns an
// attestation. The challenge is consumed whatever the outcome: a client that
// may retry against the same challenge could search for a credential that
// happens to verify.
func (s *Service) Complete(challengeID, sessionID string, assertion Assertion, now time.Time) (string, error) {
	s.mu.Lock()
	entry, present := s.challenges[challengeID]
	if present {
		delete(s.challenges, challengeID)
	}
	s.sweepLocked(now)
	s.mu.Unlock()

	if !present || !now.UTC().Before(entry.expiresAt) {
		return "", ErrNotFound
	}
	if subtle.ConstantTimeCompare([]byte(entry.sessionID), []byte(sessionID)) != 1 {
		return "", ErrNotFound
	}
	credential, registered := s.registry.Credential(assertion.CredentialID, sessionID)
	if !registered {
		return "", ErrUnknownCredential
	}
	result, err := Verify(assertion, credential, s.policy, entry.value, now)
	if err != nil {
		return "", err
	}
	s.registry.RecordSignCount(credential.ID, result.SignCount)
	return s.attest(entry.sessionID, entry.action, entry.endpointClass, now), nil
}

// VerifyAttestation checks that a completed ceremony is presented for the same
// session, action and endpoint class it was earned on, inside its lifetime.
func (s *Service) VerifyAttestation(attestation, sessionID, action, endpointClass string, now time.Time) error {
	raw, err := base64.RawURLEncoding.DecodeString(attestation)
	if err != nil || len(raw) != sha256.Size+8 {
		return ErrAttestationInvalid
	}
	issued := time.Unix(int64(decodeUint64(raw[sha256.Size:])), 0).UTC()
	if issued.After(now.UTC().Add(time.Minute)) || !now.UTC().Before(issued.Add(AttestationTTL)) {
		return ErrAttestationInvalid
	}
	expected := s.attestationMAC(sessionID, action, endpointClass, issued)
	if subtle.ConstantTimeCompare(raw[:sha256.Size], expected) != 1 {
		return ErrAttestationInvalid
	}
	return nil
}

// RelyingPartyID is the scope a client must run the ceremony under. It is
// disclosed with the challenge so a client does not have to be configured
// separately from the deployment.
func (s *Service) RelyingPartyID() string { return s.policy.RelyingPartyID }

// Outstanding reports how many challenges are in flight.
func (s *Service) Outstanding() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.challenges)
}

// Sweep drops expired challenges and reports how many were removed.
func (s *Service) Sweep(now time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sweepLocked(now)
}

func (s *Service) sweepLocked(now time.Time) int {
	removed := 0
	for id, entry := range s.challenges {
		if !now.UTC().Before(entry.expiresAt) {
			delete(s.challenges, id)
			removed++
		}
	}
	return removed
}

func (s *Service) attest(sessionID, action, endpointClass string, now time.Time) string {
	issued := now.UTC().Truncate(time.Second)
	mac := s.attestationMAC(sessionID, action, endpointClass, issued)
	raw := make([]byte, 0, sha256.Size+8)
	raw = append(raw, mac...)
	raw = append(raw, encodeUint64(uint64(issued.Unix()))...)
	return base64.RawURLEncoding.EncodeToString(raw)
}

func (s *Service) attestationMAC(sessionID, action, endpointClass string, issued time.Time) []byte {
	mac := hmac.New(sha256.New, s.secret)
	mac.Write([]byte(attestationContext))
	for _, part := range []string{sessionID, action, endpointClass} {
		mac.Write([]byte(part))
		mac.Write([]byte{0})
	}
	mac.Write(encodeUint64(uint64(issued.Unix())))
	return mac.Sum(nil)
}

func encodeUint64(value uint64) []byte {
	raw := make([]byte, 8)
	for index := 7; index >= 0; index-- {
		raw[index] = byte(value)
		value >>= 8
	}
	return raw
}

func decodeUint64(raw []byte) uint64 {
	value := uint64(0)
	for _, part := range raw {
		value = value<<8 | uint64(part)
	}
	return value
}
