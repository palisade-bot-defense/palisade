// Package issuertrust verifies the signed, expiring local record of which
// external credential issuers a deployment accepts.
//
// PALISADE verifies issuer assertions and never issues them, so this list is
// the complete trust root for issuer-backed assurance. It is distributed as a
// file and verified offline, reusing the pattern already proven by the signed
// crawler registry: no issuer lookup, no revocation fetch and no network call
// happens while a request is handled. Revocation is delivered by reissuing the
// list with a short validity window, which is why an expired list degrades
// every issuer to untrusted instead of remaining in force.
package issuertrust

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"regexp"
	"sync"
	"time"

	"github.com/palisade-human-trust/palisade/pkg/palisadeassurance"
)

const (
	// SchemaVersion identifies the frozen trust-list contract.
	SchemaVersion = "palisade.issuer-trust-list.v1"

	// MaximumDocumentBytes bounds an encoded trust list.
	MaximumDocumentBytes = 512 << 10
	// MaximumLifetime keeps the revocation window short. A longer window would
	// widen the period in which a revoked credential still verifies.
	MaximumLifetime = 24 * time.Hour
	// MaximumClockSkew tolerates a small difference between the publisher and
	// the deployment.
	MaximumClockSkew = 5 * time.Minute

	maximumIssuers  = 64
	maximumRevoked  = 4096
	domainSeparator = "PALISADE\x00ISSUER-TRUST-LIST\x00V1\x00"
)

var (
	// ErrInvalid covers every structural, vocabulary and signature failure.
	ErrInvalid = errors.New("invalid issuer trust list")
	// ErrExpired reports a list that is no longer valid at the supplied time.
	// Callers must treat every issuer as untrusted, never as still accepted.
	ErrExpired = errors.New("expired issuer trust list")
	// ErrRollback reports a list whose revision did not increase.
	ErrRollback = errors.New("issuer trust list revision did not increase")

	issuerID  = regexp.MustCompile(`^[a-z0-9][a-z0-9._:-]{2,63}$`)
	base64Key = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

	uniquenessScopes = map[string]struct{}{"none": {}, "device": {}, "issuer": {}}
	purposes         = map[string]struct{}{
		"human_presence": {}, "workforce": {}, "age_assurance": {},
		"sector_credential": {}, "other": {},
	}
)

// Issuer is one accepted external credential issuer.
type Issuer struct {
	IssuerID              string `json:"issuer_id"`
	PublicKey             string `json:"public_key"`
	MaximumAssuranceLevel int    `json:"maximum_assurance_level"`
	UniquenessScope       string `json:"uniqueness_scope"`
	Purpose               string `json:"purpose"`
}

// Payload is the signed content of a trust list.
type Payload struct {
	SchemaVersion      string   `json:"schema_version"`
	Revision           uint64   `json:"revision"`
	IssuedAt           string   `json:"issued_at"`
	ExpiresAt          string   `json:"expires_at"`
	Issuers            []Issuer `json:"issuers"`
	RevokedCredentials []string `json:"revoked_credentials"`
}

// Document is the encoded trust list as distributed to a deployment.
type Document struct {
	Payload   Payload `json:"payload"`
	Signature string  `json:"signature"`
}

// Decision is the outcome of asking the trust list about one issuer.
type Decision struct {
	// Trusted reports whether the issuer may back an assurance claim at all.
	Trusted bool
	// MaximumAssuranceLevel is the ceiling the deployment grants this issuer,
	// already clamped to what this implementation can verify.
	MaximumAssuranceLevel int
	// UniquenessScope is the strongest uniqueness the issuer may assert.
	UniquenessScope string
	// Purpose records what the issuer was assessed to verify.
	Purpose string
}

// Untrusted is the answer whenever the list is absent, expired or silent about
// an issuer. It is the zero value on purpose: forgetting to check still fails
// closed.
var Untrusted = Decision{Trusted: false, MaximumAssuranceLevel: palisadeassurance.LevelUnattributed, UniquenessScope: "none"}

// Store holds the currently accepted trust list. It is safe for concurrent use
// and performs no I/O of its own; the deployment supplies the document.
type Store struct {
	publisherKey ed25519.PublicKey

	mu       sync.RWMutex
	revision uint64
	payload  Payload
	issuers  map[string]Issuer
	revoked  map[string]struct{}
	expires  time.Time
}

// NewStore binds a store to the publisher key that signs trust lists. The
// private half stays with the offline or deployment-controlled publisher.
func NewStore(publisherKey ed25519.PublicKey) (*Store, error) {
	if len(publisherKey) != ed25519.PublicKeySize {
		return nil, ErrInvalid
	}
	return &Store{
		publisherKey: append(ed25519.PublicKey(nil), publisherKey...),
		issuers:      map[string]Issuer{},
		revoked:      map[string]struct{}{},
	}, nil
}

// Sign produces an encoded trust list. It exists so a publisher and the
// conformance fixtures share exactly one encoding.
func Sign(payload Payload, privateKey ed25519.PrivateKey) ([]byte, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, ErrInvalid
	}
	payload.SchemaVersion = SchemaVersion
	payload.Issuers = issuersOrEmpty(payload.Issuers)
	payload.RevokedCredentials = stringsOrEmpty(payload.RevokedCredentials)
	if err := validatePayload(payload); err != nil {
		return nil, err
	}
	canonical, err := json.Marshal(payload)
	if err != nil {
		return nil, ErrInvalid
	}
	document := Document{
		Payload:   payload,
		Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, signingMessage(canonical))),
	}
	encoded, err := json.Marshal(document)
	if err != nil || len(encoded) > MaximumDocumentBytes {
		return nil, ErrInvalid
	}
	return encoded, nil
}

// Update verifies a trust list and, when it is newer than the stored one,
// installs it. A rollback, an expired list or any structural failure leaves the
// previous state untouched.
func (s *Store) Update(encoded []byte, now time.Time) error {
	payload, err := s.verify(encoded, now)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if payload.Revision <= s.revision {
		return ErrRollback
	}
	issuers := make(map[string]Issuer, len(payload.Issuers))
	for _, issuer := range payload.Issuers {
		issuers[issuer.IssuerID] = issuer
	}
	revoked := make(map[string]struct{}, len(payload.RevokedCredentials))
	for _, commitment := range payload.RevokedCredentials {
		revoked[commitment] = struct{}{}
	}
	expires, err := canonicalTime(payload.ExpiresAt)
	if err != nil {
		return ErrInvalid
	}
	s.revision, s.payload, s.issuers, s.revoked, s.expires = payload.Revision, payload, issuers, revoked, expires
	return nil
}

// Evaluate answers what one issuer may back at the supplied time. It returns
// Untrusted when no list is installed, when the installed list has expired,
// when the issuer is absent, or when the presented credential commitment is
// revoked.
func (s *Store) Evaluate(issuerID, credentialCommitment string, now time.Time) Decision {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.revision == 0 || !s.expires.After(now.UTC()) {
		return Untrusted
	}
	issuer, known := s.issuers[issuerID]
	if !known {
		return Untrusted
	}
	if _, isRevoked := s.revoked[credentialCommitment]; isRevoked {
		return Untrusted
	}
	level := issuer.MaximumAssuranceLevel
	if level > palisadeassurance.MaximumSupportedLevel {
		// The deployment may grant a higher ceiling than this build can verify.
		// Clamping here means a trust list can be written for the future
		// without silently granting assurance nothing checks today.
		level = palisadeassurance.MaximumSupportedLevel
	}
	return Decision{
		Trusted:               true,
		MaximumAssuranceLevel: level,
		UniquenessScope:       issuer.UniquenessScope,
		Purpose:               issuer.Purpose,
	}
}

// Revision reports the installed revision, or zero when no list is installed.
func (s *Store) Revision() uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.revision
}

// Expired reports whether the installed list has lapsed. A deployment should
// alert on this: it means issuer-backed assurance is silently unavailable.
func (s *Store) Expired(now time.Time) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.revision == 0 || !s.expires.After(now.UTC())
}

func (s *Store) verify(encoded []byte, now time.Time) (Payload, error) {
	if len(encoded) == 0 || len(encoded) > MaximumDocumentBytes {
		return Payload{}, ErrInvalid
	}
	if err := requireCompleteDocument(encoded); err != nil {
		return Payload{}, err
	}
	var document Document
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil || decoder.More() {
		return Payload{}, ErrInvalid
	}
	if err := validatePayload(document.Payload); err != nil {
		return Payload{}, err
	}
	signature, err := base64.RawURLEncoding.DecodeString(document.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return Payload{}, ErrInvalid
	}
	canonical, err := json.Marshal(document.Payload)
	if err != nil || !ed25519.Verify(s.publisherKey, signingMessage(canonical), signature) {
		return Payload{}, ErrInvalid
	}
	issuedAt, err := canonicalTime(document.Payload.IssuedAt)
	if err != nil || issuedAt.After(now.UTC().Add(MaximumClockSkew)) {
		return Payload{}, ErrInvalid
	}
	expiresAt, err := canonicalTime(document.Payload.ExpiresAt)
	if err != nil {
		return Payload{}, ErrInvalid
	}
	if !expiresAt.After(now.UTC()) {
		return Payload{}, ErrExpired
	}
	return document.Payload, nil
}

func validatePayload(payload Payload) error {
	if payload.SchemaVersion != SchemaVersion || payload.Revision == 0 {
		return ErrInvalid
	}
	issuedAt, err := canonicalTime(payload.IssuedAt)
	if err != nil {
		return ErrInvalid
	}
	expiresAt, err := canonicalTime(payload.ExpiresAt)
	if err != nil || !expiresAt.After(issuedAt) || expiresAt.Sub(issuedAt) > MaximumLifetime {
		return ErrInvalid
	}
	if len(payload.Issuers) > maximumIssuers || len(payload.RevokedCredentials) > maximumRevoked {
		return ErrInvalid
	}
	seenIssuer := make(map[string]struct{}, len(payload.Issuers))
	seenKey := make(map[string]struct{}, len(payload.Issuers))
	for _, issuer := range payload.Issuers {
		if !issuerID.MatchString(issuer.IssuerID) || !base64Key.MatchString(issuer.PublicKey) {
			return ErrInvalid
		}
		if issuer.MaximumAssuranceLevel < palisadeassurance.LevelUnattributed ||
			issuer.MaximumAssuranceLevel > palisadeassurance.MaximumSpecifiedLevel {
			return ErrInvalid
		}
		if _, known := uniquenessScopes[issuer.UniquenessScope]; !known {
			return ErrInvalid
		}
		if _, known := purposes[issuer.Purpose]; !known {
			return ErrInvalid
		}
		// An issuer that may assert uniqueness must be granted a level that can
		// carry it, otherwise the two statements contradict each other.
		if issuer.UniquenessScope != "none" && issuer.MaximumAssuranceLevel < palisadeassurance.LevelAttestedDevice {
			return ErrInvalid
		}
		if _, duplicate := seenIssuer[issuer.IssuerID]; duplicate {
			return ErrInvalid
		}
		if _, duplicate := seenKey[issuer.PublicKey]; duplicate {
			return ErrInvalid
		}
		seenIssuer[issuer.IssuerID] = struct{}{}
		seenKey[issuer.PublicKey] = struct{}{}
	}
	seenRevoked := make(map[string]struct{}, len(payload.RevokedCredentials))
	for _, commitment := range payload.RevokedCredentials {
		if !base64Key.MatchString(commitment) {
			return ErrInvalid
		}
		if _, duplicate := seenRevoked[commitment]; duplicate {
			return ErrInvalid
		}
		seenRevoked[commitment] = struct{}{}
	}
	return nil
}

func requireCompleteDocument(encoded []byte) error {
	var document map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &document); err != nil {
		return ErrInvalid
	}
	if err := requireFields(document, "payload", "signature"); err != nil {
		return err
	}
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(document["payload"], &payload); err != nil {
		return ErrInvalid
	}
	return requireFields(payload,
		"schema_version", "revision", "issued_at", "expires_at", "issuers", "revoked_credentials")
}

func requireFields(object map[string]json.RawMessage, names ...string) error {
	if len(object) != len(names) {
		return ErrInvalid
	}
	for _, name := range names {
		value, present := object[name]
		if !present || len(value) == 0 || string(value) == "null" {
			return ErrInvalid
		}
	}
	return nil
}

func canonicalTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil || parsed.Location() != time.UTC || parsed.Format(time.RFC3339) != value {
		return time.Time{}, ErrInvalid
	}
	return parsed, nil
}

func signingMessage(canonical []byte) []byte {
	message := make([]byte, 0, len(domainSeparator)+len(canonical))
	message = append(message, domainSeparator...)
	return append(message, canonical...)
}

func issuersOrEmpty(values []Issuer) []Issuer {
	if values == nil {
		return []Issuer{}
	}
	return values
}

func stringsOrEmpty(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}
