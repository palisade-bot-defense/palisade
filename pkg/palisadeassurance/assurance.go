// Package palisadeassurance defines the closed human-assurance assertion that
// PALISADE emits to a relying service. An assertion states how much verified
// human evidence backed one interaction. It deliberately carries no subject
// identity, biometric material, device identifier or cross-site identifier, and
// it is bound to a single audience, session, action and endpoint class for a
// few minutes at most.
//
// The specified ladder reaches LevelIssuerUnique. This implementation supports
// only what it can itself verify today, which is MaximumSupportedLevel. Signing
// or accepting a higher level fails rather than making a claim no mechanism in
// this repository can back.
package palisadeassurance

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"time"
)

const (
	// SchemaVersion identifies the frozen assertion contract.
	SchemaVersion = "palisade.human-assurance-assertion.v1"

	// LevelUnattributed carries no human evidence at all.
	LevelUnattributed = 0
	// LevelBehavioral means PALISADE verified bounded interaction evidence
	// against its own event store.
	LevelBehavioral = 1
	// LevelInteractive additionally requires a completed interactive liveness
	// challenge. No such challenge exists in this repository: the current
	// proof-of-work challenge is a cost and outcome signal that browser
	// automation may complete routinely.
	LevelInteractive = 2
	// LevelAttestedDevice additionally requires a hardware-attested key bound
	// to the session. Not implemented.
	LevelAttestedDevice = 3
	// LevelIssuerVerified additionally requires an external issuer's assertion
	// of verified liveness at enrolment. Not implemented.
	LevelIssuerVerified = 4
	// LevelIssuerUnique additionally requires an external issuer's assertion of
	// uniqueness within a declared scope. Not implemented.
	LevelIssuerUnique = 5

	// MaximumSpecifiedLevel is the top of the documented ladder.
	MaximumSpecifiedLevel = LevelIssuerUnique
	// MaximumSupportedLevel is the highest level this implementation can
	// produce or accept. Raising it requires a mechanism that positively
	// verifies the added evidence class, not a constant change.
	MaximumSupportedLevel = LevelBehavioral

	// MaximumLifetime bounds how long an assertion stays valid. It matches the
	// existing short-lived proof-token bound.
	MaximumLifetime = 5 * time.Minute
	// MaximumClockSkew tolerates a small clock difference between the emitting
	// deployment and the relying service.
	MaximumClockSkew = 30 * time.Second
	// MaximumDocumentBytes bounds an encoded assertion.
	MaximumDocumentBytes = 8 << 10

	domainSeparator = "PALISADE\x00HUMAN-ASSURANCE-ASSERTION\x00V1\x00"
	bindingContext  = "PALISADE\x00ASSURANCE-SESSION-BINDING\x00V1\x00"
)

var (
	// ErrInvalid covers every structural, vocabulary, binding, signature and
	// consistency failure. Callers must not branch on the specific cause.
	ErrInvalid = errors.New("invalid human assurance assertion")
	// ErrExpired reports an assertion that is structurally sound but no longer
	// valid at the supplied time.
	ErrExpired = errors.New("expired human assurance assertion")
	// ErrUnsupportedLevel reports a level this implementation cannot verify.
	ErrUnsupportedLevel = errors.New("unsupported human assurance level")

	stableVersion = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{2,63}$`)
	reasonCode    = regexp.MustCompile(`^[a-z][a-z0-9_]{2,63}$`)
	audienceValue = regexp.MustCompile(`^[a-z0-9][a-z0-9._:-]{0,127}$`)

	assuranceSources = []string{"behavioral", "challenge", "device", "issuer"}
	uniquenessScopes = []string{"none", "device", "issuer"}
	agentProvenances = []string{"none", "declared", "authorized", "verified_purpose"}
	requestActions   = []string{
		"read", "write", "create", "update", "delete", "search", "compare",
		"login", "logout", "register", "checkout", "purchase", "other",
	}
	endpointClasses = []string{
		"public_content", "compare_index", "compare_noindex", "challenge_worker",
		"other_public", "account", "login", "checkout", "other",
	}

	// requiredSources records the evidence class each level adds. A level is
	// only well formed when every class up to it is present.
	requiredSources = map[int][]string{
		LevelUnattributed:   {},
		LevelBehavioral:     {"behavioral"},
		LevelInteractive:    {"behavioral", "challenge"},
		LevelAttestedDevice: {"behavioral", "challenge", "device"},
		LevelIssuerVerified: {"behavioral", "challenge", "device", "issuer"},
		LevelIssuerUnique:   {"behavioral", "challenge", "device", "issuer"},
	}
)

// AssuranceSources returns the closed evidence-class vocabulary.
func AssuranceSources() []string { return clone(assuranceSources) }

// UniquenessScopes returns the closed uniqueness vocabulary. Global personhood
// is deliberately absent.
func UniquenessScopes() []string { return clone(uniquenessScopes) }

// AgentProvenances returns the closed agent-identification vocabulary.
func AgentProvenances() []string { return clone(agentProvenances) }

// Binding ties an assertion to exactly one audience, session, action and
// endpoint class.
type Binding struct {
	SessionBinding string `json:"session_binding"`
	RequestAction  string `json:"request_action"`
	EndpointClass  string `json:"endpoint_class"`
	Audience       string `json:"audience"`
}

// Payload is the signed content of an assertion.
type Payload struct {
	SchemaVersion    string   `json:"schema_version"`
	AssuranceLevel   int      `json:"assurance_level"`
	AssuranceSources []string `json:"assurance_sources"`
	ReasonCodes      []string `json:"reason_codes"`
	UniquenessScope  string   `json:"uniqueness_scope"`
	AgentProvenance  string   `json:"agent_provenance"`
	Binding          Binding  `json:"binding"`
	PolicyVersion    string   `json:"policy_version"`
	ModelVersion     string   `json:"model_version"`
	IssuedAt         string   `json:"issued_at"`
	ExpiresAt        string   `json:"expires_at"`
	Nonce            string   `json:"nonce"`
}

// Assertion is the encoded document exchanged with a relying service.
type Assertion struct {
	Payload   Payload `json:"payload"`
	KeyID     string  `json:"key_id"`
	Signature string  `json:"signature"`
}

// Verified reports an accepted assertion and its parsed validity window.
type Verified struct {
	Payload   Payload
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// SessionBinding derives the opaque per-audience session commitment. The same
// session produces a different value for every audience, so two relying
// services cannot link the same visitor by comparing assertions. The secret
// never leaves the emitting deployment.
func SessionBinding(secret []byte, sessionID, audience string) (string, error) {
	if len(secret) < 32 || len(sessionID) < 8 || len(sessionID) > 128 || !audienceValue.MatchString(audience) {
		return "", ErrInvalid
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(bindingContext))
	mac.Write([]byte(audience))
	mac.Write([]byte{0})
	mac.Write([]byte(sessionID))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

// KeyID identifies the signing key without revealing it.
func KeyID(publicKey ed25519.PublicKey) string {
	digest := sha256.Sum256(publicKey)
	return hex.EncodeToString(digest[:8])
}

// Sign produces an encoded assertion. It refuses any level above
// MaximumSupportedLevel: this deployment must not state more than it verified.
func Sign(payload Payload, ttl time.Duration, now time.Time, privateKey ed25519.PrivateKey) ([]byte, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, ErrInvalid
	}
	if ttl <= 0 || ttl > MaximumLifetime {
		return nil, ErrInvalid
	}
	issuedAt := now.UTC().Truncate(time.Second)
	payload.SchemaVersion = SchemaVersion
	payload.IssuedAt = issuedAt.Format(time.RFC3339)
	payload.ExpiresAt = issuedAt.Add(ttl).Format(time.RFC3339)
	nonce, err := newNonce()
	if err != nil {
		return nil, err
	}
	payload.Nonce = nonce
	if err := validatePayload(payload); err != nil {
		return nil, err
	}
	if payload.AssuranceLevel > MaximumSupportedLevel {
		return nil, ErrUnsupportedLevel
	}
	canonical, err := json.Marshal(payload)
	if err != nil {
		return nil, ErrInvalid
	}
	publicKey, ok := privateKey.Public().(ed25519.PublicKey)
	if !ok {
		return nil, ErrInvalid
	}
	document := Assertion{
		Payload:   payload,
		KeyID:     KeyID(publicKey),
		Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, signingMessage(canonical))),
	}
	encoded, err := json.Marshal(document)
	if err != nil || len(encoded) > MaximumDocumentBytes {
		return nil, ErrInvalid
	}
	return encoded, nil
}

// Verifier accepts assertions signed by one key for one audience. It is
// stateless and performs no network call, no lookup and no clock read of its
// own: the caller supplies the evaluation time.
type Verifier struct {
	publicKey ed25519.PublicKey
	keyID     string
	audience  string
}

// NewVerifier binds a verifier to one signing key and one relying-party scope.
func NewVerifier(publicKey ed25519.PublicKey, audience string) (*Verifier, error) {
	if len(publicKey) != ed25519.PublicKeySize || !audienceValue.MatchString(audience) {
		return nil, ErrInvalid
	}
	return &Verifier{
		publicKey: append(ed25519.PublicKey(nil), publicKey...),
		keyID:     KeyID(publicKey),
		audience:  audience,
	}, nil
}

// Verify checks structure, vocabulary, binding, signature and validity window.
// It rejects any level this implementation cannot itself verify, so a forged or
// optimistic high-level assertion fails closed instead of being trusted.
func (v *Verifier) Verify(encoded []byte, now time.Time) (Verified, error) {
	if len(encoded) == 0 || len(encoded) > MaximumDocumentBytes {
		return Verified{}, ErrInvalid
	}
	var document Assertion
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil || decoder.More() {
		return Verified{}, ErrInvalid
	}
	if err := validatePayload(document.Payload); err != nil {
		return Verified{}, err
	}
	if document.Payload.Binding.Audience != v.audience || document.KeyID != v.keyID {
		return Verified{}, ErrInvalid
	}
	signature, err := base64.RawURLEncoding.DecodeString(document.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return Verified{}, ErrInvalid
	}
	canonical, err := json.Marshal(document.Payload)
	if err != nil || !ed25519.Verify(v.publicKey, signingMessage(canonical), signature) {
		return Verified{}, ErrInvalid
	}
	issuedAt, expiresAt, err := validityWindow(document.Payload, now)
	if err != nil {
		return Verified{}, err
	}
	if document.Payload.AssuranceLevel > MaximumSupportedLevel {
		return Verified{}, ErrUnsupportedLevel
	}
	return Verified{Payload: document.Payload, IssuedAt: issuedAt, ExpiresAt: expiresAt}, nil
}

// Satisfies reports whether an accepted assertion meets a relying service's
// minimum. Insufficient assurance is an ordinary policy input, not an error.
func (v Verified) Satisfies(minimumLevel int, requireUnique bool) bool {
	if v.Payload.AssuranceLevel < minimumLevel {
		return false
	}
	return !requireUnique || v.Payload.UniquenessScope != "none"
}

func validatePayload(payload Payload) error {
	if payload.SchemaVersion != SchemaVersion {
		return ErrInvalid
	}
	if payload.AssuranceLevel < LevelUnattributed || payload.AssuranceLevel > MaximumSpecifiedLevel {
		return ErrInvalid
	}
	if !stableVersion.MatchString(payload.PolicyVersion) || !stableVersion.MatchString(payload.ModelVersion) {
		return ErrInvalid
	}
	if !contains(uniquenessScopes, payload.UniquenessScope) || !contains(agentProvenances, payload.AgentProvenance) {
		return ErrInvalid
	}
	if len(payload.Nonce) != 22 || !isBase64URL(payload.Nonce) {
		return ErrInvalid
	}
	if err := validateSources(payload); err != nil {
		return err
	}
	if err := validateReasonCodes(payload.ReasonCodes); err != nil {
		return err
	}
	if err := validateBinding(payload.Binding); err != nil {
		return err
	}
	// Uniqueness is an issuer property. A deployment cannot assert a distinct
	// subject without the evidence class that establishes one.
	if payload.UniquenessScope == "issuer" && !contains(payload.AssuranceSources, "issuer") {
		return ErrInvalid
	}
	if payload.UniquenessScope == "device" && !contains(payload.AssuranceSources, "device") {
		return ErrInvalid
	}
	return nil
}

func validateSources(payload Payload) error {
	if len(payload.AssuranceSources) > len(assuranceSources) {
		return ErrInvalid
	}
	seen := make(map[string]struct{}, len(payload.AssuranceSources))
	for _, source := range payload.AssuranceSources {
		if !contains(assuranceSources, source) {
			return ErrInvalid
		}
		if _, duplicate := seen[source]; duplicate {
			return ErrInvalid
		}
		seen[source] = struct{}{}
	}
	for _, required := range requiredSources[payload.AssuranceLevel] {
		if _, present := seen[required]; !present {
			return ErrInvalid
		}
	}
	return nil
}

func validateReasonCodes(codes []string) error {
	if len(codes) > 16 {
		return ErrInvalid
	}
	seen := make(map[string]struct{}, len(codes))
	for _, code := range codes {
		if !reasonCode.MatchString(code) {
			return ErrInvalid
		}
		if _, duplicate := seen[code]; duplicate {
			return ErrInvalid
		}
		seen[code] = struct{}{}
	}
	return nil
}

func validateBinding(binding Binding) error {
	if len(binding.SessionBinding) != 43 || !isBase64URL(binding.SessionBinding) {
		return ErrInvalid
	}
	if !contains(requestActions, binding.RequestAction) || !contains(endpointClasses, binding.EndpointClass) {
		return ErrInvalid
	}
	if !audienceValue.MatchString(binding.Audience) {
		return ErrInvalid
	}
	return nil
}

func validityWindow(payload Payload, now time.Time) (time.Time, time.Time, error) {
	issuedAt, err := canonicalTime(payload.IssuedAt)
	if err != nil {
		return time.Time{}, time.Time{}, ErrInvalid
	}
	expiresAt, err := canonicalTime(payload.ExpiresAt)
	if err != nil || !expiresAt.After(issuedAt) || expiresAt.Sub(issuedAt) > MaximumLifetime {
		return time.Time{}, time.Time{}, ErrInvalid
	}
	if issuedAt.After(now.UTC().Add(MaximumClockSkew)) {
		return time.Time{}, time.Time{}, ErrInvalid
	}
	if !expiresAt.After(now.UTC()) {
		return time.Time{}, time.Time{}, ErrExpired
	}
	return issuedAt, expiresAt, nil
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

func newNonce() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", ErrInvalid
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func isBase64URL(value string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) > 0
}

func contains(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

func clone(values []string) []string {
	return append([]string(nil), values...)
}
