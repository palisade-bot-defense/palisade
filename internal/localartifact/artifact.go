package localartifact

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"sync"
	"time"
)

const (
	SchemaVersion = "palisade.local-artifact.v1"
	TypePolicy    = "policy_bundle"
	TypeDetector  = "detector_bundle"

	MaximumDocumentBytes = 64 << 10
	MaximumLifetime      = 31 * 24 * time.Hour
	MaximumClockSkew     = 5 * time.Minute
)

var (
	ErrInvalid   = errors.New("invalid local artifact")
	ErrExpired   = errors.New("local artifact expired")
	ErrRollback  = errors.New("local artifact revision did not increase")
	ErrUnchanged = errors.New("local artifact document is unchanged")
	stableID     = regexp.MustCompile(`^[a-z0-9][a-z0-9_.:-]{2,63}$`)
)

type Metadata struct {
	SchemaVersion string `json:"schema_version"`
	ArtifactType  string `json:"artifact_type"`
	ArtifactID    string `json:"artifact_id"`
	Revision      uint64 `json:"revision"`
	IssuedAt      string `json:"issued_at"`
	ExpiresAt     string `json:"expires_at"`
	KeyID         string `json:"key_id"`
}

type Document struct {
	Metadata  Metadata        `json:"metadata"`
	Payload   json.RawMessage `json:"payload"`
	Signature string          `json:"signature"`
}

type Verified struct {
	Metadata     Metadata
	Payload      json.RawMessage
	DigestSHA256 string
	IssuedAt     time.Time
	ExpiresAt    time.Time
}

type Verifier struct {
	publicKey    ed25519.PublicKey
	expectedType string

	mu       sync.Mutex
	revision uint64
	digest   string
}

func NewVerifier(publicKey ed25519.PublicKey, expectedType string) (*Verifier, error) {
	if len(publicKey) != ed25519.PublicKeySize || !validType(expectedType) {
		return nil, ErrInvalid
	}
	return &Verifier{publicKey: append(ed25519.PublicKey(nil), publicKey...), expectedType: expectedType}, nil
}

func Sign(metadata Metadata, payload any, privateKey ed25519.PrivateKey) ([]byte, error) {
	if len(privateKey) != ed25519.PrivateKeySize || !validType(metadata.ArtifactType) {
		return nil, ErrInvalid
	}
	metadata.SchemaVersion = SchemaVersion
	metadata.KeyID = KeyID(privateKey.Public().(ed25519.PublicKey))
	payloadJSON, err := json.Marshal(payload)
	if err != nil || len(payloadJSON) == 0 {
		return nil, ErrInvalid
	}
	document := Document{Metadata: metadata, Payload: payloadJSON}
	canonical, err := canonical(document.Metadata, document.Payload)
	if err != nil {
		return nil, err
	}
	document.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, signingMessage(canonical)))
	encoded, err := json.Marshal(document)
	if err != nil || len(encoded) > MaximumDocumentBytes {
		return nil, ErrInvalid
	}
	return append(encoded, '\n'), nil
}

func (v *Verifier) VerifyAndAdvance(encoded []byte, now time.Time) (Verified, error) {
	if v == nil || len(v.publicKey) != ed25519.PublicKeySize || len(encoded) == 0 || len(encoded) > MaximumDocumentBytes {
		return Verified{}, ErrInvalid
	}
	document, canonical, err := decodeDocument(encoded)
	if err != nil {
		return Verified{}, err
	}
	issuedAt, expiresAt, err := validateMetadata(document.Metadata, v.expectedType, KeyID(v.publicKey), now.UTC())
	if err != nil {
		return Verified{}, err
	}
	signature, err := base64.RawURLEncoding.DecodeString(document.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize || base64.RawURLEncoding.EncodeToString(signature) != document.Signature ||
		!ed25519.Verify(v.publicKey, signingMessage(canonical), signature) {
		return Verified{}, ErrInvalid
	}
	digestBytes := sha256.Sum256(canonical)
	digest := hex.EncodeToString(digestBytes[:])
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.revision != 0 {
		if document.Metadata.Revision == v.revision && digest == v.digest {
			return Verified{}, ErrUnchanged
		}
		if document.Metadata.Revision <= v.revision {
			return Verified{}, ErrRollback
		}
	}
	v.revision = document.Metadata.Revision
	v.digest = digest
	return Verified{
		Metadata: document.Metadata, Payload: append(json.RawMessage(nil), document.Payload...), DigestSHA256: digest,
		IssuedAt: issuedAt, ExpiresAt: expiresAt,
	}, nil
}

func KeyID(publicKey ed25519.PublicKey) string {
	digest := sha256.Sum256(publicKey)
	return hex.EncodeToString(digest[:8])
}

func decodeDocument(encoded []byte) (Document, []byte, error) {
	var document Document
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return Document{}, nil, ErrInvalid
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Document{}, nil, ErrInvalid
	}
	if len(document.Payload) == 0 || len(document.Signature) != 86 {
		return Document{}, nil, ErrInvalid
	}
	canonical, err := canonical(document.Metadata, document.Payload)
	if err != nil {
		return Document{}, nil, ErrInvalid
	}
	return document, canonical, nil
}

func canonical(metadata Metadata, payload json.RawMessage) ([]byte, error) {
	return json.Marshal(struct {
		Metadata Metadata        `json:"metadata"`
		Payload  json.RawMessage `json:"payload"`
	}{Metadata: metadata, Payload: payload})
}

func signingMessage(canonical []byte) []byte {
	message := make([]byte, 0, len(canonical)+32)
	message = append(message, "PALISADE\x00LOCAL-ARTIFACT\x00V1\x00"...)
	return append(message, canonical...)
}

func validateMetadata(metadata Metadata, expectedType, expectedKeyID string, now time.Time) (time.Time, time.Time, error) {
	if metadata.SchemaVersion != SchemaVersion || metadata.ArtifactType != expectedType || !validType(metadata.ArtifactType) ||
		!stableID.MatchString(metadata.ArtifactID) || metadata.Revision == 0 || metadata.KeyID != expectedKeyID {
		return time.Time{}, time.Time{}, ErrInvalid
	}
	issuedAt, err := canonicalTime(metadata.IssuedAt)
	if err != nil || issuedAt.After(now.Add(MaximumClockSkew)) {
		return time.Time{}, time.Time{}, ErrInvalid
	}
	expiresAt, err := canonicalTime(metadata.ExpiresAt)
	if err != nil || !expiresAt.After(issuedAt) {
		return time.Time{}, time.Time{}, ErrInvalid
	}
	if !expiresAt.After(now) {
		return time.Time{}, time.Time{}, ErrExpired
	}
	if expiresAt.Sub(issuedAt) > MaximumLifetime {
		return time.Time{}, time.Time{}, ErrInvalid
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

func validType(value string) bool {
	return value == TypePolicy || value == TypeDetector
}
