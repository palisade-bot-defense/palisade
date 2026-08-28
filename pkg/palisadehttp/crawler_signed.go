package palisadehttp

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"time"
)

const (
	CrawlerRegistrySchemaVersion = "palisade.crawler-registry.v1"
	maxSignedCrawlerRegistrySize = 1 << 20
	maxCrawlerRegistryLifetime   = 31 * 24 * time.Hour
	maxCrawlerRegistryClockSkew  = 5 * time.Minute
	minCrawlerRegistryWatch      = 10 * time.Second
	maxCrawlerRegistryWatch      = 24 * time.Hour
)

var (
	ErrInvalidCrawlerRegistry   = errors.New("invalid crawler registry")
	ErrCrawlerRegistryExpired   = errors.New("crawler registry expired")
	ErrCrawlerRegistryRollback  = errors.New("crawler registry revision did not increase")
	ErrCrawlerRegistryUnchanged = errors.New("crawler registry document is unchanged")
)

type CrawlerRegistryPayload struct {
	SchemaVersion string            `json:"schema_version"`
	Revision      uint64            `json:"revision"`
	IssuedAt      string            `json:"issued_at"`
	ExpiresAt     string            `json:"expires_at"`
	Entries       []CrawlerIdentity `json:"entries"`
}

type SignedCrawlerRegistryDocument struct {
	Payload   CrawlerRegistryPayload `json:"payload"`
	Signature string                 `json:"signature"`
}

// CrawlerRegistryStatus contains no vendor identity, address or user-agent
// value and is safe for aggregate operational monitoring.
type CrawlerRegistryStatus struct {
	State         string    `json:"state"`
	Revision      uint64    `json:"revision"`
	IssuedAt      time.Time `json:"issued_at,omitempty"`
	ExpiresAt     time.Time `json:"expires_at,omitempty"`
	DigestSHA256  string    `json:"digest_sha256,omitempty"`
	IdentityCount int       `json:"identity_count"`
	PrefixCount   int       `json:"prefix_count"`
}

type CrawlerRegistryReloadEvent struct {
	State  string                `json:"state"`
	Reason string                `json:"reason"`
	Status CrawlerRegistryStatus `json:"status"`
}

// NewSignedCrawlerRegistry creates an initially empty fail-closed registry.
// UpdateSignedJSON or UpdateSignedFile must install a verified snapshot before
// any crawler can qualify.
func NewSignedCrawlerRegistry(publicKey ed25519.PublicKey) (*CrawlerRegistry, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return nil, ErrInvalidCrawlerRegistry
	}
	key := append([]byte(nil), publicKey...)
	return &CrawlerRegistry{verificationKey: key}, nil
}

// EncodeSignedCrawlerRegistry deterministically signs the payload. It is
// intended for an offline publisher; production verifier processes need only
// the public key.
func EncodeSignedCrawlerRegistry(payload CrawlerRegistryPayload, privateKey ed25519.PrivateKey) ([]byte, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, ErrInvalidCrawlerRegistry
	}
	canonical, err := json.Marshal(payload)
	if err != nil {
		return nil, ErrInvalidCrawlerRegistry
	}
	document := SignedCrawlerRegistryDocument{
		Payload:   payload,
		Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, canonical)),
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		return nil, ErrInvalidCrawlerRegistry
	}
	return append(encoded, '\n'), nil
}

// UpdateSignedJSON verifies a complete snapshot before one atomic pointer
// swap. Invalid, expired, non-increasing or partially written updates leave the
// last known-good in-process snapshot untouched.
func (r *CrawlerRegistry) UpdateSignedJSON(encoded []byte, now time.Time) error {
	if r == nil || len(r.verificationKey) != ed25519.PublicKeySize || len(encoded) == 0 || len(encoded) > maxSignedCrawlerRegistrySize {
		return ErrInvalidCrawlerRegistry
	}
	var document SignedCrawlerRegistryDocument
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return ErrInvalidCrawlerRegistry
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return ErrInvalidCrawlerRegistry
	}
	canonical, err := json.Marshal(document.Payload)
	if err != nil {
		return ErrInvalidCrawlerRegistry
	}
	signature, err := base64.RawURLEncoding.DecodeString(document.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize ||
		base64.RawURLEncoding.EncodeToString(signature) != document.Signature ||
		!ed25519.Verify(ed25519.PublicKey(r.verificationKey), canonical, signature) {
		return ErrInvalidCrawlerRegistry
	}
	issuedAt, expiresAt, err := validateCrawlerRegistryPayload(document.Payload, now.UTC())
	if err != nil {
		return err
	}
	snapshot, err := buildCrawlerSnapshot(document.Payload.Entries)
	if err != nil {
		return err
	}
	snapshot.revision = document.Payload.Revision
	snapshot.issuedAt = issuedAt
	snapshot.expiresAt = expiresAt
	digest := sha256.Sum256(canonical)
	snapshot.digest = hex.EncodeToString(digest[:])
	for {
		current := r.signed.Load()
		if current != nil {
			if snapshot.revision == current.revision && snapshot.digest == current.digest {
				return ErrCrawlerRegistryUnchanged
			}
			if snapshot.revision <= current.revision {
				return ErrCrawlerRegistryRollback
			}
		}
		if r.signed.CompareAndSwap(current, snapshot) {
			return nil
		}
	}
}

func (r *CrawlerRegistry) UpdateSignedFile(path string, now time.Time) error {
	file, err := os.Open(path)
	if err != nil {
		return ErrInvalidCrawlerRegistry
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > maxSignedCrawlerRegistrySize {
		return ErrInvalidCrawlerRegistry
	}
	encoded, err := io.ReadAll(io.LimitReader(file, maxSignedCrawlerRegistrySize+1))
	if err != nil || len(encoded) > maxSignedCrawlerRegistrySize {
		return ErrInvalidCrawlerRegistry
	}
	return r.UpdateSignedJSON(encoded, now)
}

// WatchSignedFile reloads a local deployment-managed file outside the request
// hot path. Startup requires one valid document. Later failures are reported
// through closed events while the last known-good snapshot remains active only
// until its signed expiry.
func (r *CrawlerRegistry) WatchSignedFile(ctx context.Context, path string, interval time.Duration, observe func(CrawlerRegistryReloadEvent)) error {
	if ctx == nil || interval < minCrawlerRegistryWatch || interval > maxCrawlerRegistryWatch {
		return ErrInvalidCrawlerRegistry
	}
	now := time.Now().UTC()
	err := r.UpdateSignedFile(path, now)
	event := CrawlerRegistryReloadEvent{State: "updated", Reason: "accepted", Status: r.Status(now)}
	if errors.Is(err, ErrCrawlerRegistryUnchanged) {
		event.State = "unchanged"
		event.Reason = "same_document"
	} else if err != nil {
		return err
	}
	emitCrawlerReload(observe, event)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case checkedAt := <-ticker.C:
			err := r.UpdateSignedFile(path, checkedAt.UTC())
			event := CrawlerRegistryReloadEvent{State: "updated", Reason: "accepted", Status: r.Status(checkedAt.UTC())}
			if errors.Is(err, ErrCrawlerRegistryUnchanged) {
				event.State = "unchanged"
				event.Reason = "same_document"
			} else if err != nil {
				event.State = "rejected"
				event.Reason = crawlerReloadReason(err)
				if event.Status.State == "expired" {
					event.State = "expired"
				}
			}
			emitCrawlerReload(observe, event)
		}
	}
}

func crawlerReloadReason(err error) string {
	switch {
	case errors.Is(err, ErrCrawlerRegistryExpired):
		return "expired_document"
	case errors.Is(err, ErrCrawlerRegistryRollback):
		return "non_increasing_revision"
	default:
		return "invalid_document"
	}
}

func emitCrawlerReload(observe func(CrawlerRegistryReloadEvent), event CrawlerRegistryReloadEvent) {
	if observe != nil {
		observe(event)
	}
}

func (r *CrawlerRegistry) Status(now time.Time) CrawlerRegistryStatus {
	if r == nil {
		return CrawlerRegistryStatus{State: "empty"}
	}
	if r.static != nil {
		return statusFromCrawlerSnapshot("static", r.static)
	}
	snapshot := r.signed.Load()
	if snapshot == nil {
		return CrawlerRegistryStatus{State: "empty"}
	}
	state := "current"
	if !now.UTC().Before(snapshot.expiresAt) {
		state = "expired"
	}
	return statusFromCrawlerSnapshot(state, snapshot)
}

func statusFromCrawlerSnapshot(state string, snapshot *crawlerSnapshot) CrawlerRegistryStatus {
	return CrawlerRegistryStatus{
		State: state, Revision: snapshot.revision, IssuedAt: snapshot.issuedAt, ExpiresAt: snapshot.expiresAt,
		DigestSHA256: snapshot.digest, IdentityCount: len(snapshot.identities), PrefixCount: snapshot.prefixCount,
	}
}

func validateCrawlerRegistryPayload(payload CrawlerRegistryPayload, now time.Time) (time.Time, time.Time, error) {
	if payload.SchemaVersion != CrawlerRegistrySchemaVersion || payload.Revision == 0 {
		return time.Time{}, time.Time{}, ErrInvalidCrawlerRegistry
	}
	issuedAt, err := time.Parse(time.RFC3339, payload.IssuedAt)
	if err != nil || issuedAt.Location() != time.UTC || issuedAt.Format(time.RFC3339) != payload.IssuedAt {
		return time.Time{}, time.Time{}, ErrInvalidCrawlerRegistry
	}
	expiresAt, err := time.Parse(time.RFC3339, payload.ExpiresAt)
	if err != nil || expiresAt.Location() != time.UTC || expiresAt.Format(time.RFC3339) != payload.ExpiresAt {
		return time.Time{}, time.Time{}, ErrInvalidCrawlerRegistry
	}
	if issuedAt.After(now.Add(maxCrawlerRegistryClockSkew)) || !expiresAt.After(now) || !expiresAt.After(issuedAt) {
		if !expiresAt.After(now) {
			return time.Time{}, time.Time{}, ErrCrawlerRegistryExpired
		}
		return time.Time{}, time.Time{}, ErrInvalidCrawlerRegistry
	}
	if expiresAt.Sub(issuedAt) > maxCrawlerRegistryLifetime {
		return time.Time{}, time.Time{}, ErrInvalidCrawlerRegistry
	}
	return issuedAt, expiresAt, nil
}
