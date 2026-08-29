package localartifact

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestSignedArtifactLifecycleAndRollback(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewVerifier(publicKey, TypePolicy)
	if err != nil {
		t.Fatal(err)
	}
	first := signFixture(t, privateKey, TypePolicy, "policy-v1", 1, now, now.Add(time.Hour), map[string]any{"profile": "closed"})
	verified, err := verifier.VerifyAndAdvance(first, now)
	if err != nil || verified.Metadata.Revision != 1 || verified.Metadata.KeyID != KeyID(publicKey) || verified.DigestSHA256 == "" {
		t.Fatalf("verified=%+v err=%v", verified, err)
	}
	if _, err := verifier.VerifyAndAdvance(first, now); !errors.Is(err, ErrUnchanged) {
		t.Fatalf("unchanged error=%v", err)
	}
	rollback := signFixture(t, privateKey, TypePolicy, "policy-v1", 1, now, now.Add(time.Hour), map[string]any{"profile": "different"})
	if _, err := verifier.VerifyAndAdvance(rollback, now); !errors.Is(err, ErrRollback) {
		t.Fatalf("rollback error=%v", err)
	}
	second := signFixture(t, privateKey, TypePolicy, "policy-v2", 2, now, now.Add(time.Hour), map[string]any{"profile": "closed"})
	if _, err := verifier.VerifyAndAdvance(second, now); err != nil {
		t.Fatal(err)
	}
}

func TestSignedArtifactRejectsTamperingTypeKeyAndTimePoisoning(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	wrongPublicKey, _, _ := ed25519.GenerateKey(rand.Reader)
	valid := signFixture(t, privateKey, TypePolicy, "policy-v1", 1, now, now.Add(time.Hour), map[string]any{"profile": "closed"})

	tests := []struct {
		name     string
		encoded  []byte
		key      ed25519.PublicKey
		typeName string
		at       time.Time
		want     error
	}{
		{name: "wrong signer", encoded: valid, key: wrongPublicKey, typeName: TypePolicy, at: now, want: ErrInvalid},
		{name: "type confusion", encoded: valid, key: publicKey, typeName: TypeDetector, at: now, want: ErrInvalid},
		{name: "expired", encoded: valid, key: publicKey, typeName: TypePolicy, at: now.Add(time.Hour), want: ErrExpired},
		{name: "future", encoded: signFixture(t, privateKey, TypePolicy, "policy-v1", 1, now.Add(MaximumClockSkew+time.Second), now.Add(time.Hour), map[string]any{}), key: publicKey, typeName: TypePolicy, at: now, want: ErrInvalid},
		{name: "excessive lifetime", encoded: signFixture(t, privateKey, TypePolicy, "policy-v1", 1, now, now.Add(MaximumLifetime+time.Second), map[string]any{}), key: publicKey, typeName: TypePolicy, at: now, want: ErrInvalid},
		{name: "trailing json", encoded: append(append([]byte(nil), valid...), []byte(`{}`)...), key: publicKey, typeName: TypePolicy, at: now, want: ErrInvalid},
		{name: "unknown outer field", encoded: []byte(strings.Replace(string(valid), `"signature":`, `"unknown":true,"signature":`, 1)), key: publicKey, typeName: TypePolicy, at: now, want: ErrInvalid},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			verifier, err := NewVerifier(test.key, test.typeName)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := verifier.VerifyAndAdvance(test.encoded, test.at); !errors.Is(err, test.want) {
				t.Fatalf("error=%v want=%v", err, test.want)
			}
		})
	}

	tampered := append([]byte(nil), valid...)
	var document map[string]any
	if err := json.Unmarshal(tampered, &document); err != nil {
		t.Fatal(err)
	}
	payload := document["payload"].(map[string]any)
	payload["profile"] = "tampered"
	tampered, _ = json.Marshal(document)
	verifier, _ := NewVerifier(publicKey, TypePolicy)
	if _, err := verifier.VerifyAndAdvance(tampered, now); !errors.Is(err, ErrInvalid) {
		t.Fatalf("tamper error=%v", err)
	}
}

func signFixture(t *testing.T, privateKey ed25519.PrivateKey, artifactType, id string, revision uint64, issuedAt, expiresAt time.Time, payload any) []byte {
	t.Helper()
	encoded, err := Sign(Metadata{
		ArtifactType: artifactType, ArtifactID: id, Revision: revision,
		IssuedAt: issuedAt.Format(time.RFC3339), ExpiresAt: expiresAt.Format(time.RFC3339),
	}, payload, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
