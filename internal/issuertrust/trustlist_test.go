package issuertrust

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/palisade-human-trust/palisade/pkg/palisadeassurance"
)

var now = time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)

func keyPair(t *testing.T, seed byte) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	raw := make([]byte, ed25519.SeedSize)
	for index := range raw {
		raw[index] = seed
	}
	private := ed25519.NewKeyFromSeed(raw)
	return private.Public().(ed25519.PublicKey), private
}

func commitment(seed byte) string {
	raw := make([]byte, 32)
	for index := range raw {
		raw[index] = seed
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

func payload(revision uint64, lifetime time.Duration, issuers []Issuer, revoked []string) Payload {
	return Payload{
		Revision:           revision,
		IssuedAt:           now.Format(time.RFC3339),
		ExpiresAt:          now.Add(lifetime).Format(time.RFC3339),
		Issuers:            issuers,
		RevokedCredentials: revoked,
	}
}

func presenceIssuer() Issuer {
	return Issuer{
		IssuerID:              "eu.wallet.reference",
		PublicKey:             commitment(7),
		MaximumAssuranceLevel: palisadeassurance.LevelIssuerVerified,
		UniquenessScope:       "issuer",
		Purpose:               "human_presence",
	}
}

func newStore(t *testing.T, public ed25519.PublicKey) *Store {
	t.Helper()
	store, err := NewStore(public)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	return store
}

func TestAnEmptyStoreTrustsNobody(t *testing.T) {
	public, _ := keyPair(t, 1)
	store := newStore(t, public)

	if decision := store.Evaluate("eu.wallet.reference", commitment(9), now); decision != Untrusted {
		t.Fatalf("an empty store trusted an issuer: %+v", decision)
	}
	if !store.Expired(now) || store.Revision() != 0 {
		t.Fatal("an empty store did not report itself as unusable")
	}
	// The zero value must itself be the safe answer, so a caller that forgets
	// to check still fails closed.
	var zero Decision
	if zero.Trusted || zero.MaximumAssuranceLevel != palisadeassurance.LevelUnattributed {
		t.Fatalf("the zero decision is not fail-closed: %+v", zero)
	}
}

func TestTrustedIssuerIsClampedToWhatThisBuildCanVerify(t *testing.T) {
	public, private := keyPair(t, 2)
	store := newStore(t, public)

	encoded, err := Sign(payload(1, time.Hour, []Issuer{presenceIssuer()}, nil), private)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := store.Update(encoded, now); err != nil {
		t.Fatalf("update: %v", err)
	}

	decision := store.Evaluate("eu.wallet.reference", commitment(9), now)
	if !decision.Trusted {
		t.Fatal("a listed issuer was not trusted")
	}
	// The list grants level 4. Nothing in this repository verifies an issuer
	// credential, so the granted ceiling must be clamped rather than honoured.
	if decision.MaximumAssuranceLevel != palisadeassurance.MaximumSupportedLevel {
		t.Fatalf("issuer ceiling %d was not clamped to %d",
			decision.MaximumAssuranceLevel, palisadeassurance.MaximumSupportedLevel)
	}
	if decision.UniquenessScope != "issuer" || decision.Purpose != "human_presence" {
		t.Fatalf("issuer properties were lost: %+v", decision)
	}
	if store.Expired(now) || store.Revision() != 1 {
		t.Fatalf("store state after update is wrong: revision %d", store.Revision())
	}
}

func TestExpiryDegradesEveryIssuerToUntrusted(t *testing.T) {
	public, private := keyPair(t, 3)
	store := newStore(t, public)
	encoded, err := Sign(payload(1, time.Hour, []Issuer{presenceIssuer()}, nil), private)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := store.Update(encoded, now); err != nil {
		t.Fatalf("update: %v", err)
	}

	later := now.Add(2 * time.Hour)
	if decision := store.Evaluate("eu.wallet.reference", commitment(9), later); decision != Untrusted {
		t.Fatalf("an expired list still trusted an issuer: %+v", decision)
	}
	if !store.Expired(later) {
		t.Fatal("an expired list did not report itself as expired")
	}
	// Installing an already expired list must fail rather than replace a good one.
	stale, err := Sign(payload(2, time.Minute, []Issuer{presenceIssuer()}, nil), private)
	if err != nil {
		t.Fatalf("sign stale: %v", err)
	}
	if err := store.Update(stale, later); err != ErrExpired {
		t.Fatalf("an expired list was installed: %v", err)
	}
}

func TestRevocationRemovesOneCredentialWithoutRemovingTheIssuer(t *testing.T) {
	public, private := keyPair(t, 4)
	store := newStore(t, public)
	revoked := commitment(11)

	first, err := Sign(payload(1, time.Hour, []Issuer{presenceIssuer()}, nil), private)
	if err != nil {
		t.Fatalf("sign first: %v", err)
	}
	if err := store.Update(first, now); err != nil {
		t.Fatalf("update first: %v", err)
	}
	if !store.Evaluate("eu.wallet.reference", revoked, now).Trusted {
		t.Fatal("the credential was not trusted before revocation")
	}

	second, err := Sign(payload(2, time.Hour, []Issuer{presenceIssuer()}, []string{revoked}), private)
	if err != nil {
		t.Fatalf("sign second: %v", err)
	}
	if err := store.Update(second, now); err != nil {
		t.Fatalf("update second: %v", err)
	}
	if decision := store.Evaluate("eu.wallet.reference", revoked, now); decision != Untrusted {
		t.Fatalf("a revoked credential was still trusted: %+v", decision)
	}
	if !store.Evaluate("eu.wallet.reference", commitment(12), now).Trusted {
		t.Fatal("revoking one credential removed the whole issuer")
	}
}

func TestRollbackAndForeignSignaturesAreRefused(t *testing.T) {
	public, private := keyPair(t, 5)
	_, otherPrivate := keyPair(t, 6)
	store := newStore(t, public)

	current, err := Sign(payload(2, time.Hour, []Issuer{presenceIssuer()}, nil), private)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := store.Update(current, now); err != nil {
		t.Fatalf("update: %v", err)
	}

	older, err := Sign(payload(1, time.Hour, nil, nil), private)
	if err != nil {
		t.Fatalf("sign older: %v", err)
	}
	if err := store.Update(older, now); err != ErrRollback {
		t.Fatalf("a rollback was installed: %v", err)
	}
	if err := store.Update(current, now); err != ErrRollback {
		t.Fatalf("replaying the current revision was accepted: %v", err)
	}
	if !store.Evaluate("eu.wallet.reference", commitment(9), now).Trusted {
		t.Fatal("a refused update damaged the installed list")
	}

	foreign, err := Sign(payload(3, time.Hour, nil, nil), otherPrivate)
	if err != nil {
		t.Fatalf("sign foreign: %v", err)
	}
	if err := store.Update(foreign, now); err != ErrInvalid {
		t.Fatalf("a list signed by another publisher was accepted: %v", err)
	}

	// A signature made under a different domain must not verify here.
	crossDomain := signWithDomain(t, payload(4, time.Hour, nil, nil), private,
		"PALISADE\x00HUMAN-ASSURANCE-ASSERTION\x00V1\x00")
	if err := store.Update(crossDomain, now); err != ErrInvalid {
		t.Fatalf("a foreign-domain signature was accepted: %v", err)
	}
	if store.Revision() != 2 {
		t.Fatalf("a refused update changed the revision: %d", store.Revision())
	}
}

func TestMalformedListsAreRefused(t *testing.T) {
	public, private := keyPair(t, 7)
	store := newStore(t, public)

	uniqueWithoutLevel := presenceIssuer()
	uniqueWithoutLevel.MaximumAssuranceLevel = palisadeassurance.LevelBehavioral
	uniqueWithoutLevel.UniquenessScope = "issuer"

	duplicateKey := presenceIssuer()
	duplicateKey.IssuerID = "second.issuer"

	for name, invalid := range map[string]Payload{
		"zero revision":                  payload(0, time.Hour, []Issuer{presenceIssuer()}, nil),
		"lifetime too long":              payload(1, 48*time.Hour, []Issuer{presenceIssuer()}, nil),
		"uniqueness above granted level": payload(1, time.Hour, []Issuer{uniqueWithoutLevel}, nil),
		"duplicate issuer key":           payload(1, time.Hour, []Issuer{presenceIssuer(), duplicateKey}, nil),
		"unknown purpose": payload(1, time.Hour, []Issuer{{
			IssuerID: "x.issuer", PublicKey: commitment(3), MaximumAssuranceLevel: 0,
			UniquenessScope: "none", Purpose: "surveillance",
		}}, nil),
		"level above the ladder": payload(1, time.Hour, []Issuer{{
			IssuerID: "x.issuer", PublicKey: commitment(3), MaximumAssuranceLevel: 9,
			UniquenessScope: "none", Purpose: "other",
		}}, nil),
		"malformed revocation": payload(1, time.Hour, nil, []string{"not-a-commitment"}),
	} {
		if _, err := Sign(invalid, private); err == nil {
			t.Fatalf("%s was signable", name)
		}
	}

	valid, err := Sign(payload(1, time.Hour, []Issuer{presenceIssuer()}, nil), private)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	for name, mutate := range map[string]func(map[string]any){
		"unknown top-level field": func(document map[string]any) { document["extra"] = 1 },
		"unknown payload field": func(document map[string]any) {
			document["payload"].(map[string]any)["subject"] = "person"
		},
		"absent issuers": func(document map[string]any) {
			delete(document["payload"].(map[string]any), "issuers")
		},
		"null revocations": func(document map[string]any) {
			document["payload"].(map[string]any)["revoked_credentials"] = nil
		},
		"raised issuer level": func(document map[string]any) {
			issuers := document["payload"].(map[string]any)["issuers"].([]any)
			issuers[0].(map[string]any)["maximum_assurance_level"] = float64(5)
		},
	} {
		var document map[string]any
		if err := json.Unmarshal(valid, &document); err != nil {
			t.Fatalf("decode: %v", err)
		}
		mutate(document)
		mutated, err := json.Marshal(document)
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		if err := store.Update(mutated, now); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
}

func TestSignedListCarriesNoSubjectData(t *testing.T) {
	_, private := keyPair(t, 8)
	encoded, err := Sign(payload(1, time.Hour, []Issuer{presenceIssuer()}, []string{commitment(11)}), private)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	for _, banned := range []string{"subject", "email", "name", "biometric", "template", "@"} {
		if strings.Contains(string(encoded), banned) {
			t.Fatalf("trust list carries %q: %s", banned, encoded)
		}
	}
	if strings.Contains(string(encoded), "null") {
		t.Fatalf("trust list encoded a null value: %s", encoded)
	}
}

func TestEmptyListInstallsAndTrustsNobody(t *testing.T) {
	public, private := keyPair(t, 9)
	store := newStore(t, public)
	// Revoking every issuer is a legitimate emergency action, so an empty list
	// must install rather than be rejected as malformed.
	encoded, err := Sign(payload(1, time.Hour, nil, nil), private)
	if err != nil {
		t.Fatalf("sign empty: %v", err)
	}
	if err := store.Update(encoded, now); err != nil {
		t.Fatalf("update empty: %v", err)
	}
	if store.Expired(now) {
		t.Fatal("an empty but valid list reported itself expired")
	}
	if decision := store.Evaluate("eu.wallet.reference", commitment(9), now); decision != Untrusted {
		t.Fatalf("an empty list trusted an issuer: %+v", decision)
	}
}

func signWithDomain(t *testing.T, payload Payload, private ed25519.PrivateKey, domain string) []byte {
	t.Helper()
	payload.SchemaVersion = SchemaVersion
	payload.Issuers = issuersOrEmpty(payload.Issuers)
	payload.RevokedCredentials = stringsOrEmpty(payload.RevokedCredentials)
	canonical, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	message := append([]byte(domain), canonical...)
	encoded, err := json.Marshal(Document{
		Payload:   payload,
		Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, message)),
	})
	if err != nil {
		t.Fatalf("marshal document: %v", err)
	}
	return encoded
}
