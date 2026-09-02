package deviceattest

import (
	"crypto/ecdsa"
	"encoding/base64"
	"sync"
	"testing"
	"time"
)

// testRegistry stands in for whatever store a deployment's registration
// ceremony writes to. PALISADE never writes one itself.
type testRegistry struct {
	mu         sync.Mutex
	credential Credential
	session    string
	counts     []uint32
}

func (r *testRegistry) Credential(credentialID, sessionID string) (Credential, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if credentialID != r.credential.ID || (r.session != "" && sessionID != r.session) {
		return Credential{}, false
	}
	return r.credential, true
}

func (r *testRegistry) RecordSignCount(_ string, signCount uint32) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.counts = append(r.counts, signCount)
}

func newService(t *testing.T) (*Service, *testRegistry, *ecdsa.PrivateKey) {
	t.Helper()
	key, credential := es256Credential(t)
	registry := &testRegistry{credential: credential}
	service, err := NewService(Config{
		Secret:   []byte("device-attestation-secret-32-bytes!!"),
		Registry: registry,
		Policy:   policy(),
	})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	return service, registry, key
}

// ceremony answers an issued challenge the way a client would.
func ceremony(t *testing.T, key *ecdsa.PrivateKey, issued []byte, signCount uint32) Assertion {
	t.Helper()
	client := clientDataJSON(t, expectedType, base64.RawURLEncoding.EncodeToString(issued), origin)
	authData := authenticatorData(relyingParty, flagUserPresent, signCount)
	return Assertion{
		CredentialID: credentialID, AuthenticatorData: authData,
		ClientDataJSON: client, Signature: signES256(t, key, authData, client),
	}
}

func TestACompletedCeremonyProducesABoundAttestation(t *testing.T) {
	service, registry, key := newService(t)
	id, issued, err := service.Challenge(testSession, "checkout", "checkout", now)
	if err != nil {
		t.Fatalf("challenge: %v", err)
	}
	if len(issued) != ChallengeBytes {
		t.Fatalf("challenge is %d bytes", len(issued))
	}
	attestation, err := service.Complete(id, testSession, ceremony(t, key, issued, 1), now)
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	if err := service.VerifyAttestation(attestation, testSession, "checkout", "checkout", now.Add(time.Second)); err != nil {
		t.Fatalf("the attestation did not verify: %v", err)
	}
	// The counter is handed back so the deployment can detect a clone next time.
	if len(registry.counts) != 1 || registry.counts[0] != 1 {
		t.Fatalf("sign counts = %v", registry.counts)
	}
	// The challenge is consumed, so the same ceremony cannot be replayed.
	if _, err := service.Complete(id, testSession, ceremony(t, key, issued, 2), now); err != ErrNotFound {
		t.Fatalf("a consumed challenge was reusable: %v", err)
	}
	if service.Outstanding() != 0 {
		t.Fatalf("outstanding = %d", service.Outstanding())
	}
}

func TestTheAttestationIsBoundToWhatTheChallengeWasIssuedFor(t *testing.T) {
	service, _, key := newService(t)
	id, issued, err := service.Challenge(testSession, "checkout", "checkout", now)
	if err != nil {
		t.Fatalf("challenge: %v", err)
	}
	attestation, err := service.Complete(id, testSession, ceremony(t, key, issued, 1), now)
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	// A ceremony earned for a checkout must not authorise a login, and must not
	// travel to another session.
	for name, args := range map[string][3]string{
		"another action":   {testSession, "login", "checkout"},
		"another endpoint": {testSession, "checkout", "login"},
		"another session":  {"session-87654321", "checkout", "checkout"},
	} {
		if err := service.VerifyAttestation(attestation, args[0], args[1], args[2], now.Add(time.Second)); err != ErrAttestationInvalid {
			t.Fatalf("%s accepted the attestation: %v", name, err)
		}
	}
	if err := service.VerifyAttestation(attestation, testSession, "checkout", "checkout", now.Add(AttestationTTL+time.Minute)); err != ErrAttestationInvalid {
		t.Fatal("an expired attestation was accepted")
	}
}

func TestAFailedCeremonyConsumesItsChallenge(t *testing.T) {
	service, _, key := newService(t)
	id, issued, err := service.Challenge(testSession, "checkout", "checkout", now)
	if err != nil {
		t.Fatalf("challenge: %v", err)
	}
	// A client that could retry against the same challenge would be able to
	// search for a credential that happens to verify.
	wrong := ceremony(t, key, issued, 1)
	wrong.CredentialID = "some-other-credential"
	if _, err := service.Complete(id, testSession, wrong, now); err != ErrUnknownCredential {
		t.Fatalf("an unregistered credential was accepted: %v", err)
	}
	if _, err := service.Complete(id, testSession, ceremony(t, key, issued, 1), now); err != ErrNotFound {
		t.Fatal("a failed ceremony left its challenge usable")
	}
}

func TestAnotherSessionCannotAnswerAChallenge(t *testing.T) {
	service, _, key := newService(t)
	id, issued, err := service.Challenge(testSession, "checkout", "checkout", now)
	if err != nil {
		t.Fatalf("challenge: %v", err)
	}
	if _, err := service.Complete(id, "session-87654321", ceremony(t, key, issued, 1), now); err != ErrNotFound {
		t.Fatalf("another session answered the challenge: %v", err)
	}
}

func TestAChallengeFromAnotherIssueDoesNotVerify(t *testing.T) {
	service, _, key := newService(t)
	first, firstValue, err := service.Challenge(testSession, "checkout", "checkout", now)
	if err != nil {
		t.Fatalf("challenge: %v", err)
	}
	_, secondValue, err := service.Challenge(testSession, "checkout", "checkout", now)
	if err != nil {
		t.Fatalf("challenge: %v", err)
	}
	if base64.RawURLEncoding.EncodeToString(firstValue) == base64.RawURLEncoding.EncodeToString(secondValue) {
		t.Fatal("two challenges were identical")
	}
	// Signing the other challenge proves possession of a key, not freshness
	// here, so it must fail.
	if _, err := service.Complete(first, testSession, ceremony(t, key, secondValue, 1), now); err != ErrChallenge {
		t.Fatalf("a ceremony over another challenge was accepted: %v", err)
	}
}

func TestExpiredChallengesAreSweptAndCapacityIsBounded(t *testing.T) {
	service, _, key := newService(t)
	id, issued, err := service.Challenge(testSession, "checkout", "checkout", now)
	if err != nil {
		t.Fatalf("challenge: %v", err)
	}
	if _, err := service.Complete(id, testSession, ceremony(t, key, issued, 1), now.Add(ChallengeTTL+time.Minute)); err != ErrNotFound {
		t.Fatal("an expired challenge was answerable")
	}

	registry := &testRegistry{}
	bounded, err := NewService(Config{
		Secret: []byte("device-attestation-secret-32-bytes!!"), Registry: registry,
		Policy: policy(), MaxChallenges: 1,
	})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	if _, _, err := bounded.Challenge(testSession, "checkout", "checkout", now); err != nil {
		t.Fatalf("first challenge: %v", err)
	}
	if _, _, err := bounded.Challenge("session-87654321", "checkout", "checkout", now); err != ErrCapacityExceeded {
		t.Fatalf("the capacity bound was not enforced: %v", err)
	}
	if removed := bounded.Sweep(now.Add(ChallengeTTL + time.Minute)); removed != 1 {
		t.Fatalf("swept %d", removed)
	}
}

func TestServiceConfigurationIsValidated(t *testing.T) {
	registry := &testRegistry{}
	for name, config := range map[string]Config{
		"no secret":    {Registry: registry, Policy: policy()},
		"short secret": {Secret: []byte("short"), Registry: registry, Policy: policy()},
		"no registry":  {Secret: []byte("device-attestation-secret-32-bytes!!"), Policy: policy()},
		"no relying party": {
			Secret: []byte("device-attestation-secret-32-bytes!!"), Registry: registry,
			Policy: Policy{Origin: origin}},
		"no origin": {
			Secret: []byte("device-attestation-secret-32-bytes!!"), Registry: registry,
			Policy: Policy{RelyingPartyID: relyingParty}},
	} {
		if _, err := NewService(config); err != ErrInvalid {
			t.Fatalf("%s was accepted", name)
		}
	}
	service, _, _ := newService(t)
	if service.RelyingPartyID() != relyingParty {
		t.Fatalf("relying party = %q", service.RelyingPartyID())
	}
	if _, _, err := service.Challenge("short", "checkout", "checkout", now); err != ErrInvalid {
		t.Fatal("a short session was accepted")
	}
}

func TestAnotherDeploymentSecretDoesNotVerify(t *testing.T) {
	service, registry, key := newService(t)
	id, issued, err := service.Challenge(testSession, "checkout", "checkout", now)
	if err != nil {
		t.Fatalf("challenge: %v", err)
	}
	attestation, err := service.Complete(id, testSession, ceremony(t, key, issued, 1), now)
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	other, err := NewService(Config{
		Secret: []byte("a-different-deployment-secret-32byte"), Registry: registry, Policy: policy()})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	if err := other.VerifyAttestation(attestation, testSession, "checkout", "checkout", now.Add(time.Second)); err != ErrAttestationInvalid {
		t.Fatal("an attestation verified under another deployment secret")
	}
}
