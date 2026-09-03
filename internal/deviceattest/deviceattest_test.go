package deviceattest

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

var (
	now             = time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	issuedChallenge = []byte("palisade-issued-challenge-32bytes")
)

const (
	testSession  = "session-12345678"
	relyingParty = "relying.example"
	origin       = "https://relying.example"
	credentialID = "Y3JlZGVudGlhbC1pZGVudGlmaWVy"
)

func policy() Policy {
	return Policy{RelyingPartyID: relyingParty, Origin: origin}
}

func clientDataJSON(t *testing.T, kind, challenge, org string) []byte {
	t.Helper()
	encoded, err := json.Marshal(map[string]string{"type": kind, "challenge": challenge, "origin": org})
	if err != nil {
		t.Fatalf("encode client data: %v", err)
	}
	return encoded
}

func authenticatorData(rpID string, flags byte, signCount uint32) []byte {
	hash := sha256.Sum256([]byte(rpID))
	data := make([]byte, 0, authenticatorDataMinimum)
	data = append(data, hash[:]...)
	data = append(data, flags)
	return append(data, byte(signCount>>24), byte(signCount>>16), byte(signCount>>8), byte(signCount))
}

// signES256 produces the assertion an authenticator would return.
func signES256(t *testing.T, key *ecdsa.PrivateKey, authData, client []byte) []byte {
	t.Helper()
	clientHash := sha256.Sum256(client)
	digest := sha256.Sum256(append(append([]byte{}, authData...), clientHash[:]...))
	signature, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signature
}

func es256Credential(t *testing.T) (*ecdsa.PrivateKey, Credential) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return key, Credential{
		ID: credentialID, Algorithm: ES256,
		PublicKey: elliptic.Marshal(elliptic.P256(), key.PublicKey.X, key.PublicKey.Y),
	}
}

// countedAssertion is a valid assertion carrying a chosen signature counter.
func countedAssertion(t *testing.T, key *ecdsa.PrivateKey, signCount uint32) Assertion {
	t.Helper()
	client := clientDataJSON(t, expectedType, base64.RawURLEncoding.EncodeToString(issuedChallenge), origin)
	authData := authenticatorData(relyingParty, flagUserPresent, signCount)
	return Assertion{
		CredentialID: credentialID, AuthenticatorData: authData,
		ClientDataJSON: client, Signature: signES256(t, key, authData, client),
	}
}

func validAssertion(t *testing.T, key *ecdsa.PrivateKey) Assertion {
	t.Helper()
	client := clientDataJSON(t, expectedType, base64.RawURLEncoding.EncodeToString(issuedChallenge), origin)
	authData := authenticatorData(relyingParty, flagUserPresent, 1)
	return Assertion{
		CredentialID:      credentialID,
		AuthenticatorData: authData,
		ClientDataJSON:    client,
		Signature:         signES256(t, key, authData, client),
	}
}

func TestAFreshAssertionFromARegisteredCredentialVerifies(t *testing.T) {
	key, credential := es256Credential(t)
	result, err := Verify(validAssertion(t, key), credential, policy(), issuedChallenge, now)
	if err != nil {
		t.Fatalf("a valid assertion did not verify: %v", err)
	}
	if result.CredentialID != credentialID || result.SignCount != 1 {
		t.Fatalf("unexpected result: %+v", result)
	}
	// User presence was signalled but not user verification, so the result must
	// not claim the person was verified.
	if result.UserVerified {
		t.Fatal("presence alone was reported as user verification")
	}
}

func TestASignatureOverAnotherChallengeIsRefused(t *testing.T) {
	key, credential := es256Credential(t)
	assertion := validAssertion(t, key)

	// Verifying against a challenge this deployment did not issue would prove
	// only that a key exists somewhere, not that it was used here and now.
	if _, err := Verify(assertion, credential, policy(), []byte("some-other-challenge-32-bytes!!"), now); err != ErrChallenge {
		t.Fatalf("an assertion for another challenge was accepted: %v", err)
	}

	// A registration ceremony proves something different and must not pass as
	// an authentication.
	client := clientDataJSON(t, "webauthn.create", base64.RawURLEncoding.EncodeToString(issuedChallenge), origin)
	authData := authenticatorData(relyingParty, flagUserPresent, 1)
	registration := Assertion{
		CredentialID: credentialID, AuthenticatorData: authData,
		ClientDataJSON: client, Signature: signES256(t, key, authData, client),
	}
	if _, err := Verify(registration, credential, policy(), issuedChallenge, now); err != ErrChallenge {
		t.Fatalf("a registration ceremony was accepted as authentication: %v", err)
	}
}

func TestTheCeremonyIsBoundToItsRelyingPartyAndOrigin(t *testing.T) {
	key, credential := es256Credential(t)

	// A ceremony run on another origin, even with a valid signature, is a
	// phishing result rather than evidence about this deployment.
	client := clientDataJSON(t, expectedType, base64.RawURLEncoding.EncodeToString(issuedChallenge), "https://attacker.example")
	authData := authenticatorData(relyingParty, flagUserPresent, 1)
	phished := Assertion{
		CredentialID: credentialID, AuthenticatorData: authData,
		ClientDataJSON: client, Signature: signES256(t, key, authData, client),
	}
	if _, err := Verify(phished, credential, policy(), issuedChallenge, now); err != ErrChallenge {
		t.Fatalf("an assertion from another origin was accepted: %v", err)
	}

	// The authenticator's own relying-party binding must match too.
	client = clientDataJSON(t, expectedType, base64.RawURLEncoding.EncodeToString(issuedChallenge), origin)
	authData = authenticatorData("attacker.example", flagUserPresent, 1)
	wrongParty := Assertion{
		CredentialID: credentialID, AuthenticatorData: authData,
		ClientDataJSON: client, Signature: signES256(t, key, authData, client),
	}
	if _, err := Verify(wrongParty, credential, policy(), issuedChallenge, now); err != ErrChallenge {
		t.Fatalf("an assertion scoped to another relying party was accepted: %v", err)
	}
}

func TestAnUntouchedAuthenticatorIsRefused(t *testing.T) {
	key, credential := es256Credential(t)
	client := clientDataJSON(t, expectedType, base64.RawURLEncoding.EncodeToString(issuedChallenge), origin)
	authData := authenticatorData(relyingParty, 0, 1)
	silent := Assertion{
		CredentialID: credentialID, AuthenticatorData: authData,
		ClientDataJSON: client, Signature: signES256(t, key, authData, client),
	}
	if _, err := Verify(silent, credential, policy(), issuedChallenge, now); err != ErrPresence {
		t.Fatalf("an assertion without user presence was accepted: %v", err)
	}
}

func TestUserVerificationIsOptionalButReported(t *testing.T) {
	key, credential := es256Credential(t)
	client := clientDataJSON(t, expectedType, base64.RawURLEncoding.EncodeToString(issuedChallenge), origin)
	authData := authenticatorData(relyingParty, flagUserPresent|flagUserVerified, 2)
	verified := Assertion{
		CredentialID: credentialID, AuthenticatorData: authData,
		ClientDataJSON: client, Signature: signES256(t, key, authData, client),
	}
	result, err := Verify(verified, credential, policy(), issuedChallenge, now)
	if err != nil || !result.UserVerified {
		t.Fatalf("user verification was not reported: %+v %v", result, err)
	}

	// Requiring it excludes authenticators that cannot do it, so a deployment
	// must opt in rather than get it silently.
	strict := policy()
	strict.RequireUserVerification = true
	if _, err := Verify(validAssertion(t, key), credential, strict, issuedChallenge, now); err != ErrPresence {
		t.Fatalf("a presence-only assertion satisfied a verification requirement: %v", err)
	}
}

func TestACounterThatDoesNotAdvanceIsRefused(t *testing.T) {
	key, credential := es256Credential(t)
	credential.SignCount = 5
	client := clientDataJSON(t, expectedType, base64.RawURLEncoding.EncodeToString(issuedChallenge), origin)
	authData := authenticatorData(relyingParty, flagUserPresent, 5)
	replayed := Assertion{
		CredentialID: credentialID, AuthenticatorData: authData,
		ClientDataJSON: client, Signature: signES256(t, key, authData, client),
	}
	// A counter that fails to advance is the signal that a credential was
	// cloned.
	if _, err := Verify(replayed, credential, policy(), issuedChallenge, now); err != ErrReplay {
		t.Fatalf("a non-advancing counter was accepted: %v", err)
	}

	// A stored counter of five and an incoming zero is not "this authenticator
	// keeps no counter" — it is a counter that went backwards, and it used to be
	// accepted because the guard only looked at the incoming value. The caller
	// then persisted that zero over the five, so one such assertion disabled
	// clone detection for the credential from then on.
	zeroed := countedAssertion(t, key, 0)
	if _, err := Verify(zeroed, credential, policy(), issuedChallenge, now); err != ErrReplay {
		t.Fatalf("a counter that dropped to zero erased the stored one: %v", err)
	}
}

// The authenticator behind a synced passkey reports zero on every ceremony,
// which must keep verifying however many times it is used. This is the case a
// too-eager counter guard breaks, and it is the case almost every real person
// presents.
func TestACounterlessAuthenticatorVerifiesEveryTime(t *testing.T) {
	key, credential := es256Credential(t)
	for ceremony := range 3 {
		result, err := Verify(countedAssertion(t, key, 0), credential, policy(), issuedChallenge, now)
		if err != nil {
			t.Fatalf("ceremony %d: a counterless authenticator was refused: %v", ceremony, err)
		}
		if result.CounterPresent {
			t.Fatal("a ceremony with no counter on either side reported one")
		}
		// What the deployment stores after each ceremony, which stays zero.
		credential.SignCount = result.SignCount
	}
}

// A successful verification does not by itself mean clone detection ran. An
// operator who cannot tell the two apart will believe a control is protecting
// them that never executed.
func TestCounterPresenceIsReported(t *testing.T) {
	key, credential := es256Credential(t)
	result, err := Verify(countedAssertion(t, key, 7), credential, policy(), issuedChallenge, now)
	if err != nil || !result.CounterPresent || result.SignCount != 7 {
		t.Fatalf("a counting authenticator was not reported as one: %+v %v", result, err)
	}

	// A stored counter alone is enough for the comparison to be meaningful,
	// even before this ceremony's own value is read.
	credential.SignCount = 7
	if _, err := Verify(countedAssertion(t, key, 8), credential, policy(), issuedChallenge, now); err != nil {
		t.Fatalf("an advancing counter was refused: %v", err)
	}
}

func TestForgedAndForeignSignaturesAreRefused(t *testing.T) {
	key, credential := es256Credential(t)
	other, _ := es256Credential(t)

	tampered := validAssertion(t, key)
	tampered.Signature[len(tampered.Signature)-1] ^= 0xff
	if _, err := Verify(tampered, credential, policy(), issuedChallenge, now); err != ErrSignature {
		t.Fatalf("a tampered signature was accepted: %v", err)
	}

	foreign := validAssertion(t, other)
	if _, err := Verify(foreign, credential, policy(), issuedChallenge, now); err != ErrSignature {
		t.Fatalf("another key's signature was accepted: %v", err)
	}

	// Swapping the authenticator data after signing must invalidate it, since
	// the signature covers it.
	swapped := validAssertion(t, key)
	swapped.AuthenticatorData = authenticatorData(relyingParty, flagUserPresent|flagUserVerified, 9)
	if _, err := Verify(swapped, credential, policy(), issuedChallenge, now); err != ErrSignature {
		t.Fatalf("modified authenticator data was accepted: %v", err)
	}
}

func TestMalformedKeysAndAlgorithmsAreRefused(t *testing.T) {
	key, credential := es256Credential(t)
	assertion := validAssertion(t, key)

	for name, broken := range map[string]Credential{
		"unknown algorithm": {ID: credentialID, Algorithm: "rs256", PublicKey: credential.PublicKey},
		"empty algorithm":   {ID: credentialID, PublicKey: credential.PublicKey},
		"truncated key":     {ID: credentialID, Algorithm: ES256, PublicKey: credential.PublicKey[:32]},
		"compressed point":  {ID: credentialID, Algorithm: ES256, PublicKey: append([]byte{2}, credential.PublicKey[1:]...)},
		"point off curve": {ID: credentialID, Algorithm: ES256, PublicKey: func() []byte {
			bad := append([]byte{}, credential.PublicKey...)
			bad[len(bad)-1] ^= 0xff
			return bad
		}()},
	} {
		if _, err := Verify(assertion, broken, policy(), issuedChallenge, now); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
}

func TestEd25519CredentialsVerify(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	credential := Credential{ID: credentialID, Algorithm: EdDSA, PublicKey: public}

	client := clientDataJSON(t, expectedType, base64.RawURLEncoding.EncodeToString(issuedChallenge), origin)
	authData := authenticatorData(relyingParty, flagUserPresent, 1)
	clientHash := sha256.Sum256(client)
	signed := append(append([]byte{}, authData...), clientHash[:]...)
	assertion := Assertion{
		CredentialID: credentialID, AuthenticatorData: authData,
		ClientDataJSON: client, Signature: ed25519.Sign(private, signed),
	}
	if _, err := Verify(assertion, credential, policy(), issuedChallenge, now); err != nil {
		t.Fatalf("an Ed25519 assertion did not verify: %v", err)
	}

	assertion.Signature[0] ^= 0xff
	if _, err := Verify(assertion, credential, policy(), issuedChallenge, now); err != ErrSignature {
		t.Fatalf("a tampered Ed25519 signature was accepted: %v", err)
	}
}

func TestStructurallyImpossibleInputIsRefused(t *testing.T) {
	key, credential := es256Credential(t)
	valid := validAssertion(t, key)

	short := valid
	short.AuthenticatorData = valid.AuthenticatorData[:20]
	oversized := valid
	oversized.ClientDataJSON = make([]byte, MaximumClientDataBytes+1)
	mismatched := valid
	mismatched.CredentialID = "another-credential"
	unparsable := valid
	unparsable.ClientDataJSON = []byte("{")

	for name, assertion := range map[string]Assertion{
		"short authenticator data": short,
		"oversized client data":    oversized,
		"another credential":       mismatched,
		"unparsable client data":   unparsable,
		"empty signature":          {CredentialID: credentialID, AuthenticatorData: valid.AuthenticatorData, ClientDataJSON: valid.ClientDataJSON},
	} {
		if _, err := Verify(assertion, credential, policy(), issuedChallenge, now); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}

	for name, broken := range map[string]Policy{
		"no relying party": {Origin: origin},
		"no origin":        {RelyingPartyID: relyingParty},
	} {
		if _, err := Verify(valid, credential, broken, issuedChallenge, now); err != ErrInvalid {
			t.Fatalf("%s policy was accepted", name)
		}
	}
	// A short challenge is guessable, so it is refused at the boundary rather
	// than verified against.
	if _, err := Verify(valid, credential, policy(), []byte("short"), now); err != ErrInvalid {
		t.Fatal("a short challenge was accepted")
	}
}

// A synced passkey lives on every device signed into an account, so a ceremony
// with one evidences possession of the account's credential rather than of one
// device. The flag is in the assertion; reading it is the difference between
// "device-bound" meaning something and being decoration.
func TestBackupEligibleCredentialsAreReportedAndOptionallyRefused(t *testing.T) {
	key, credential := es256Credential(t)
	client := clientDataJSON(t, expectedType, base64.RawURLEncoding.EncodeToString(issuedChallenge), origin)

	synced := authenticatorData(relyingParty, flagUserPresent|flagBackupEligible|flagBackedUp, 1)
	assertion := Assertion{
		CredentialID: credentialID, AuthenticatorData: synced,
		ClientDataJSON: client, Signature: signES256(t, key, synced, client),
	}

	// The default accepts it — refusing synced passkeys excludes almost
	// everyone — but must report what it accepted.
	result, err := Verify(assertion, credential, policy(), issuedChallenge, now)
	if err != nil {
		t.Fatalf("a synced credential was refused by default: %v", err)
	}
	if !result.BackupEligible || !result.BackedUp {
		t.Fatalf("a synced credential was not reported as such: %+v", result)
	}

	// A deployment that reads "device-bound" literally can require it.
	strict := policy()
	strict.RequireDeviceBound = true
	if _, err := Verify(assertion, credential, strict, issuedChallenge, now); err != ErrNotDeviceBound {
		t.Fatalf("a synced credential satisfied a device-bound requirement: %v", err)
	}

	// A credential the authenticator cannot copy satisfies it, and is reported
	// as not backed up.
	bound := authenticatorData(relyingParty, flagUserPresent, 2)
	single := Assertion{
		CredentialID: credentialID, AuthenticatorData: bound,
		ClientDataJSON: client, Signature: signES256(t, key, bound, client),
	}
	result, err = Verify(single, credential, strict, issuedChallenge, now)
	if err != nil {
		t.Fatalf("a device-bound credential was refused: %v", err)
	}
	if result.BackupEligible || result.BackedUp {
		t.Fatalf("a device-bound credential was reported as synced: %+v", result)
	}
}
