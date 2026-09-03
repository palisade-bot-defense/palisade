package httpapi

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/palisade-human-trust/palisade/internal/deviceattest"
	"github.com/palisade-human-trust/palisade/internal/liveness"
)

// A liveness attestation and a device attestation are the same shape on the
// wire: base64url of a 32-byte MAC followed by an 8-byte timestamp, presented
// on the same surfaces through sibling headers. Nothing about one is
// distinguishable from the other by looking at it.
//
// What keeps them apart is a domain-separation string inside the MAC and the
// rule that each service holds its own secret. The second of those is an
// operator instruction, which means some deployment will get it wrong — so
// these tests configure both services with one shared secret, the mistake
// rather than the intent, and check that domain separation alone still refuses
// the swap.
//
// The stake is a level, not just a check: liveness is the H2 evidence class and
// device attestation the H3 one. An attestation accepted by the wrong verifier
// would turn evidence a person produced by clicking into evidence of a
// registered credential, which is an escalation rather than a bypass.
const sharedAttestationSecret = "one-secret-for-both-services-32b!!!!"

func confusableServices(t *testing.T) (*liveness.Service, *deviceattest.Service, *ecdsa.PrivateKey) {
	t.Helper()
	live, err := liveness.New(liveness.Config{Secret: []byte(sharedAttestationSecret)})
	if err != nil {
		t.Fatalf("liveness service: %v", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	devices, err := deviceattest.NewService(deviceattest.Config{
		Secret: []byte(sharedAttestationSecret),
		Registry: stubRegistry{credential: deviceattest.Credential{
			ID: deviceCredentialID, Algorithm: deviceattest.ES256,
			PublicKey: elliptic.Marshal(elliptic.P256(), key.PublicKey.X, key.PublicKey.Y),
		}},
		Policy: deviceattest.Policy{RelyingPartyID: "relying.example", Origin: "https://relying.example"},
	})
	if err != nil {
		t.Fatalf("device service: %v", err)
	}
	return live, devices, key
}

// earnLivenessAttestation answers every round the way a person would.
func earnLivenessAttestation(t *testing.T, service *liveness.Service, session, action, class string) string {
	t.Helper()
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	id, prompt, err := service.Begin(session, action, class, now)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	for round := 0; ; round++ {
		now = now.Add(time.Second)
		progress, err := service.Answer(id, session, prompt.Target, round, now)
		if err != nil {
			t.Fatalf("round %d: %v", round, err)
		}
		if progress.Completed {
			return progress.Attestation
		}
		prompt = *progress.Next
	}
}

// earnDeviceAttestation runs the ceremony a WebAuthn client would run.
func earnDeviceAttestation(
	t *testing.T,
	service *deviceattest.Service,
	key *ecdsa.PrivateKey,
	session, action, class string,
	now time.Time,
) string {
	t.Helper()
	challengeID, challenge, err := service.Challenge(session, action, class, now)
	if err != nil {
		t.Fatalf("device challenge: %v", err)
	}
	clientData, err := json.Marshal(map[string]string{
		"type":      "webauthn.get",
		"challenge": base64.RawURLEncoding.EncodeToString(challenge),
		"origin":    "https://relying.example",
	})
	if err != nil {
		t.Fatalf("encode client data: %v", err)
	}
	relyingPartyHash := sha256.Sum256([]byte("relying.example"))
	authData := append(append([]byte{}, relyingPartyHash[:]...), 0x01, 0, 0, 0, 1)
	clientHash := sha256.Sum256(clientData)
	digest := sha256.Sum256(append(append([]byte{}, authData...), clientHash[:]...))
	signature, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	attestation, err := service.Complete(challengeID, session, deviceattest.Assertion{
		CredentialID: deviceCredentialID, AuthenticatorData: authData,
		ClientDataJSON: clientData, Signature: signature,
	}, now)
	if err != nil {
		t.Fatalf("device complete: %v", err)
	}
	return attestation
}

func TestOneKindOfAttestationIsNotAcceptedAsTheOther(t *testing.T) {
	const session, action, class = "confusion-session-1", "login", "login"
	live, devices, key := confusableServices(t)
	now := time.Date(2026, 9, 3, 12, 0, 30, 0, time.UTC)

	livenessAttestation := earnLivenessAttestation(t, live, session, action, class)
	deviceAttestation := earnDeviceAttestation(t, devices, key, session, action, class, now)

	// Each is genuine for its own verifier. Without this the test could pass by
	// refusing two strings that were never valid in the first place.
	if err := live.VerifyAttestation(livenessAttestation, session, action, class, now); err != nil {
		t.Fatalf("a genuine liveness attestation was refused by its own verifier: %v", err)
	}
	if err := devices.VerifyAttestation(deviceAttestation, session, action, class, now); err != nil {
		t.Fatalf("a genuine device attestation was refused by its own verifier: %v", err)
	}

	// The swap, in both directions, with the same secret behind both services.
	if err := devices.VerifyAttestation(livenessAttestation, session, action, class, now); err == nil {
		t.Fatal("a liveness attestation was accepted as device evidence: H2 evidence became H3")
	}
	if err := live.VerifyAttestation(deviceAttestation, session, action, class, now); err == nil {
		t.Fatal("a device attestation was accepted as liveness evidence")
	}
}

// The two attestations are indistinguishable to anything that does not hold a
// secret. A deployment cannot route them by inspection, and neither can an
// attacker choose between them by looking — which is why the refusal above has
// to come from the MAC rather than from a format check that happens to differ.
func TestBothAttestationsAreTheSameShape(t *testing.T) {
	const session, action, class = "confusion-session-2", "login", "login"
	live, devices, key := confusableServices(t)
	now := time.Date(2026, 9, 3, 12, 0, 30, 0, time.UTC)

	livenessAttestation := earnLivenessAttestation(t, live, session, action, class)
	deviceAttestation := earnDeviceAttestation(t, devices, key, session, action, class, now)

	if len(livenessAttestation) != len(deviceAttestation) {
		t.Fatalf("the two attestations differ in length (%d vs %d), so this test no longer describes the risk",
			len(livenessAttestation), len(deviceAttestation))
	}
	for _, encoded := range []string{livenessAttestation, deviceAttestation} {
		raw, err := base64.RawURLEncoding.DecodeString(encoded)
		if err != nil || len(raw) != sha256.Size+8 {
			t.Fatalf("attestation is not a MAC and a timestamp: %v", err)
		}
	}
}
