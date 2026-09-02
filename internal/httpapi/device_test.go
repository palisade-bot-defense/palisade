package httpapi

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/palisade-human-trust/palisade/internal/deviceattest"
	"github.com/palisade-human-trust/palisade/pkg/palisadeassurance"
)

// The device transport: PALISADE issues a challenge, the client answers it
// with a credential the deployment registered elsewhere, and the completed
// ceremony becomes an attestation presented on any assurance surface.

const deviceCredentialID = "Y3JlZGVudGlhbC1pZGVudGlmaWVy"

type stubRegistry struct{ credential deviceattest.Credential }

func (r stubRegistry) Credential(credentialID, _ string) (deviceattest.Credential, bool) {
	if credentialID != r.credential.ID {
		return deviceattest.Credential{}, false
	}
	return r.credential, true
}

func (stubRegistry) RecordSignCount(string, uint32) {}

func deviceService(t *testing.T) (*deviceattest.Service, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	service, err := deviceattest.NewService(deviceattest.Config{
		Secret: []byte("device-attestation-secret-32-bytes!!"),
		Registry: stubRegistry{credential: deviceattest.Credential{
			ID: deviceCredentialID, Algorithm: deviceattest.ES256,
			PublicKey: elliptic.Marshal(elliptic.P256(), key.PublicKey.X, key.PublicKey.Y),
		}},
		Policy: deviceattest.Policy{RelyingPartyID: "relying.example", Origin: "https://relying.example"},
	})
	if err != nil {
		t.Fatalf("device service: %v", err)
	}
	return service, key
}

// completeCeremony walks the transport the way a WebAuthn client would.
func completeCeremony(t *testing.T, server *Server, key *ecdsa.PrivateKey, action, endpointClass string) string {
	t.Helper()
	begin := post(t, server, "/v1/assurance/device/challenge",
		`{"session_id":"`+assuranceSession+`","action":"`+action+`","endpoint_class":"`+endpointClass+`"}`, nil)
	if begin.Code != http.StatusOK {
		t.Fatalf("challenge status=%d body=%s", begin.Code, begin.Body.String())
	}
	var issued deviceChallengeResponse
	if err := json.Unmarshal(begin.Body.Bytes(), &issued); err != nil {
		t.Fatalf("decode challenge: %v", err)
	}

	clientData, err := json.Marshal(map[string]string{
		"type": "webauthn.get", "challenge": issued.Challenge, "origin": "https://relying.example",
	})
	if err != nil {
		t.Fatalf("encode client data: %v", err)
	}
	relyingPartyHash := sha256.Sum256([]byte(issued.RelyingPartyID))
	authData := append(append([]byte{}, relyingPartyHash[:]...), 0x01, 0, 0, 0, 1)
	clientHash := sha256.Sum256(clientData)
	digest := sha256.Sum256(append(append([]byte{}, authData...), clientHash[:]...))
	signature, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	body, err := json.Marshal(deviceCompleteRequest{
		ChallengeID: issued.ChallengeID, SessionID: assuranceSession, CredentialID: deviceCredentialID,
		AuthenticatorData: base64.RawURLEncoding.EncodeToString(authData),
		ClientDataJSON:    base64.RawURLEncoding.EncodeToString(clientData),
		Signature:         base64.RawURLEncoding.EncodeToString(signature),
	})
	if err != nil {
		t.Fatalf("encode completion: %v", err)
	}
	complete := post(t, server, "/v1/assurance/device/complete", string(body), nil)
	if complete.Code != http.StatusOK {
		t.Fatalf("complete status=%d body=%s", complete.Code, complete.Body.String())
	}
	var result deviceCompleteResponse
	if err := json.Unmarshal(complete.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode completion: %v", err)
	}
	return result.Attestation
}

func TestDeviceCeremonyYieldsAnAttestationRecordedInTheAssertion(t *testing.T) {
	devices, key := deviceService(t)
	config, public := assuranceConfig(t, 70)
	server := assuranceServer(t, assuranceEngine{evidence: verifiedSequence()}, config).
		WithLiveness(livenessService(t)).WithDeviceAttestation(devices)

	attestation := completeCeremony(t, server, key, "login", "login")
	if attestation == "" {
		t.Fatal("a completed ceremony produced no attestation")
	}

	body := `{"session_id":"` + assuranceSession + `","action":"login","endpoint_class":"login","sequence":1,"observations":{}}`
	response := post(t, server, "/v1/assurance", body,
		map[string]string{AudienceHeader: testAudience, DeviceAttestationHeader: attestation})
	verifier, err := palisadeassurance.NewVerifier(public, testAudience)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	verified, err := verifier.Verify(response.Body.Bytes(), time.Now().UTC())
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	// A device credential alone is possession, not presence, so the level is
	// unchanged and the assertion says only that interaction evidence backed it.
	if verified.Payload.AssuranceLevel != palisadeassurance.LevelBehavioral {
		t.Fatalf("a device credential changed the level to %d", verified.Payload.AssuranceLevel)
	}
	if strings.Contains(response.Body.String(), "attested_device_credential_verified") {
		t.Fatalf("device evidence was credited without the interactive step: %s", response.Body.String())
	}
}

func TestDeviceEvidenceIsRecordedOnlyWithLivenessAndIsThenWithheld(t *testing.T) {
	devices, key := deviceService(t)
	liveService := livenessService(t)
	config, _ := assuranceConfig(t, 71)
	server := assuranceServer(t, assuranceEngine{evidence: verifiedSequence()}, config).
		WithLiveness(liveService).WithDeviceAttestation(devices)

	device := completeCeremony(t, server, key, "login", "login")
	live := completeLiveness(t, server, liveService)

	response := post(t, server, "/v1/assurance",
		`{"session_id":"`+assuranceSession+`","action":"login","endpoint_class":"login","sequence":1,"observations":{}}`,
		map[string]string{
			AudienceHeader: testAudience, LivenessAttestationHeader: live, DeviceAttestationHeader: device,
		})
	body := response.Body.String()
	// The full stack computes H3. The ceiling withholds it, and the assertion
	// must say the level was withheld rather than unearned.
	if !strings.Contains(body, "attested_device_credential_verified") ||
		!strings.Contains(body, "level_withheld_pending_measurement") {
		t.Fatalf("the device ceremony was not recorded as withheld evidence: %s", body)
	}
	// A withheld level must not name the evidence it does not claim.
	if strings.Contains(body, `"device"`) {
		t.Fatalf("a withheld level named its evidence class: %s", body)
	}
}

func TestADeviceAttestationDoesNotTravel(t *testing.T) {
	devices, key := deviceService(t)
	config, _ := assuranceConfig(t, 72)
	server := assuranceServer(t, assuranceEngine{evidence: verifiedSequence()}, config).
		WithDeviceAttestation(devices)
	attestation := completeCeremony(t, server, key, "login", "login")

	for name, body := range map[string]string{
		"another action":   `{"session_id":"` + assuranceSession + `","action":"checkout","endpoint_class":"login","sequence":1,"observations":{}}`,
		"another endpoint": `{"session_id":"` + assuranceSession + `","action":"login","endpoint_class":"checkout","sequence":1,"observations":{}}`,
		"another session":  `{"session_id":"session-87654321","action":"login","endpoint_class":"login","sequence":1,"observations":{}}`,
	} {
		response := post(t, server, "/v1/assurance", body,
			map[string]string{AudienceHeader: testAudience, DeviceAttestationHeader: attestation})
		if response.Code != http.StatusOK {
			t.Fatalf("%s status=%d", name, response.Code)
		}
		if strings.Contains(response.Body.String(), "attested_device_credential_verified") {
			t.Fatalf("%s accepted an attestation earned elsewhere", name)
		}
	}
	// A forged attestation is ignored rather than accepted or fatal.
	response := post(t, server, "/v1/assurance",
		`{"session_id":"`+assuranceSession+`","action":"login","endpoint_class":"login","sequence":1,"observations":{}}`,
		map[string]string{AudienceHeader: testAudience, DeviceAttestationHeader: "forged"})
	if response.Code != http.StatusOK {
		t.Fatalf("a forged attestation produced status %d", response.Code)
	}
}

func TestAFailedCeremonyRevealsNothing(t *testing.T) {
	devices, _ := deviceService(t)
	config, _ := assuranceConfig(t, 73)
	server := assuranceServer(t, assuranceEngine{}, config).WithDeviceAttestation(devices)

	begin := post(t, server, "/v1/assurance/device/challenge",
		`{"session_id":"`+assuranceSession+`","action":"login","endpoint_class":"login"}`, nil)
	var issued deviceChallengeResponse
	if err := json.Unmarshal(begin.Body.Bytes(), &issued); err != nil {
		t.Fatalf("decode: %v", err)
	}
	body, err := json.Marshal(deviceCompleteRequest{
		ChallengeID: issued.ChallengeID, SessionID: assuranceSession,
		CredentialID: "an-unregistered-credential", AuthenticatorData: base64.RawURLEncoding.EncodeToString([]byte("x")),
		ClientDataJSON: base64.RawURLEncoding.EncodeToString([]byte("{}")), Signature: base64.RawURLEncoding.EncodeToString([]byte("x")),
	})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	response := post(t, server, "/v1/assurance/device/complete", string(body), nil)
	if response.Code != http.StatusConflict {
		t.Fatalf("status=%d", response.Code)
	}
	// Saying whether the credential was unknown, the signature wrong or the
	// counter stale would say which constraint to work on, and would reveal
	// whether a credential identifier is registered here.
	for _, leak := range []string{"credential", "signature", "counter", "presence", "unknown"} {
		if strings.Contains(response.Body.String(), leak) {
			t.Fatalf("the failure reported %q: %s", leak, response.Body.String())
		}
	}
}

func TestDeviceEndpointsAreDisabledUnlessConfigured(t *testing.T) {
	config, _ := assuranceConfig(t, 74)
	server := assuranceServer(t, assuranceEngine{}, config)
	for _, path := range []string{"/v1/assurance/device/challenge", "/v1/assurance/device/complete"} {
		if response := post(t, server, path, `{}`, nil); response.Code != http.StatusNotImplemented {
			t.Fatalf("%s produced status %d instead of failing closed", path, response.Code)
		}
	}
}
