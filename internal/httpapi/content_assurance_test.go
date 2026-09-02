package httpapi

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/palisade-human-trust/palisade/pkg/palisadeassurance"
)

// The content surface mints an assertion bound to a message the sender
// committed to. PALISADE never sees the message; a recipient verifies the
// assertion with its own client and checks the commitment against what it
// received.

func contentRequestBody(t *testing.T, commitment string) string {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"session_id": assuranceSession, "action": "write", "endpoint_class": "other",
		"sequence": 1, "observations": map[string]any{}, "content_commitment": commitment,
	})
	if err != nil {
		t.Fatalf("encode body: %v", err)
	}
	return string(body)
}

func TestContentSurfaceMintsAnAssertionBoundToTheMessage(t *testing.T) {
	config, public := assuranceConfig(t, 50)
	server := assuranceServer(t, assuranceEngine{evidence: verifiedSequence()}, config)
	message := []byte("the message that was actually sent")

	response := post(t, server, "/v1/assurance/content",
		contentRequestBody(t, palisadeassurance.ContentCommitment(message)),
		map[string]string{AudienceHeader: testAudience})
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	// The message itself must not appear anywhere in what PALISADE emits.
	if strings.Contains(response.Body.String(), "actually sent") {
		t.Fatalf("the assertion carried the message: %s", response.Body.String())
	}

	verifier, err := palisadeassurance.NewVerifier(public, testAudience)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	// Read the next day: a message is read later than it is sent.
	verified, err := verifier.Verify(response.Body.Bytes(), time.Now().UTC().Add(20*time.Hour))
	if err != nil {
		t.Fatalf("a content assertion did not verify the next day: %v", err)
	}
	if verified.Payload.Binding.Profile != palisadeassurance.ProfileContent {
		t.Fatalf("profile = %q", verified.Payload.Binding.Profile)
	}
	if verified.Payload.AssuranceLevel != palisadeassurance.LevelBehavioral {
		t.Fatalf("level = %d", verified.Payload.AssuranceLevel)
	}
	if !verified.MatchesContent(message) {
		t.Fatal("the assertion did not match the message it was minted for")
	}
	if verified.MatchesContent([]byte("a forwarded or altered message")) {
		t.Fatal("the assertion matched a different message")
	}
	// Evidence age is the issue time; a recipient shows it separately from
	// validity.
	if time.Since(verified.IssuedAt) > time.Minute {
		t.Fatalf("issued_at does not record the send time: %v", verified.IssuedAt)
	}
}

func TestContentSurfaceRefusesAMalformedOrMissingCommitment(t *testing.T) {
	config, _ := assuranceConfig(t, 51)
	server := assuranceServer(t, assuranceEngine{evidence: verifiedSequence()}, config)

	for name, commitment := range map[string]string{
		"missing":       "",
		"too short":     "abc",
		"not base64url": strings.Repeat("!", 43),
		"wrong length":  strings.Repeat("A", 44),
	} {
		response := post(t, server, "/v1/assurance/content", contentRequestBody(t, commitment),
			map[string]string{AudienceHeader: testAudience})
		if response.Code != http.StatusBadRequest {
			t.Fatalf("%s commitment produced status %d", name, response.Code)
		}
	}
	// A commitment must never be inferred: an omitted field is refused too.
	response := post(t, server, "/v1/assurance/content",
		`{"session_id":"`+assuranceSession+`","action":"write","endpoint_class":"other","sequence":1,"observations":{}}`,
		map[string]string{AudienceHeader: testAudience})
	if response.Code != http.StatusBadRequest {
		t.Fatalf("an omitted commitment produced status %d", response.Code)
	}
}

func TestContentAssertionIsScopedToItsRecipient(t *testing.T) {
	config, public := assuranceConfig(t, 52, "alice.example", "bob.example")
	server := assuranceServer(t, assuranceEngine{evidence: verifiedSequence()}, config)
	message := []byte("for one recipient")
	response := post(t, server, "/v1/assurance/content",
		contentRequestBody(t, palisadeassurance.ContentCommitment(message)),
		map[string]string{AudienceHeader: "alice.example"})
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	// Bob's client must not be able to verify an assertion minted for Alice,
	// even holding the same message.
	other, err := palisadeassurance.NewVerifier(public, "bob.example")
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	if _, err := other.Verify(response.Body.Bytes(), time.Now().UTC()); err == nil {
		t.Fatal("an assertion minted for one recipient verified for another")
	}
}

func TestContentSurfaceIsDisabledWhenTheTTLExceedsTheContract(t *testing.T) {
	config, _ := assuranceConfig(t, 53)
	config.ContentAssertionTTL = palisadeassurance.MaximumContentLifetime + time.Hour
	server := assuranceServer(t, assuranceEngine{}, config)
	if server.AssuranceVerificationKey() != nil {
		t.Fatal("a content TTL beyond the contract enabled the surface")
	}
	response := post(t, server, "/v1/assurance/content",
		contentRequestBody(t, palisadeassurance.ContentCommitment([]byte("x"))),
		map[string]string{AudienceHeader: testAudience})
	if response.Code != http.StatusNotImplemented {
		t.Fatalf("status=%d", response.Code)
	}
}

func TestContentSurfaceLeavesTheRequestSurfaceUnchanged(t *testing.T) {
	config, public := assuranceConfig(t, 54)
	server := assuranceServer(t, assuranceEngine{evidence: verifiedSequence()}, config)
	response := post(t, server, "/v1/assurance",
		`{"session_id":"`+assuranceSession+`","action":"login","endpoint_class":"login","sequence":1,"observations":{}}`,
		map[string]string{AudienceHeader: testAudience})
	verifier, err := palisadeassurance.NewVerifier(public, testAudience)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	verified, err := verifier.Verify(response.Body.Bytes(), time.Now().UTC())
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if verified.Payload.Binding.Profile != palisadeassurance.ProfileRequest || verified.Payload.Binding.ContentCommitment != "" {
		t.Fatalf("the request surface changed profile: %+v", verified.Payload.Binding)
	}
	if verified.MatchesContent([]byte("anything")) {
		t.Fatal("a request assertion matched content")
	}
}
