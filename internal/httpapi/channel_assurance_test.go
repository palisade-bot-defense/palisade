package httpapi

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/palisade-human-trust/palisade/pkg/palisadeassurance"
)

// The call surface: one assertion per interval for as long as the call lasts.
// The other participant's client verifies each one and checks that it
// continues the channel the call started on.

func channelRequestBody(t *testing.T, channelID string) string {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"session_id": assuranceSession, "action": "other", "endpoint_class": "other",
		"sequence": 1, "observations": map[string]any{}, "channel_id": channelID,
	})
	if err != nil {
		t.Fatalf("encode body: %v", err)
	}
	return string(body)
}

func TestChannelSurfaceMintsAnAssertionForTheCurrentInterval(t *testing.T) {
	config, public := assuranceConfig(t, 60)
	server := assuranceServer(t, assuranceEngine{evidence: verifiedSequence()}, config)

	response := post(t, server, "/v1/assurance/channel", channelRequestBody(t, "call-identifier-0001"),
		map[string]string{AudienceHeader: testAudience})
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	verifier, err := palisadeassurance.NewVerifier(public, testAudience)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	now := time.Now().UTC()
	verified, err := verifier.Verify(response.Body.Bytes(), now)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if verified.Payload.Binding.Profile != palisadeassurance.ProfileChannel {
		t.Fatalf("profile = %q", verified.Payload.Binding.Profile)
	}
	// The deployment, not the client, decides which interval this is.
	if verified.Payload.Binding.IntervalIndex == nil || *verified.Payload.Binding.IntervalIndex != palisadeassurance.IntervalIndex(now) {
		t.Fatalf("interval = %v, want %d", verified.Payload.Binding.IntervalIndex, palisadeassurance.IntervalIndex(now))
	}
	// Presence must be re-established: the assertion cannot outlive the bound.
	if verified.ExpiresAt.Sub(verified.IssuedAt) > palisadeassurance.MaximumChannelLifetime {
		t.Fatalf("channel assertion lives %v", verified.ExpiresAt.Sub(verified.IssuedAt))
	}
	if _, err := verifier.Verify(response.Body.Bytes(), now.Add(3*time.Minute)); err != palisadeassurance.ErrExpired {
		t.Fatalf("a channel assertion three minutes old was not expired: %v", err)
	}
}

func TestChannelContinuityIsTheOtherParticipantsCheck(t *testing.T) {
	config, public := assuranceConfig(t, 61)
	server := assuranceServer(t, assuranceEngine{evidence: verifiedSequence()}, config)
	verifier, err := palisadeassurance.NewVerifier(public, testAudience)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	mint := func(channelID string) palisadeassurance.Verified {
		t.Helper()
		response := post(t, server, "/v1/assurance/channel", channelRequestBody(t, channelID),
			map[string]string{AudienceHeader: testAudience})
		if response.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
		}
		verified, err := verifier.Verify(response.Body.Bytes(), time.Now().UTC())
		if err != nil {
			t.Fatalf("verify: %v", err)
		}
		return verified
	}

	first := mint("call-identifier-0001")
	sameInterval := mint("call-identifier-0001")
	// Two assertions in the same interval re-attest nothing: the interval did
	// not advance, so the second is a replay as far as continuity goes.
	if sameInterval.ChannelContinues(first) {
		t.Fatal("an assertion for the same interval counted as a re-attestation")
	}
	// The same channel yields the same commitment, so a later interval would
	// continue it; another channel must not, whatever its interval.
	other := mint("call-identifier-0002")
	if other.Payload.Binding.ChannelBinding == first.Payload.Binding.ChannelBinding {
		t.Fatal("two channels produced the same commitment")
	}
	later := other
	next := *other.Payload.Binding.IntervalIndex + 1
	later.Payload.Binding.IntervalIndex = &next
	if later.ChannelContinues(first) {
		t.Fatal("another channel continued this one")
	}
	advanced := first
	advanced.Payload.Binding.IntervalIndex = &next
	if !advanced.ChannelContinues(first) {
		t.Fatal("a later interval on the same channel did not continue it")
	}
	// The channel commitment is per audience: another participant scope sees
	// a different commitment for the same call, so scopes cannot be linked.
	otherAudience := assuranceConfig2(t, 62, "other.example")
	otherServer := assuranceServer(t, assuranceEngine{evidence: verifiedSequence()}, otherAudience)
	response := post(t, otherServer, "/v1/assurance/channel", channelRequestBody(t, "call-identifier-0001"),
		map[string]string{AudienceHeader: "other.example"})
	var document struct {
		Payload struct {
			Binding struct {
				ChannelBinding string `json:"channel_binding"`
			} `json:"binding"`
		} `json:"payload"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &document); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if document.Payload.Binding.ChannelBinding == first.Payload.Binding.ChannelBinding {
		t.Fatal("the same call produced a linkable channel commitment across audiences")
	}
}

func TestChannelSurfaceRefusesABadChannelReference(t *testing.T) {
	config, _ := assuranceConfig(t, 63)
	server := assuranceServer(t, assuranceEngine{}, config)
	for name, channelID := range map[string]string{"missing": "", "short": "abc"} {
		response := post(t, server, "/v1/assurance/channel", channelRequestBody(t, channelID),
			map[string]string{AudienceHeader: testAudience})
		if response.Code != http.StatusBadRequest {
			t.Fatalf("%s channel produced status %d", name, response.Code)
		}
	}
	// A client-supplied interval is not a field: it is refused as unknown.
	response := post(t, server, "/v1/assurance/channel",
		`{"session_id":"`+assuranceSession+`","action":"other","endpoint_class":"other","sequence":1,"observations":{},"channel_id":"call-identifier-0001","interval_index":99999999}`,
		map[string]string{AudienceHeader: testAudience})
	if response.Code != http.StatusBadRequest {
		t.Fatalf("a client-supplied interval produced status %d", response.Code)
	}
}

// assuranceConfig2 mirrors assuranceConfig with the same binding secret so two
// servers represent the same deployment answering two audiences.
func assuranceConfig2(t *testing.T, seed byte, audience string) AssuranceConfig {
	t.Helper()
	config, _ := assuranceConfig(t, seed, audience)
	return config
}
