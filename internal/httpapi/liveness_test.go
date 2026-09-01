package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/palisade-human-trust/palisade/internal/liveness"
	"github.com/palisade-human-trust/palisade/pkg/palisadeassurance"
)

func livenessService(t *testing.T) *liveness.Service {
	t.Helper()
	service, err := liveness.New(liveness.Config{Secret: []byte("liveness-attestation-secret-32-bytes")})
	if err != nil {
		t.Fatalf("liveness service: %v", err)
	}
	return service
}

func post(t *testing.T, server *Server, path, body string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, path, bytes.NewBufferString(body))
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	return response
}

// completeLiveness walks the whole challenge and returns the attestation.
//
// The transport deliberately never discloses a round's target, so a test cannot
// learn it from the HTTP response. It therefore opens the attempt through the
// service, which knows the target, and answers every round through HTTP. Both
// share one service instance, so the state is the same one the handler sees.
func completeLiveness(t *testing.T, server *Server, service *liveness.Service) string {
	t.Helper()
	id, prompt, err := service.Begin(assuranceSession, "login", "login", time.Now().UTC())
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	for {
		// The reaction floor is real: answering in microseconds is refused, so
		// the test waits like a person would.
		time.Sleep(liveness.MinimumResponse + 10*time.Millisecond)
		body, err := json.Marshal(livenessAnswerRequest{
			ChallengeID: id, SessionID: assuranceSession, Round: prompt.Round, Answer: prompt.Target,
		})
		if err != nil {
			t.Fatalf("encode answer: %v", err)
		}
		response := post(t, server, "/v1/assurance/liveness/answer", string(body), nil)
		if response.Code != http.StatusOK {
			t.Fatalf("answer status=%d body=%s", response.Code, response.Body.String())
		}
		var progress liveness.Progress
		if err := json.Unmarshal(response.Body.Bytes(), &progress); err != nil {
			t.Fatalf("decode answer: %v", err)
		}
		if progress.Completed {
			return progress.Attestation
		}
		// The HTTP response withholds the target, so the next round's target
		// comes from the service the handler just advanced.
		prompt = nextTarget(t, service, id, progress)
	}
}

// nextTarget re-reads the round the handler just revealed. The service exposes
// it to this package's tests only; no client ever sees it.
func nextTarget(t *testing.T, service *liveness.Service, id string, progress liveness.Progress) liveness.Prompt {
	t.Helper()
	prompt, ok := service.PromptForTest(id, progress.Next.Round)
	if !ok {
		t.Fatalf("round %d is not open", progress.Next.Round)
	}
	return prompt
}

func TestLivenessEndpointsCompleteAndRaiseNothingOnTheirOwn(t *testing.T) {
	service := livenessService(t)
	config, public := assuranceConfig(t, 40)
	server := assuranceServer(t, assuranceEngine{evidence: verifiedSequence()}, config).WithLiveness(service)

	attestation := completeLiveness(t, server, service)
	if attestation == "" {
		t.Fatal("a completed challenge produced no attestation")
	}

	// Without the attestation the assertion stays at the behavioral level.
	plain := post(t, server, "/v1/assurance",
		`{"session_id":"`+assuranceSession+`","action":"login","endpoint_class":"login","sequence":1,"observations":{}}`,
		map[string]string{AudienceHeader: testAudience})
	verifier, err := palisadeassurance.NewVerifier(public, testAudience)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	without, err := verifier.Verify(plain.Body.Bytes(), time.Now().UTC())
	if err != nil {
		t.Fatalf("verify: %v", err)
	}

	// With it, the level is still H1 because the ceiling withholds H2, but the
	// assertion must say that a liveness challenge was completed and that the
	// level was withheld rather than unearned.
	withAttestation := post(t, server, "/v1/assurance",
		`{"session_id":"`+assuranceSession+`","action":"login","endpoint_class":"login","sequence":1,"observations":{}}`,
		map[string]string{AudienceHeader: testAudience, LivenessAttestationHeader: attestation})
	with, err := verifier.Verify(withAttestation.Body.Bytes(), time.Now().UTC())
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if with.Payload.AssuranceLevel != without.Payload.AssuranceLevel {
		t.Fatalf("liveness changed the granted level from %d to %d",
			without.Payload.AssuranceLevel, with.Payload.AssuranceLevel)
	}
	body := withAttestation.Body.String()
	if !strings.Contains(body, "interactive_liveness_completed") ||
		!strings.Contains(body, "level_withheld_pending_measurement") {
		t.Fatalf("the completed challenge was not recorded in the assertion: %s", body)
	}
}

func TestAttestationIsRefusedForAnotherActionOrSession(t *testing.T) {
	service := livenessService(t)
	config, _ := assuranceConfig(t, 41)
	server := assuranceServer(t, assuranceEngine{evidence: verifiedSequence()}, config).WithLiveness(service)
	attestation := completeLiveness(t, server, service)

	for name, body := range map[string]string{
		"another action":   `{"session_id":"` + assuranceSession + `","action":"checkout","endpoint_class":"login","sequence":1,"observations":{}}`,
		"another endpoint": `{"session_id":"` + assuranceSession + `","action":"login","endpoint_class":"checkout","sequence":1,"observations":{}}`,
		"another session":  `{"session_id":"session-87654321","action":"login","endpoint_class":"login","sequence":1,"observations":{}}`,
	} {
		response := post(t, server, "/v1/assurance", body,
			map[string]string{AudienceHeader: testAudience, LivenessAttestationHeader: attestation})
		if response.Code != http.StatusOK {
			t.Fatalf("%s status=%d", name, response.Code)
		}
		if strings.Contains(response.Body.String(), "interactive_liveness_completed") {
			t.Fatalf("%s accepted an attestation earned elsewhere: %s", name, response.Body.String())
		}
	}

	// A forged attestation is ignored rather than accepted or fatal.
	response := post(t, server, "/v1/assurance",
		`{"session_id":"`+assuranceSession+`","action":"login","endpoint_class":"login","sequence":1,"observations":{}}`,
		map[string]string{AudienceHeader: testAudience, LivenessAttestationHeader: "forged"})
	if response.Code != http.StatusOK || strings.Contains(response.Body.String(), "interactive_liveness_completed") {
		t.Fatalf("a forged attestation was honoured: %d %s", response.Code, response.Body.String())
	}
}

func TestLivenessPromptNeverDisclosesItsTarget(t *testing.T) {
	service := livenessService(t)
	config, _ := assuranceConfig(t, 42)
	server := assuranceServer(t, assuranceEngine{}, config).WithLiveness(service)

	response := post(t, server, "/v1/assurance/liveness",
		`{"session_id":"`+assuranceSession+`","action":"login","endpoint_class":"login"}`, nil)
	if response.Code != http.StatusOK {
		t.Fatalf("begin status=%d body=%s", response.Code, response.Body.String())
	}
	// Disclosing the target would make the challenge answerable without
	// reacting to it, which is the whole mechanism.
	if strings.Contains(response.Body.String(), `"target"`) {
		t.Fatalf("the prompt disclosed its target: %s", response.Body.String())
	}
	var begun map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &begun); err != nil {
		t.Fatalf("decode: %v", err)
	}
	prompt, ok := begun["prompt"].(map[string]any)
	if !ok {
		t.Fatalf("no prompt in %v", begun)
	}
	if len(prompt) != 3 {
		t.Fatalf("the prompt carries unexpected fields: %v", prompt)
	}
}

func TestFailedRoundsRevealNothingAndEndTheAttempt(t *testing.T) {
	service := livenessService(t)
	config, _ := assuranceConfig(t, 43)
	server := assuranceServer(t, assuranceEngine{}, config).WithLiveness(service)

	response := post(t, server, "/v1/assurance/liveness",
		`{"session_id":"`+assuranceSession+`","action":"login","endpoint_class":"login"}`, nil)
	var begun livenessBeginResponse
	if err := json.Unmarshal(response.Body.Bytes(), &begun); err != nil {
		t.Fatalf("decode begin: %v", err)
	}

	wrong := post(t, server, "/v1/assurance/liveness/answer",
		`{"challenge_id":"`+begun.ChallengeID+`","session_id":"`+assuranceSession+`","round":0,"answer":"definitely-not-an-option"}`, nil)
	if wrong.Code != http.StatusConflict {
		t.Fatalf("a wrong answer produced status %d", wrong.Code)
	}
	// The error must not say which constraint failed: distinguishing "too fast"
	// from "wrong answer" tells an attacker which one to tune.
	for _, leak := range []string{"too_fast", "wrong", "expired", "target"} {
		if strings.Contains(wrong.Body.String(), leak) {
			t.Fatalf("the failure reported %q: %s", leak, wrong.Body.String())
		}
	}
}

func TestLivenessEndpointsAreDisabledUnlessConfigured(t *testing.T) {
	config, _ := assuranceConfig(t, 44)
	server := assuranceServer(t, assuranceEngine{}, config)
	for _, path := range []string{"/v1/assurance/liveness", "/v1/assurance/liveness/answer"} {
		if response := post(t, server, path, `{}`, nil); response.Code != http.StatusNotImplemented {
			t.Fatalf("%s produced status %d instead of failing closed", path, response.Code)
		}
	}
}
