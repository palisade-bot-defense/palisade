package httpapi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/palisade-human-trust/palisade/internal/core"
	"github.com/palisade-human-trust/palisade/internal/token"
	"github.com/palisade-human-trust/palisade/pkg/palisadeassurance"
)

const (
	testAudience     = "relying.example"
	assuranceSession = "session-12345678"
)

// assuranceEngine returns a decision whose evidence PALISADE verified against
// its own event store, which is the only evidence that raises a level today.
type assuranceEngine struct{ evidence []core.Evidence }

func (e assuranceEngine) Decide(context.Context, core.DecisionRequest) (core.Decision, error) {
	return core.Decision{
		DecisionID:    "assurance-test",
		Action:        core.ActionAllow,
		Evidence:      e.evidence,
		PolicyVersion: "default-v5",
		ModelVersion:  "transparent-baseline-v13",
		ExpiresAt:     time.Now().UTC().Add(time.Minute),
	}, nil
}

func verifiedSequence() []core.Evidence {
	return []core.Evidence{{
		Code: "BROWSER_SEQUENCE_PRESENT", Detector: "protocol_consistency",
		Dimension: core.DimensionContinuity, Direction: core.DirectionBenign,
		Strength: .24, Confidence: .64,
	}}
}

func assuranceConfig(t *testing.T, seed byte, audiences ...string) (AssuranceConfig, ed25519.PublicKey) {
	t.Helper()
	raw := make([]byte, ed25519.SeedSize)
	for index := range raw {
		raw[index] = seed
	}
	private := ed25519.NewKeyFromSeed(raw)
	if len(audiences) == 0 {
		audiences = []string{testAudience}
	}
	return AssuranceConfig{
		SigningKey:       private,
		BindingSecret:    []byte("assurance-binding-secret-32-bytes!!"),
		AllowedAudiences: audiences,
	}, private.Public().(ed25519.PublicKey)
}

func assuranceServer(t *testing.T, engine DecisionEngine, config AssuranceConfig) *Server {
	t.Helper()
	tokens, err := token.NewService([]byte("0123456789abcdef0123456789abcdef"), token.NewMemoryNonceStore())
	if err != nil {
		t.Fatalf("token service: %v", err)
	}
	return New(engine, tokens, "key", slog.Default()).WithAssurance(config)
}

func assuranceRequest(audience string) *http.Request {
	body := `{"session_id":"` + assuranceSession + `","action":"login","endpoint_class":"login","sequence":1,"observations":{}}`
	request := httptest.NewRequest(http.MethodPost, "/v1/assurance", bytes.NewBufferString(body))
	if audience != "" {
		request.Header.Set(AudienceHeader, audience)
	}
	return request
}

func TestAssuranceSurfaceReturnsAVerifiableAssertion(t *testing.T) {
	config, public := assuranceConfig(t, 30)
	server := assuranceServer(t, assuranceEngine{evidence: verifiedSequence()}, config)

	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, assuranceRequest(testAudience))
	if response.Code != http.StatusOK {
		t.Fatalf("assurance status=%d body=%s", response.Code, response.Body.String())
	}
	if got := response.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("content type = %q", got)
	}

	verifier, err := palisadeassurance.NewVerifier(public, testAudience)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	verified, err := verifier.Verify(response.Body.Bytes(), time.Now().UTC())
	if err != nil {
		t.Fatalf("the emitted assertion did not verify: %v", err)
	}
	if verified.Payload.AssuranceLevel != palisadeassurance.LevelBehavioral {
		t.Fatalf("verified interaction evidence produced level %d", verified.Payload.AssuranceLevel)
	}
	if verified.Payload.Binding.RequestAction != "login" || verified.Payload.Binding.EndpointClass != "login" {
		t.Fatalf("the assertion was not bound to the request: %+v", verified.Payload.Binding)
	}
	if !assuranceResponseIsClosed(response.Body.Bytes()) {
		t.Fatalf("the response carries unexpected fields: %s", response.Body.String())
	}
}

func TestAssuranceResponseRevealsNoRiskDecision(t *testing.T) {
	config, _ := assuranceConfig(t, 31)
	server := assuranceServer(t, assuranceEngine{evidence: verifiedSequence()}, config)
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, assuranceRequest(testAudience))

	body := response.Body.String()
	// A relying service asking about human presence has no need for the risk
	// decision, and must not learn the raw session identifier either.
	for _, banned := range []string{
		"decision_id", "assurance-test", "scores", "automation_risk", "abuse_intent",
		"account_continuity", "computed_action", "directive", "rollout_id", assuranceSession,
	} {
		if strings.Contains(body, banned) {
			t.Fatalf("the assurance response leaked %q: %s", banned, body)
		}
	}
}

func TestAssuranceIsUnlinkableAcrossAudiences(t *testing.T) {
	config, _ := assuranceConfig(t, 32, "one.example", "two.example")
	server := assuranceServer(t, assuranceEngine{evidence: verifiedSequence()}, config)

	bindings := make([]string, 0, 2)
	for _, audience := range []string{"one.example", "two.example"} {
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, assuranceRequest(audience))
		if response.Code != http.StatusOK {
			t.Fatalf("%s status=%d body=%s", audience, response.Code, response.Body.String())
		}
		var document struct {
			Payload struct {
				Binding struct {
					SessionBinding string `json:"session_binding"`
				} `json:"binding"`
			} `json:"payload"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &document); err != nil {
			t.Fatalf("decode: %v", err)
		}
		bindings = append(bindings, document.Payload.Binding.SessionBinding)
	}
	if bindings[0] == bindings[1] {
		t.Fatal("the same session produced a linkable commitment across two relying services")
	}
}

func TestAssertionsAreMintedOnlyForAllowedAudiences(t *testing.T) {
	config, public := assuranceConfig(t, 33)
	server := assuranceServer(t, assuranceEngine{evidence: verifiedSequence()}, config)

	for name, audience := range map[string]string{
		"absent":       "",
		"unlisted":     "attacker.example",
		"uppercase":    "Relying.Example",
		"with spaces":  "relying example",
		"with a slash": "relying.example/x",
	} {
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, assuranceRequest(audience))
		if response.Code != http.StatusBadRequest {
			t.Fatalf("%s audience produced status %d", name, response.Code)
		}
	}

	// An assertion for the permitted audience must not verify for another one.
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, assuranceRequest(testAudience))
	foreign, err := palisadeassurance.NewVerifier(public, "other.example")
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	if _, err := foreign.Verify(response.Body.Bytes(), time.Now().UTC()); err == nil {
		t.Fatal("an assertion verified for an audience it was not minted for")
	}
}

func TestAssuranceSurfaceIsDisabledUnlessFullyConfigured(t *testing.T) {
	complete, _ := assuranceConfig(t, 34)
	for name, config := range map[string]AssuranceConfig{
		"no configuration at all": {},
		"missing signing key": {
			BindingSecret: complete.BindingSecret, AllowedAudiences: complete.AllowedAudiences},
		"short binding secret": {
			SigningKey: complete.SigningKey, BindingSecret: []byte("short"), AllowedAudiences: complete.AllowedAudiences},
		"no allowed audience": {
			SigningKey: complete.SigningKey, BindingSecret: complete.BindingSecret},
	} {
		server := assuranceServer(t, assuranceEngine{evidence: verifiedSequence()}, config)
		if server.AssuranceVerificationKey() != nil {
			t.Fatalf("%s enabled the surface", name)
		}
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, assuranceRequest(testAudience))
		if response.Code != http.StatusNotImplemented {
			t.Fatalf("%s produced status %d instead of failing closed", name, response.Code)
		}
	}
}

func TestAssuranceSurfaceLeavesTheDecisionSurfaceUnchanged(t *testing.T) {
	config, _ := assuranceConfig(t, 35)
	engine := assuranceEngine{evidence: verifiedSequence()}
	withAssurance := assuranceServer(t, engine, config)
	withoutAssurance := assuranceServer(t, engine, AssuranceConfig{})

	body := `{"session_id":"` + assuranceSession + `","action":"login","endpoint_class":"login","sequence":1,"observations":{}}`
	responses := make([]*httptest.ResponseRecorder, 0, 2)
	for _, server := range []*Server{withAssurance, withoutAssurance} {
		request := httptest.NewRequest(http.MethodPost, "/v1/decision", bytes.NewBufferString(body))
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("decision status=%d body=%s", response.Code, response.Body.String())
		}
		responses = append(responses, response)
	}
	// The decision expiry is wall-clock, so compare everything else exactly.
	first, second := withoutExpiry(t, responses[0].Body.Bytes()), withoutExpiry(t, responses[1].Body.Bytes())
	if first != second {
		t.Fatalf("enabling assurance changed the decision response:\n%s\n%s", first, second)
	}
	// The decision response must not gain an assertion either.
	if strings.Contains(responses[0].Body.String(), "assurance_level") {
		t.Fatalf("the decision response carries an assertion: %s", responses[0].Body.String())
	}
}

func TestAssuranceRejectsMalformedRequestsLikeTheDecisionSurface(t *testing.T) {
	config, _ := assuranceConfig(t, 36)
	server := assuranceServer(t, assuranceEngine{evidence: verifiedSequence()}, config)

	// A request outside the closed vocabulary is the caller's error, not an
	// outage. The engine here deliberately does not validate, so these cases
	// prove the assurance surface refuses to describe what it cannot express.
	for name, body := range map[string]string{
		"unknown field":  `{"session_id":"` + assuranceSession + `","action":"login","endpoint_class":"login","sequence":1,"observations":{},"unknown":true}`,
		"invalid json":   `{`,
		"raw endpoint":   `{"session_id":"` + assuranceSession + `","action":"login","endpoint_class":"/account/settings","sequence":1,"observations":{}}`,
		"unknown action": `{"session_id":"` + assuranceSession + `","action":"exfiltrate","endpoint_class":"login","sequence":1,"observations":{}}`,
		"short session":  `{"session_id":"abc","action":"login","endpoint_class":"login","sequence":1,"observations":{}}`,
	} {
		request := httptest.NewRequest(http.MethodPost, "/v1/assurance", bytes.NewBufferString(body))
		request.Header.Set(AudienceHeader, testAudience)
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("%s produced status %d instead of 400", name, response.Code)
		}
	}
}

func withoutExpiry(t *testing.T, encoded []byte) string {
	t.Helper()
	var document map[string]any
	if err := json.Unmarshal(encoded, &document); err != nil {
		t.Fatalf("decode decision: %v", err)
	}
	delete(document, "expires_at")
	normalized, err := json.Marshal(document)
	if err != nil {
		t.Fatalf("encode decision: %v", err)
	}
	return string(normalized)
}

func TestAssuranceReportsNoHumanEvidenceHonestly(t *testing.T) {
	config, public := assuranceConfig(t, 37)
	server := assuranceServer(t, assuranceEngine{}, config)

	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, assuranceRequest(testAudience))
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	verifier, err := palisadeassurance.NewVerifier(public, testAudience)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	verified, err := verifier.Verify(response.Body.Bytes(), time.Now().UTC())
	if err != nil {
		t.Fatalf("an unattributed assertion did not verify: %v", err)
	}
	// No evidence must produce a signed level 0, not an error and not a
	// missing response: "we could not establish presence" is a real answer.
	if verified.Payload.AssuranceLevel != palisadeassurance.LevelUnattributed {
		t.Fatalf("an evidence-free request produced level %d", verified.Payload.AssuranceLevel)
	}
	if verified.Satisfies(palisadeassurance.LevelBehavioral, false) {
		t.Fatal("an unattributed assertion satisfied a behavioral minimum")
	}
}
