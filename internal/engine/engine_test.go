package engine

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/palisade-bot-defense/palisade/internal/core"
	"github.com/palisade-bot-defense/palisade/internal/detector"
	"github.com/palisade-bot-defense/palisade/internal/policy"
	"github.com/palisade-bot-defense/palisade/internal/rollout"
	"github.com/palisade-bot-defense/palisade/internal/session"
	"github.com/palisade-bot-defense/palisade/internal/token"
)

func TestShadowModeOverridesRiskyComputedAction(t *testing.T) {
	engine := newTestEngine(t, core.RuntimeModeShadow)
	decision, err := engine.Decide(context.Background(), highRiskRequest())
	if err != nil {
		t.Fatal(err)
	}
	if decision.ComputedAction != core.ActionBlock || decision.Action != core.ActionObserve {
		t.Fatalf("unexpected shadow actions: computed=%s enforced=%s", decision.ComputedAction, decision.Action)
	}
	if decision.Mode != core.RuntimeModeShadow {
		t.Fatalf("mode = %s, want shadow", decision.Mode)
	}
	if !hasReason(decision.ReasonCodes, core.ReasonShadowActionOverridden) {
		t.Fatalf("missing %s in %v", core.ReasonShadowActionOverridden, decision.ReasonCodes)
	}
	if decision.PolicyVersion != "default-v4" || decision.ModelVersion != "transparent-baseline-v8" {
		t.Fatalf("unexpected versions: policy=%s model=%s", decision.PolicyVersion, decision.ModelVersion)
	}
}

func TestEnforceModeUsesComputedAction(t *testing.T) {
	engine := newTestEngine(t, core.RuntimeModeEnforce)
	decision, err := engine.Decide(context.Background(), highRiskRequest())
	if err != nil {
		t.Fatal(err)
	}
	if decision.ComputedAction != core.ActionBlock || decision.Action != core.ActionBlock {
		t.Fatalf("unexpected enforce actions: computed=%s enforced=%s", decision.ComputedAction, decision.Action)
	}
	if decision.Mode != core.RuntimeModeEnforce {
		t.Fatalf("mode = %s, want enforce", decision.Mode)
	}
	if hasReason(decision.ReasonCodes, core.ReasonShadowActionOverridden) {
		t.Fatalf("unexpected shadow override reason in %v", decision.ReasonCodes)
	}
}

func TestSignedRolloutProducesOriginDirective(t *testing.T) {
	base := newTestEngine(t, core.RuntimeModeShadow)
	now := time.Unix(1_800_000_000, 0).UTC()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	plan := rollout.Plan{
		SchemaVersion: rollout.SchemaVersion, RolloutID: "enforce-test", ApprovalID: "review-test", PredecessorRolloutID: "canary-test",
		CreatedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339),
		SourceReportSHA256: strings.Repeat("a", 64), SourceReadinessState: "operator_review_candidate",
		PolicyVersion: "default-v4", ModelVersion: "transparent-baseline-v8", Stage: core.RuntimeModeEnforce,
		EndpointClasses: []string{"public_content"}, MaxAction: core.ActionBlock, CanaryBasisPoints: rollout.FullRolloutBasisPoints,
		ThrottleSeconds: 5, ChallengeTTLSeconds: 300, BlockSeconds: 300,
	}
	signed, err := rollout.Sign(plan, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	controller, err := rollout.NewController(signed, publicKey, []byte("0123456789abcdef0123456789abcdef"), "default-v4", "transparent-baseline-v8", now)
	if err != nil {
		t.Fatal(err)
	}
	base.rollout = controller
	request := highRiskRequest()
	request.EndpointClass = "public_content"
	decision, err := base.Decide(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Action != core.ActionBlock || decision.Mode != core.RuntimeModeEnforce || decision.RolloutID != "enforce-test" {
		t.Fatalf("decision=%+v", decision)
	}
	if decision.Directive.Handling != "block" || decision.Directive.HTTPStatus != 403 || decision.Directive.RetryAfterSeconds != 300 {
		t.Fatalf("directive=%+v", decision.Directive)
	}
}

func TestUnknownModeFailsClosedToShadow(t *testing.T) {
	engine := newTestEngine(t, core.RuntimeMode("unknown"))
	decision, err := engine.Decide(context.Background(), highRiskRequest())
	if err != nil {
		t.Fatal(err)
	}
	if decision.Mode != core.RuntimeModeShadow || decision.Action != core.ActionObserve {
		t.Fatalf("unknown mode did not fail closed: %+v", decision)
	}
}

func TestDecisionRejectsFreeFormEvaluationCohort(t *testing.T) {
	current := newTestEngine(t, core.RuntimeModeShadow)
	request := highRiskRequest()
	request.EvaluationCohort = "browser-fingerprint-value"
	if _, err := current.Decide(context.Background(), request); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("free-form evaluation cohort error = %v", err)
	}
}

func TestDecisionRejectsRawEndpointClass(t *testing.T) {
	current := newTestEngine(t, core.RuntimeModeShadow)
	request := highRiskRequest()
	request.EndpointClass = "/private/account?token=secret"
	if _, err := current.Decide(context.Background(), request); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("raw endpoint class error = %v", err)
	}
}

func TestDecisionRejectsFreeFormTransportClasses(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*core.Observations)
	}{
		{name: "protocol", mutate: func(observations *core.Observations) { observations.TransportProtocol = "raw-http-value" }},
		{name: "security", mutate: func(observations *core.Observations) { observations.TransportSecurity = "forwarded-user-value" }},
		{name: "address source", mutate: func(observations *core.Observations) { observations.ClientAddressSource = "198.51.100.7" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			current := newTestEngine(t, core.RuntimeModeShadow)
			request := highRiskRequest()
			test.mutate(&request.Observations)
			if _, err := current.Decide(context.Background(), request); !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("free-form transport class error = %v", err)
			}
		})
	}
}

func TestDecideAtRejectsProofEnforcement(t *testing.T) {
	engine := newTestEngineWithProof(t, core.RuntimeModeShadow, true)
	_, err := engine.DecideAt(context.Background(), highRiskRequest(), time.Unix(1_800_000_000, 0))
	if !errors.Is(err, ErrExplicitTimeWithProof) {
		t.Fatalf("DecideAt error = %v, want %v", err, ErrExplicitTimeWithProof)
	}
	_, err = engine.Decide(context.Background(), highRiskRequest())
	if !errors.Is(err, ErrProofRequired) {
		t.Fatalf("live Decide error = %v, want %v", err, ErrProofRequired)
	}
}

func TestDataBoundVelocityRemainsProgressiveInShadow(t *testing.T) {
	tests := []struct {
		name             string
		requests         int
		duration         time.Duration
		computedAction   core.Action
		expectedEvidence []string
	}{
		{name: "legacy count is low risk", requests: 41, duration: 30 * time.Second, computedAction: core.ActionAllow},
		{name: "slow volume computes delay", requests: 100, duration: 2 * time.Minute, computedAction: core.ActionDelay, expectedEvidence: []string{"SESSION_VOLUME_HIGH"}},
		{name: "fast high volume requests step up", requests: 100, duration: 30 * time.Second, computedAction: core.ActionChallenge, expectedEvidence: []string{"SESSION_VOLUME_HIGH", "SESSION_BURST_FAST"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			current := newVelocityTestEngine(t)
			start := time.Unix(1_800_000_000, 0).UTC()
			var decision core.Decision
			for index := 0; index < test.requests; index++ {
				offset := time.Duration(0)
				if test.requests > 1 {
					offset = time.Duration(index) * test.duration / time.Duration(test.requests-1)
				}
				var err error
				decision, err = current.DecideAt(context.Background(), core.DecisionRequest{
					SessionID: "velocity-session", Action: "read", EndpointClass: "public_content", Sequence: uint64(index + 1),
					Observations: core.Observations{UserAgentPresent: true},
				}, start.Add(offset))
				if err != nil {
					t.Fatal(err)
				}
			}
			if decision.ComputedAction != test.computedAction {
				t.Fatalf("computed action = %s, want %s; evidence=%+v scores=%+v", decision.ComputedAction, test.computedAction, decision.Evidence, decision.Scores)
			}
			if decision.Action != core.ActionAllow && decision.Action != core.ActionObserve {
				t.Fatalf("shadow enforced unsafe action %s", decision.Action)
			}
			for _, expected := range test.expectedEvidence {
				if !hasEvidence(decision.Evidence, expected) {
					t.Fatalf("missing evidence %s in %+v", expected, decision.Evidence)
				}
			}
		})
	}
}

func newTestEngine(t *testing.T, mode core.RuntimeMode) *Engine {
	return newTestEngineWithProof(t, mode, false)
}

func newTestEngineWithProof(t *testing.T, mode core.RuntimeMode, requireProof bool) *Engine {
	t.Helper()
	tokens, err := token.NewService([]byte("0123456789abcdef0123456789abcdef"), token.NewMemoryNonceStore())
	if err != nil {
		t.Fatal(err)
	}
	policyEngine, err := policy.NewDefault()
	if err != nil {
		t.Fatal(err)
	}
	fixedNow := time.Unix(1_800_000_000, 0).UTC()
	return New(
		session.NewMemoryStore(time.Minute, 100),
		detector.NewRegistry(),
		policyEngine,
		tokens,
		requireProof,
		mode,
		WithClock(func() time.Time { return fixedNow }),
		WithDecisionIDGenerator(func() string { return "decision-test" }),
	)
}

func newVelocityTestEngine(t *testing.T) *Engine {
	t.Helper()
	tokens, err := token.NewService([]byte("0123456789abcdef0123456789abcdef"), token.NewMemoryNonceStore())
	if err != nil {
		t.Fatal(err)
	}
	policyEngine, err := policy.NewDefault()
	if err != nil {
		t.Fatal(err)
	}
	return New(
		session.NewMemoryStore(5*time.Minute, 100),
		detector.NewRegistry(detector.SequenceVelocity{}),
		policyEngine,
		tokens,
		false,
		core.RuntimeModeShadow,
		WithDecisionIDGenerator(func() string { return "velocity-decision" }),
	)
}

func highRiskRequest() core.DecisionRequest {
	return core.DecisionRequest{
		SessionID: "session-12345678", Action: "read", EndpointClass: "account", Sequence: 1,
		Observations: core.Observations{HoneypotHits: 1, PolicyAlert: true},
	}
}

func hasReason(reasons []string, expected string) bool {
	for _, reason := range reasons {
		if reason == expected {
			return true
		}
	}
	return false
}

func hasEvidence(evidence []core.Evidence, expected string) bool {
	for _, item := range evidence {
		if item.Code == expected {
			return true
		}
	}
	return false
}
