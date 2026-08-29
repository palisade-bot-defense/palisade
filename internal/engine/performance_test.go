package engine

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"sort"
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

const pilotDecisionP95Budget = 10 * time.Millisecond

func TestInProcessDecisionP95MeetsPilotBudget(t *testing.T) {
	current := newProductionPathTestEngine(t)
	request := performanceRequest()
	assertDecisionP95(t, current, request)
}

func TestSignedAdaptiveRolloutP95MeetsPilotBudget(t *testing.T) {
	current := newProductionPathTestEngine(t)
	now := time.Unix(1_800_000_000, 0).UTC()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	plan := rollout.Plan{
		SchemaVersion: rollout.SchemaVersion, RolloutID: "adaptive-performance", ApprovalID: "review-performance", PredecessorRolloutID: "canary-performance",
		CreatedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339),
		SourceReportSHA256: strings.Repeat("a", 64), SourceReadinessState: "operator_review_candidate",
		PolicyVersion: policy.DefaultVersion, ModelVersion: ModelVersion, Stage: core.RuntimeModeEnforce,
		EndpointClasses: []string{"public_content"}, MaxAction: core.ActionBlock, CanaryBasisPoints: rollout.FullRolloutBasisPoints,
		ThrottleSeconds: rollout.DefaultThrottleSeconds, ChallengeTTLSeconds: rollout.DefaultChallengeTTLSeconds, BlockSeconds: rollout.DefaultBlockSeconds,
	}
	signed, err := rollout.Sign(plan, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	controller, err := rollout.NewController(signed, publicKey, []byte("0123456789abcdef0123456789abcdef"), policy.DefaultVersion, ModelVersion, now)
	if err != nil {
		t.Fatal(err)
	}
	current.rollout = controller
	request := performanceRequest()
	request.Observations.HoneypotHits = 1
	request.Observations.PolicyAlert = true
	assertDecisionP95(t, current, request)
}

func assertDecisionP95(t *testing.T, current *Engine, request core.DecisionRequest) {
	t.Helper()
	for index := 0; index < 100; index++ {
		request.Sequence++
		if _, err := current.Decide(context.Background(), request); err != nil {
			t.Fatal(err)
		}
	}

	const samples = 1000
	durations := make([]time.Duration, 0, samples)
	for index := 0; index < samples; index++ {
		request.Sequence++
		started := time.Now()
		if _, err := current.Decide(context.Background(), request); err != nil {
			t.Fatal(err)
		}
		durations = append(durations, time.Since(started))
	}
	sort.Slice(durations, func(left, right int) bool { return durations[left] < durations[right] })
	p95 := durations[(samples*95+99)/100-1]
	t.Logf("in-process decision p95=%s budget=%s samples=%d", p95, pilotDecisionP95Budget, samples)
	if p95 >= pilotDecisionP95Budget {
		t.Fatalf("in-process decision p95 %s exceeds pilot budget %s", p95, pilotDecisionP95Budget)
	}
}

func BenchmarkProductionDecisionPath(b *testing.B) {
	current := newProductionPathTestEngine(b)
	request := performanceRequest()
	b.ReportAllocs()
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		request.Sequence++
		if _, err := current.Decide(context.Background(), request); err != nil {
			b.Fatal(err)
		}
	}
}

func newProductionPathTestEngine(testingContext testing.TB) *Engine {
	testingContext.Helper()
	tokens, err := token.NewService([]byte("0123456789abcdef0123456789abcdef"), token.NewMemoryNonceStore())
	if err != nil {
		testingContext.Fatal(err)
	}
	policyEngine, err := policy.NewDefault()
	if err != nil {
		testingContext.Fatal(err)
	}
	fixedNow := time.Unix(1_800_000_000, 0).UTC()
	return New(
		session.NewMemoryStore(5*time.Minute, 2048),
		detector.NewDefaultRegistry(),
		policyEngine,
		tokens,
		false,
		core.RuntimeModeShadow,
		WithClock(func() time.Time { return fixedNow }),
		WithDecisionIDGenerator(func() string { return "performance-decision" }),
	)
}

func performanceRequest() core.DecisionRequest {
	return core.DecisionRequest{
		SessionID: "performance-session", Action: "read", EndpointClass: "public_content",
		Observations: core.Observations{
			UserAgentPresent: true, ServerSessionVerified: true, BrowserEventsVerified: true,
			BrowserEventCount: 3, TransportProtocol: "http2", TransportSecurity: "direct_tls", ClientAddressSource: "direct",
		},
	}
}
