package engine

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/palisade-human-trust/palisade/internal/core"
	"github.com/palisade-human-trust/palisade/internal/detector"
	"github.com/palisade-human-trust/palisade/internal/policy"
	"github.com/palisade-human-trust/palisade/internal/rollout"
	"github.com/palisade-human-trust/palisade/internal/session"
	"github.com/palisade-human-trust/palisade/internal/token"
)

const pilotDecisionP95Budget = 10 * time.Millisecond

func TestInProcessDecisionP95MeetsPilotBudget(t *testing.T) {
	current := newProductionPathTestEngine(t)
	request := performanceRequest()
	assertDecisionP95(t, current, request)
}

func TestSignedAdaptiveRolloutP95MeetsPilotBudget(t *testing.T) {
	current := newProductionPathTestEngine(t)
	configureSignedAdaptiveRollout(t, current)
	request := performanceRequest()
	request.Observations.HoneypotHits = 1
	request.Observations.PolicyAlert = true
	assertDecisionP95(t, current, request)
}

func configureSignedAdaptiveRollout(testingContext testing.TB, current *Engine) {
	testingContext.Helper()
	now := time.Unix(1_800_000_000, 0).UTC()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		testingContext.Fatal(err)
	}
	plan := rollout.Plan{
		SchemaVersion: rollout.SchemaVersion, RolloutID: "adaptive-performance", ApprovalID: "review-performance", PredecessorRolloutID: "canary-performance",
		CreatedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339),
		SourceReportSHA256: strings.Repeat("a", 64), SourceReadinessState: "operator_review_candidate",
		PolicyVersion: policy.DefaultVersion, ModelVersion: ModelVersion, Stage: core.RuntimeModeEnforce,
		EndpointClasses: []string{"public_content"}, MaxAction: core.ActionBlock, CanaryBasisPoints: rollout.FullRolloutBasisPoints,
		ThrottleSeconds: rollout.DefaultThrottleSeconds, ChallengeTTLSeconds: rollout.DefaultChallengeTTLSeconds, BlockSeconds: rollout.DefaultBlockSeconds,
		MinMatureChallenges: rollout.DefaultMinMatureChallenges, MinChallengeOutcomeCoverage: rollout.DefaultMinChallengeOutcomeCoverage,
		MaxChallengeAbandonmentRate: rollout.DefaultMaxChallengeAbandonmentRate, MaxChallengeFallbackRate: rollout.DefaultMaxChallengeFallbackRate,
	}
	signed, err := rollout.Sign(plan, privateKey)
	if err != nil {
		testingContext.Fatal(err)
	}
	controller, err := rollout.NewController(signed, publicKey, []byte("0123456789abcdef0123456789abcdef"), policy.DefaultVersion, ModelVersion, now)
	if err != nil {
		testingContext.Fatal(err)
	}
	current.rollout = controller
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
	p50 := durations[(samples*50+99)/100-1]
	p95 := durations[(samples*95+99)/100-1]
	p99 := durations[(samples*99+99)/100-1]
	t.Logf(
		"PALISADE_BENCHMARK_LATENCY p50_ns=%d p95_ns=%d p99_ns=%d budget_ns=%d samples=%d",
		p50.Nanoseconds(), p95.Nanoseconds(), p99.Nanoseconds(), pilotDecisionP95Budget.Nanoseconds(), samples,
	)
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

func BenchmarkSignedAdaptiveDecisionPath(b *testing.B) {
	current := newProductionPathTestEngine(b)
	configureSignedAdaptiveRollout(b, current)
	request := performanceRequest()
	request.Observations.HoneypotHits = 1
	request.Observations.PolicyAlert = true
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
