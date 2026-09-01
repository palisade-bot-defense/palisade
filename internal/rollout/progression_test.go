package rollout

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/palisade-human-trust/palisade/internal/core"
)

func TestProgressionConformanceRemainsOrderedAndBounded(t *testing.T) {
	now := time.Date(2026, time.August, 29, 12, 0, 0, 0, time.UTC)
	controller := progressionController(t, now, core.ActionBlock)
	tests := []struct {
		name       string
		action     core.Action
		handling   string
		status     int
		retryAfter int
	}{
		{name: "observe", action: core.ActionObserve, handling: "pass", status: 200},
		{name: "delay", action: core.ActionDelay, handling: "delay", status: 429, retryAfter: 1},
		{name: "throttle", action: core.ActionThrottle, handling: "throttle", status: 429, retryAfter: 1},
		{name: "accessible step-up", action: core.ActionChallenge, handling: "challenge", status: 403},
		{name: "temporary block", action: core.ActionBlock, handling: "block", status: 403, retryAfter: 60},
	}
	previousRank := -1
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := controller.ApplyWithContext("progression-session", "public_content", test.action, AdaptiveContext{}, now)
			if result.Action != test.action || result.Mode != core.RuntimeModeEnforce || result.RolloutID != "progression-load-test" {
				t.Fatalf("progression result = %+v", result)
			}
			if result.Directive.Handling != test.handling || result.Directive.HTTPStatus != test.status || result.Directive.RetryAfterSeconds != test.retryAfter {
				t.Fatalf("progression directive = %+v", result.Directive)
			}
			if !result.Directive.ExpiresAt.After(now) || result.Directive.ExpiresAt.After(now.Add(5*time.Minute)) {
				t.Fatalf("unbounded progression expiry = %s", result.Directive.ExpiresAt)
			}
		})
		rank := actionRank(test.action)
		if rank <= previousRank {
			t.Fatalf("progression order regressed at %s", test.action)
		}
		previousRank = rank
	}
}

func TestProgressionFailuresDowngradeOrCapInsteadOfEscalating(t *testing.T) {
	now := time.Date(2026, time.August, 29, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name     string
		maximum  core.Action
		endpoint string
		action   core.Action
		want     core.Action
		mode     core.RuntimeMode
		reason   string
		at       time.Time
	}{
		{
			name:    "expired rollout returns to shadow observe",
			maximum: core.ActionBlock, endpoint: "public_content", action: core.ActionBlock, want: core.ActionObserve,
			mode: core.RuntimeModeShadow, reason: "ROLLOUT_EXPIRED", at: now.Add(5 * time.Minute),
		},
		{
			name:    "excluded endpoint returns to shadow observe",
			maximum: core.ActionBlock, endpoint: "login", action: core.ActionBlock, want: core.ActionObserve,
			mode: core.RuntimeModeShadow, reason: "ROLLOUT_ENDPOINT_EXCLUDED", at: now,
		},
		{
			name:    "signed maximum caps block at throttle",
			maximum: core.ActionThrottle, endpoint: "public_content", action: core.ActionBlock, want: core.ActionThrottle,
			mode: core.RuntimeModeEnforce, reason: "ROLLOUT_ACTION_CAPPED", at: now,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			controller := progressionController(t, now, test.maximum)
			result := controller.ApplyWithContext("failure-session", test.endpoint, test.action, AdaptiveContext{
				SuspiciousEvidenceConfidence: 2, RequestCount: 49, EndpointTransitions: 5, RecentEnforcements: 1,
			}, test.at)
			if result.Action != test.want || result.Mode != test.mode || !contains(result.Reasons, test.reason) {
				t.Fatalf("failure result = %+v", result)
			}
			if actionRank(result.Action) > actionRank(test.action) {
				t.Fatalf("failure escalated %s to %s", test.action, result.Action)
			}
		})
	}
}

func TestProgressionControllerConcurrentLoadIsDeterministic(t *testing.T) {
	now := time.Date(2026, time.August, 29, 12, 0, 0, 0, time.UTC)
	controller := progressionController(t, now, core.ActionBlock)
	actions := []core.Action{core.ActionObserve, core.ActionDelay, core.ActionThrottle, core.ActionChallenge, core.ActionBlock}
	contexts := []AdaptiveContext{
		{},
		{SuspiciousEvidenceConfidence: .8},
		{RequestCount: 50},
		{PrematureRetries: 1},
		{SuspiciousEvidenceConfidence: .9, RequestCount: 100, PrematureRetries: 1},
	}
	want := make([]Result, len(actions))
	for index := range actions {
		want[index] = controller.ApplyWithContext("load-baseline", "public_content", actions[index], contexts[index], now)
	}

	const workers = 32
	const iterations = 1000
	errors := make(chan error, workers)
	var wait sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		wait.Add(1)
		go func(worker int) {
			defer wait.Done()
			for iteration := 0; iteration < iterations; iteration++ {
				index := (worker + iteration) % len(actions)
				got := controller.ApplyWithContext(fmt.Sprintf("load-session-%02d", worker), "public_content", actions[index], contexts[index], now)
				if got.Action != want[index].Action || got.Mode != want[index].Mode || got.RolloutID != want[index].RolloutID ||
					got.Directive != want[index].Directive || !equalStrings(got.Reasons, want[index].Reasons) {
					errors <- fmt.Errorf("worker %d iteration %d got %+v want %+v", worker, iteration, got, want[index])
					return
				}
			}
		}(worker)
	}
	wait.Wait()
	close(errors)
	for err := range errors {
		t.Error(err)
	}
}

func BenchmarkProgressionController(b *testing.B) {
	now := time.Date(2026, time.August, 29, 12, 0, 0, 0, time.UTC)
	controller := progressionController(b, now, core.ActionBlock)
	actions := [...]core.Action{core.ActionObserve, core.ActionDelay, core.ActionThrottle, core.ActionChallenge, core.ActionBlock}
	b.ReportAllocs()
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		controller.ApplyWithContext("benchmark-session", "public_content", actions[index%len(actions)], AdaptiveContext{}, now)
	}
}

func progressionController(testingContext testing.TB, now time.Time, maximum core.Action) *Controller {
	testingContext.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		testingContext.Fatal(err)
	}
	plan := Plan{
		SchemaVersion: SchemaVersion, RolloutID: "progression-load-test", ApprovalID: "review-progression",
		PredecessorRolloutID: "canary-progression", CreatedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(5 * time.Minute).Format(time.RFC3339),
		SourceReportSHA256: strings.Repeat("a", 64), SourceReadinessState: "operator_review_candidate",
		PolicyVersion: "default-v5", ModelVersion: "transparent-baseline-v13", Stage: core.RuntimeModeEnforce,
		EndpointClasses: []string{"public_content"}, MaxAction: maximum, CanaryBasisPoints: FullRolloutBasisPoints,
		ThrottleSeconds: 20, ChallengeTTLSeconds: 300, BlockSeconds: 300,
		MinMatureChallenges: DefaultMinMatureChallenges, MinChallengeOutcomeCoverage: DefaultMinChallengeOutcomeCoverage,
		MaxChallengeAbandonmentRate: DefaultMaxChallengeAbandonmentRate, MaxChallengeFallbackRate: DefaultMaxChallengeFallbackRate,
	}
	signed, err := Sign(plan, privateKey)
	if err != nil {
		testingContext.Fatal(err)
	}
	controller, err := NewController(signed, publicKey, []byte("0123456789abcdef0123456789abcdef"), plan.PolicyVersion, plan.ModelVersion, now)
	if err != nil {
		testingContext.Fatal(err)
	}
	return controller
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
