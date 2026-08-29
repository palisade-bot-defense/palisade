package challenge

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/palisade-bot-defense/palisade/internal/core"
)

var testSecret = []byte("0123456789abcdef0123456789abcdef")

const testRedemptionBinding = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"

func TestChallengeLifecycleBindsSessionActionEndpointAndOriginFlow(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	var outcomes []Outcome
	service, err := New(Config{Secret: testSecret, Delay: time.Second, Outcome: func(outcome Outcome) {
		outcomes = append(outcomes, outcome)
	}})
	if err != nil {
		t.Fatal(err)
	}
	request, decision := challengeFixture(now)
	metadata, err := service.Issue(request, decision, testRedemptionBinding, now)
	if err != nil {
		t.Fatal(err)
	}
	if metadata.Family != Family || metadata.VerificationToken == "" || metadata.AttemptsRemaining != DefaultMaxAttempts ||
		!metadata.Accessibility.NonVisual || !metadata.Accessibility.KeyboardOnly || !metadata.Accessibility.FallbackOffered {
		t.Fatalf("unsafe metadata: %+v", metadata)
	}
	idempotent, err := service.Issue(request, decision, testRedemptionBinding, now)
	if err != nil || idempotent.ChallengeID != metadata.ChallengeID || idempotent.VerificationToken != metadata.VerificationToken {
		t.Fatalf("idempotent issuance = %+v, %v", idempotent, err)
	}
	if _, err := service.Issue(request, decision, "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD", now); !errors.Is(err, ErrInvalidChallenge) {
		t.Fatalf("idempotent issuance accepted another origin flow binding: %v", err)
	}
	if _, err := service.View(metadata.ChallengeID, "other-session", now); !errors.Is(err, ErrSessionMismatch) {
		t.Fatalf("session mismatch = %v", err)
	}
	if _, err := service.Verify(metadata.ChallengeID, request.SessionID, metadata.VerificationToken, now); !errors.Is(err, ErrNotReady) {
		t.Fatalf("early verification = %v", err)
	}
	verified, err := service.Verify(metadata.ChallengeID, request.SessionID, metadata.VerificationToken, now.Add(time.Second))
	if err != nil || verified.RedemptionToken == "" {
		t.Fatalf("verification = %+v, %v", verified, err)
	}
	if err := service.Redeem(metadata.ChallengeID, request.SessionID, verified.RedemptionToken, testRedemptionBinding, "write", request.EndpointClass, now.Add(2*time.Second)); !errors.Is(err, ErrInvalidRedemption) {
		t.Fatalf("action binding = %v", err)
	}
	if err := service.Redeem(metadata.ChallengeID, request.SessionID, verified.RedemptionToken, testRedemptionBinding, request.Action, "login", now.Add(2*time.Second)); !errors.Is(err, ErrInvalidRedemption) {
		t.Fatalf("endpoint binding = %v", err)
	}
	if err := service.Redeem(metadata.ChallengeID, request.SessionID, verified.RedemptionToken, "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD", request.Action, request.EndpointClass, now.Add(2*time.Second)); !errors.Is(err, ErrInvalidRedemption) {
		t.Fatalf("origin flow binding = %v", err)
	}
	if err := service.Redeem(metadata.ChallengeID, request.SessionID, verified.RedemptionToken, testRedemptionBinding, request.Action, request.EndpointClass, now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := service.Redeem(metadata.ChallengeID, request.SessionID, verified.RedemptionToken, testRedemptionBinding, request.Action, request.EndpointClass, now.Add(2*time.Second)); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("redemption replay = %v", err)
	}
	if _, err := service.Issue(request, decision, testRedemptionBinding, now.Add(2*time.Second)); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("completed decision was reissued = %v", err)
	}
	if len(outcomes) != 1 || outcomes[0].Kind != "challenge_passed" || outcomes[0].DecisionID != decision.DecisionID {
		t.Fatalf("outcomes = %+v", outcomes)
	}
}

func TestChallengeIssuanceRequiresAppliedBoundDirectiveAndVerifiedSession(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	service, err := New(Config{Secret: testSecret})
	if err != nil {
		t.Fatal(err)
	}
	request, decision := challengeFixture(now)
	request.Observations.ServerSessionVerified = false
	if _, err := service.Issue(request, decision, testRedemptionBinding, now); !errors.Is(err, ErrInvalidChallenge) {
		t.Fatalf("unverified session issuance = %v", err)
	}
	request.Observations.ServerSessionVerified = true
	decision.Mode = core.RuntimeModeShadow
	if _, err := service.Issue(request, decision, testRedemptionBinding, now); !errors.Is(err, ErrInvalidChallenge) {
		t.Fatalf("shadow issuance = %v", err)
	}
	decision.Mode = core.RuntimeModeCanary
	decision.Directive.ExpiresAt = now.Add(MaximumChallengeTTL + time.Second)
	if _, err := service.Issue(request, decision, testRedemptionBinding, now); !errors.Is(err, ErrInvalidChallenge) {
		t.Fatalf("oversize TTL issuance = %v", err)
	}
	decision.Directive.ExpiresAt = now.Add(time.Minute)
	if _, err := service.Issue(request, decision, "", now); !errors.Is(err, ErrInvalidChallenge) {
		t.Fatalf("missing origin binding issuance = %v", err)
	}
	decision.Directive.ExpiresAt = now.Add(DefaultDelay)
	if _, err := service.Issue(request, decision, testRedemptionBinding, now); !errors.Is(err, ErrInvalidChallenge) {
		t.Fatalf("zero usable challenge window issuance = %v", err)
	}
}

func TestInvalidVerificationExhaustsBoundedAttempts(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	var outcomes []Outcome
	service, err := New(Config{Secret: testSecret, Delay: time.Nanosecond, MaxAttempts: 2, Outcome: func(outcome Outcome) {
		outcomes = append(outcomes, outcome)
	}})
	if err != nil {
		t.Fatal(err)
	}
	request, decision := challengeFixture(now)
	metadata, err := service.Issue(request, decision, testRedemptionBinding, now)
	if err != nil {
		t.Fatal(err)
	}
	ready := now.Add(time.Second)
	if _, err := service.Verify(metadata.ChallengeID, request.SessionID, "invalid", ready); !errors.Is(err, ErrInvalidVerification) {
		t.Fatalf("first invalid token = %v", err)
	}
	view, err := service.View(metadata.ChallengeID, request.SessionID, ready)
	if err != nil || view.AttemptsRemaining != 1 {
		t.Fatalf("remaining attempts = %+v, %v", view, err)
	}
	if _, err := service.Verify(metadata.ChallengeID, request.SessionID, "invalid", ready); !errors.Is(err, ErrAttemptsExceeded) {
		t.Fatalf("attempt exhaustion = %v", err)
	}
	if len(outcomes) != 1 || outcomes[0].Kind != "challenge_failed" {
		t.Fatalf("outcomes = %+v", outcomes)
	}
}

func TestExpiryFallbackCapacityAndSweep(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	var outcomes []Outcome
	service, err := New(Config{Secret: testSecret, MaxEntries: 1, Delay: time.Second, Outcome: func(outcome Outcome) {
		outcomes = append(outcomes, outcome)
	}})
	if err != nil {
		t.Fatal(err)
	}
	request, decision := challengeFixture(now)
	metadata, err := service.Issue(request, decision, testRedemptionBinding, now)
	if err != nil {
		t.Fatal(err)
	}
	secondRequest, secondDecision := challengeFixture(now)
	secondDecision.DecisionID = "decision-2"
	if _, err := service.Issue(secondRequest, secondDecision, testRedemptionBinding, now); !errors.Is(err, ErrCapacity) {
		t.Fatalf("capacity = %v", err)
	}
	if err := service.Fallback(metadata.ChallengeID, request.SessionID, now); err != nil {
		t.Fatal(err)
	}
	if len(outcomes) != 1 || outcomes[0].Kind != "fallback_used" {
		t.Fatalf("fallback outcomes = %+v", outcomes)
	}
	if err := service.Fallback(metadata.ChallengeID, request.SessionID, now); !errors.Is(err, ErrInvalidState) || len(outcomes) != 1 {
		t.Fatalf("fallback replay = %v outcomes=%+v", err, outcomes)
	}
	if swept := service.Sweep(decision.Directive.ExpiresAt); swept != 0 {
		t.Fatalf("terminal record emitted abandonment: %d", swept)
	}
	secondDecision.Directive.ExpiresAt = decision.Directive.ExpiresAt.Add(5 * time.Minute)
	secondMetadata, err := service.Issue(secondRequest, secondDecision, testRedemptionBinding, decision.Directive.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.View(secondMetadata.ChallengeID, secondRequest.SessionID, decision.Directive.ExpiresAt); err != nil {
		t.Fatal(err)
	}
	if swept := service.Sweep(secondDecision.Directive.ExpiresAt); swept != 1 {
		t.Fatalf("abandonment sweep = %d", swept)
	}
	if len(outcomes) != 2 || outcomes[1].Kind != "challenge_abandoned" {
		t.Fatalf("sweep outcomes = %+v", outcomes)
	}
}

func TestOnlyOneConcurrentRedemptionSucceeds(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	service, err := New(Config{Secret: testSecret, Delay: time.Nanosecond})
	if err != nil {
		t.Fatal(err)
	}
	request, decision := challengeFixture(now)
	metadata, err := service.Issue(request, decision, testRedemptionBinding, now)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := service.Verify(metadata.ChallengeID, request.SessionID, metadata.VerificationToken, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	var successes atomic.Int32
	var wait sync.WaitGroup
	for range 32 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			if service.Redeem(metadata.ChallengeID, request.SessionID, verified.RedemptionToken, testRedemptionBinding, request.Action, request.EndpointClass, now.Add(2*time.Second)) == nil {
				successes.Add(1)
			}
		}()
	}
	wait.Wait()
	if successes.Load() != 1 {
		t.Fatalf("successful redemptions = %d", successes.Load())
	}
}

func challengeFixture(now time.Time) (core.DecisionRequest, core.Decision) {
	return core.DecisionRequest{SessionID: "session-12345678", Action: "read", EndpointClass: "public_content", Sequence: 1, Observations: core.Observations{ServerSessionVerified: true}}, core.Decision{
		DecisionID: "decision-1", Action: core.ActionChallenge, ComputedAction: core.ActionChallenge,
		Mode: core.RuntimeModeCanary, RolloutID: "rollout-1",
		Directive: core.EnforcementDirective{Handling: "challenge", HTTPStatus: 403, ExpiresAt: now.Add(5 * time.Minute)},
	}
}
