package policy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/palisade-bot-defense/palisade/internal/core"
)

func TestPublicContentHighRiskIsThrottled(t *testing.T) {
	engine, err := NewDefault()
	if err != nil {
		t.Fatal(err)
	}
	result, err := engine.Evaluate(Input{Scores: core.Scores{AutomationRisk: .95, AbuseIntentRisk: .6, AccountContinuity: .5}, EndpointClass: "public_content"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Action != core.ActionThrottle {
		t.Fatalf("expected throttle, got %+v", result)
	}
}

func TestDefaultPolicySourceMatchesCheckedInCEL(t *testing.T) {
	path := filepath.Join("..", "..", "policies", "defaults", "shadow.cel")
	checkedIn, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(checkedIn) != DefaultSource() {
		t.Fatalf("%s has drifted from the runtime policy; update it from policy.DefaultSource", path)
	}
}

func TestDefaultPolicyVersion(t *testing.T) {
	engine, err := NewDefault()
	if err != nil {
		t.Fatal(err)
	}
	if engine.Version() != "default-v4" {
		t.Fatalf("version = %s, want default-v4", engine.Version())
	}
}

func TestElevatedRiskComputesProgressiveDelay(t *testing.T) {
	engine, err := NewDefault()
	if err != nil {
		t.Fatal(err)
	}
	result, err := engine.Evaluate(Input{Scores: core.Scores{AutomationRisk: .55, AbuseIntentRisk: .2, AccountContinuity: .5}})
	if err != nil {
		t.Fatal(err)
	}
	if result.Action != core.ActionDelay || result.Reason != "ELEVATED_RISK" {
		t.Fatalf("result = %+v, want delay/ELEVATED_RISK", result)
	}
}

func TestVerifiedBotPolicyBoundaries(t *testing.T) {
	engine, err := NewDefault()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		input  Input
		action core.Action
		reason string
	}{
		{
			name: "high intent",
			input: Input{VerifiedBot: true, Scores: core.Scores{
				AutomationRisk: .1, AbuseIntentRisk: .95, AccountContinuity: .5,
			}},
			action: core.ActionBlock,
			reason: "HIGH_RISK",
		},
		{
			name: "elevated intent",
			input: Input{VerifiedBot: true, Scores: core.Scores{
				AutomationRisk: .1, AbuseIntentRisk: .7, AccountContinuity: .5,
			}},
			action: core.ActionChallenge,
			reason: "STEP_UP_REQUIRED",
		},
		{
			name: "policy alert only",
			input: Input{VerifiedBot: true, PolicyAlert: true, Scores: core.Scores{
				AutomationRisk: .1, AbuseIntentRisk: .5, AccountContinuity: .5,
			}},
			action: core.ActionChallenge,
			reason: "STEP_UP_REQUIRED",
		},
		{
			name: "honeypot only",
			input: Input{VerifiedBot: true, HoneypotHits: 1, Scores: core.Scores{
				AutomationRisk: .1, AbuseIntentRisk: .5, AccountContinuity: .5,
			}},
			action: core.ActionChallenge,
			reason: "STEP_UP_REQUIRED",
		},
		{
			name: "multi source",
			input: Input{VerifiedBot: true, PolicyAlert: true, HoneypotHits: 1, Scores: core.Scores{
				AutomationRisk: .1, AbuseIntentRisk: .5, AccountContinuity: .5,
			}},
			action: core.ActionBlock,
			reason: "MULTI_SOURCE_ABUSE",
		},
		{
			name: "automation only",
			input: Input{VerifiedBot: true, Scores: core.Scores{
				AutomationRisk: .95, AbuseIntentRisk: .5, AccountContinuity: .5,
			}},
			action: core.ActionAllow,
			reason: "VERIFIED_AUTOMATION_ALLOWED",
		},
		{
			name: "benign verified bot",
			input: Input{VerifiedBot: true, Scores: core.Scores{
				AutomationRisk: .1, AbuseIntentRisk: .1, AccountContinuity: .5,
			}},
			action: core.ActionAllow,
			reason: "VERIFIED_AUTOMATION_ALLOWED",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := engine.Evaluate(test.input)
			if err != nil {
				t.Fatal(err)
			}
			if result.Action != test.action || result.Reason != test.reason {
				t.Fatalf("result = %+v, want action=%s reason=%s", result, test.action, test.reason)
			}
		})
	}
}
