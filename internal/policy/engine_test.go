package policy

import (
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
