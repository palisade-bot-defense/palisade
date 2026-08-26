package fusion

import (
	"testing"

	"github.com/palisade-bot-defense/palisade/internal/core"
)

func TestSuspiciousEvidenceRaisesRisk(t *testing.T) {
	scores := Calculate([]core.Evidence{{
		Dimension: core.DimensionAutomation, Direction: core.DirectionSuspicious, Strength: 1, Confidence: 1,
	}})
	if scores.AutomationRisk <= .5 {
		t.Fatalf("expected elevated automation risk: %+v", scores)
	}
}

func TestBenignContinuityRaisesContinuity(t *testing.T) {
	scores := Calculate([]core.Evidence{{
		Dimension: core.DimensionContinuity, Direction: core.DirectionBenign, Strength: 1, Confidence: 1,
	}})
	if scores.AccountContinuity <= .5 {
		t.Fatalf("expected elevated continuity: %+v", scores)
	}
}
