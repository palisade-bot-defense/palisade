package fusion

import (
	"math"

	"github.com/palisade-human-trust/palisade/internal/core"
)

func Calculate(evidence []core.Evidence) core.Scores {
	logs := map[core.Dimension]float64{}
	for _, item := range evidence {
		direction := float64(item.Direction)
		logs[item.Dimension] += direction * clamp(item.Strength) * clamp(item.Confidence) * 2
	}
	automation := sigmoid(logs[core.DimensionAutomation])
	intent := sigmoid(logs[core.DimensionIntent])
	continuity := 1 - sigmoid(logs[core.DimensionContinuity])
	return core.Scores{
		AutomationRisk:    round4(automation),
		AbuseIntentRisk:   round4(intent),
		AccountContinuity: round4(continuity),
	}
}

func sigmoid(value float64) float64 { return 1 / (1 + math.Exp(-value)) }

func clamp(value float64) float64 {
	if value < 0 {
		return 0
	}
	if value > 1 {
		return 1
	}
	return value
}

func round4(value float64) float64 { return math.Round(value*10_000) / 10_000 }
