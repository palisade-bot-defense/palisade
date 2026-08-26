package detector

import (
	"context"
	"strings"
	"time"

	"github.com/palisade-bot-defense/palisade/internal/core"
)

type ProtocolConsistency struct{}

func (ProtocolConsistency) ID() string { return "protocol_consistency_v1" }

func (d ProtocolConsistency) Evaluate(_ context.Context, input core.DetectorInput) ([]core.Evidence, error) {
	var result []core.Evidence
	obs := input.Request.Observations
	if !obs.UserAgentPresent {
		result = append(result, evidence("UA_MISSING", d.ID(), core.DimensionAutomation, core.DirectionSuspicious, .52, .72))
	}
	if obs.BrowserEventCount > 0 && !obs.UserAgentPresent {
		result = append(result, evidence("BROWSER_PROTOCOL_CONTRADICTION", d.ID(), core.DimensionAutomation, core.DirectionSuspicious, .82, .9))
	}
	if obs.BrowserEventCount >= 3 && obs.UserAgentPresent {
		result = append(result, evidence("BROWSER_SEQUENCE_PRESENT", d.ID(), core.DimensionContinuity, core.DirectionBenign, .24, .64))
	}
	return result, nil
}

type SequenceVelocity struct{}

func (SequenceVelocity) ID() string { return "sequence_velocity_v1" }

func (d SequenceVelocity) Evaluate(_ context.Context, input core.DetectorInput) ([]core.Evidence, error) {
	var result []core.Evidence
	if input.Session.RequestCount > 40 {
		result = append(result, evidence("SESSION_BURST", d.ID(), core.DimensionIntent, core.DirectionSuspicious, .7, .78))
	}
	if input.Session.MaxSequenceGap > 20 {
		result = append(result, evidence("SEQUENCE_GAP_HIGH", d.ID(), core.DimensionAutomation, core.DirectionSuspicious, .56, .7))
	}
	if input.Session.RequestCount > 1 && input.Session.MaxSequenceGap <= 2 {
		result = append(result, evidence("SESSION_SEQUENCE_STABLE", d.ID(), core.DimensionContinuity, core.DirectionBenign, .18, .6))
	}
	if input.Request.Observations.HoneypotHits > 0 {
		strength := .62 + float64(input.Request.Observations.HoneypotHits-1)*.12
		result = append(result, evidence("HONEYPOT_INTERACTION", d.ID(), core.DimensionIntent, core.DirectionSuspicious, clamp(strength), .88))
	}
	return result, nil
}

type ExternalVerdicts struct{}

func (ExternalVerdicts) ID() string { return "external_verdicts_v1" }

func (d ExternalVerdicts) Evaluate(_ context.Context, input core.DetectorInput) ([]core.Evidence, error) {
	var result []core.Evidence
	obs := input.Request.Observations
	verdict := strings.ToLower(strings.TrimSpace(obs.AnubisVerdict))
	switch verdict {
	case "bot", "deny", "blocked", "challenge_failed":
		result = append(result, evidence("ANUBIS_SUSPICIOUS", d.ID(), core.DimensionAutomation, core.DirectionSuspicious, .74, .78))
	case "human", "allow", "passed":
		result = append(result, evidence("ANUBIS_PASSED", d.ID(), core.DimensionAutomation, core.DirectionBenign, .2, .55))
	}
	if obs.CannaiScore > 0 {
		result = append(result, evidence("CANNAI_RISK", d.ID(), core.DimensionIntent, core.DirectionSuspicious, clamp(obs.CannaiScore), .72))
	}
	if obs.CrowdSecAlert {
		result = append(result, evidence("CROWDSEC_ALERT", d.ID(), core.DimensionIntent, core.DirectionSuspicious, .82, .86))
	}
	if obs.VerifiedBot {
		result = append(result, evidence("VERIFIED_BOT_IDENTITY", d.ID(), core.DimensionIntent, core.DirectionBenign, .68, .92))
	}
	return result, nil
}

func evidence(code, detectorID string, dimension core.Dimension, direction core.Direction, strength, confidence float64) core.Evidence {
	return core.Evidence{
		Code:       code,
		Detector:   detectorID,
		Dimension:  dimension,
		Direction:  direction,
		Strength:   clamp(strength),
		Confidence: clamp(confidence),
		TTL:        5 * time.Minute,
	}
}

func clamp(value float64) float64 {
	if value < 0 {
		return 0
	}
	if value > 1 {
		return 1
	}
	return value
}
