package detector

import (
	"context"
	"strings"
	"time"

	"github.com/palisade-bot-defense/palisade/internal/core"
)

type ProtocolConsistency struct{}

func (ProtocolConsistency) ID() string { return "protocol_consistency_v2" }

func (d ProtocolConsistency) Evaluate(_ context.Context, input core.DetectorInput) ([]core.Evidence, error) {
	var result []core.Evidence
	obs := input.Request.Observations
	if !obs.UserAgentPresent {
		result = append(result, evidence("UA_MISSING", d.ID(), core.DimensionAutomation, core.DirectionSuspicious, .52, .72))
	}
	if obs.BrowserEventsVerified && obs.BrowserEventCount > 0 && !obs.UserAgentPresent {
		result = append(result, evidence("BROWSER_PROTOCOL_CONTRADICTION", d.ID(), core.DimensionAutomation, core.DirectionSuspicious, .82, .9))
	}
	if obs.BrowserEventsVerified && obs.BrowserEventCount >= 3 && obs.UserAgentPresent {
		result = append(result, evidence("BROWSER_SEQUENCE_PRESENT", d.ID(), core.DimensionContinuity, core.DirectionBenign, .24, .64))
	}
	if obs.ServerSessionVerified {
		// Cookie integrity links page views; it does not establish humanity or
		// account identity and therefore affects continuity only.
		result = append(result, evidence("SERVER_SESSION_VERIFIED", d.ID(), core.DimensionContinuity, core.DirectionBenign, .30, .95))
	}
	return result, nil
}

type SequenceVelocity struct{}

func (SequenceVelocity) ID() string { return "sequence_velocity_v2" }

func (d SequenceVelocity) Evaluate(_ context.Context, input core.DetectorInput) ([]core.Evidence, error) {
	var result []core.Evidence
	// The evaluated offline export contains weak policy labels but no confirmed-human
	// cohort. Volume therefore contributes conservative, explainable evidence
	// instead of becoming a standalone high-confidence abuse decision.
	if input.Session.RequestCount >= 100 {
		result = append(result, evidence("SESSION_VOLUME_HIGH", d.ID(), core.DimensionIntent, core.DirectionSuspicious, .54, .58))
	}
	duration := input.Session.LastSeen.Sub(input.Session.FirstSeen)
	if input.Session.RequestCount >= 50 && duration >= 0 && duration <= time.Minute {
		result = append(result, evidence("SESSION_BURST_FAST", d.ID(), core.DimensionIntent, core.DirectionSuspicious, .56, .60))
	}
	if input.Session.MaxSequenceGap > 20 {
		result = append(result, evidence("SEQUENCE_GAP_HIGH", d.ID(), core.DimensionAutomation, core.DirectionSuspicious, .56, .7))
	}
	if input.Session.RequestCount > 1 && input.Session.MaxSequenceGap <= 2 {
		result = append(result, evidence("SESSION_SEQUENCE_STABLE", d.ID(), core.DimensionContinuity, core.DirectionBenign, .18, .6))
	}
	return result, nil
}

type NavigationGraph struct{}

func (NavigationGraph) ID() string { return "navigation_graph_v1" }

func (d NavigationGraph) Evaluate(_ context.Context, input core.DetectorInput) ([]core.Evidence, error) {
	duration := input.Session.LastSeen.Sub(input.Session.FirstSeen)
	if input.Session.DistinctEndpointClasses >= 5 && input.Session.EndpointTransitions >= 6 && duration >= 0 && duration <= 2*time.Minute {
		return []core.Evidence{
			evidence("NAVIGATION_SURFACE_SWEEP", d.ID(), core.DimensionIntent, core.DirectionSuspicious, .42, .45),
		}, nil
	}
	return nil, nil
}

type DecoyInteraction struct{}

func (DecoyInteraction) ID() string { return "decoy_interaction_v1" }

func (d DecoyInteraction) Evaluate(_ context.Context, input core.DetectorInput) ([]core.Evidence, error) {
	hits := input.Request.Observations.HoneypotHits
	if hits == 0 {
		return nil, nil
	}
	strength := .62 + float64(hits-1)*.12
	return []core.Evidence{
		evidence("HONEYPOT_INTERACTION", d.ID(), core.DimensionIntent, core.DirectionSuspicious, clamp(strength), .88),
	}, nil
}

// CampaignSurface describes endpoint intent learned from an evaluated offline
// export, not client identity. The noindex comparison surfaces were the narrow
// target of a measured enumeration campaign, so they justify a reversible
// step-up in shadow mode but never a standalone block or an identity claim.
type CampaignSurface struct{}

func (CampaignSurface) ID() string { return "campaign_surface_v1" }

func (d CampaignSurface) Evaluate(_ context.Context, input core.DetectorInput) ([]core.Evidence, error) {
	if input.Request.EndpointClass != "compare_noindex" {
		return nil, nil
	}
	return []core.Evidence{
		evidence("COMPARE_NOINDEX_CAMPAIGN_SURFACE", d.ID(), core.DimensionIntent, core.DirectionSuspicious, .51, .75),
	}, nil
}

type ExternalVerdicts struct{}

func (ExternalVerdicts) ID() string { return "external_verdicts_v3" }

func (d ExternalVerdicts) Evaluate(_ context.Context, input core.DetectorInput) ([]core.Evidence, error) {
	var result []core.Evidence
	obs := input.Request.Observations
	verdict := strings.ToLower(strings.TrimSpace(obs.ChallengeVerdict))
	switch verdict {
	case "suspicious", "failed", "blocked":
		result = append(result, evidence("CHALLENGE_VERDICT_SUSPICIOUS", d.ID(), core.DimensionAutomation, core.DirectionSuspicious, .74, .78))
	case "allowed", "passed", "unknown", "":
		// A policy allow or solved proof-of-work is an outcome, not evidence of
		// humanity. Browser automation can complete the same challenge.
	}
	if obs.ExternalRiskScore > 0 {
		result = append(result, evidence("EXTERNAL_RISK", d.ID(), core.DimensionIntent, core.DirectionSuspicious, clamp(obs.ExternalRiskScore), .72))
	}
	if obs.PolicyAlert {
		result = append(result, evidence("POLICY_ALERT", d.ID(), core.DimensionIntent, core.DirectionSuspicious, .82, .86))
	}
	if core.VerifiedPublicCrawler(obs, input.Request.EndpointClass) {
		result = append(result, evidence("VERIFIED_PUBLIC_CRAWLER", d.ID(), core.DimensionAutomation, core.DirectionBenign, .68, .92))
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
