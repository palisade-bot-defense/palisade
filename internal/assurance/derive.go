// Package assurance derives a human-assurance level from a decision that has
// already been made. It is a fourth, derived view over the existing automation,
// abuse-intent and continuity scores: it never replaces them, never changes an
// enforcement action and never adds a signal class.
//
// The derivation is deliberately conservative. Only positive, server-verified
// evidence raises a level. The absence of automation evidence never does, and a
// completed proof-of-work challenge never does, because browser automation may
// complete the same challenge routinely.
package assurance

import (
	"sort"

	"github.com/palisade-human-trust/palisade/internal/core"
	"github.com/palisade-human-trust/palisade/pkg/palisadeassurance"
)

const (
	// EvidenceVerifiedBrowserSequence is the only evidence code that currently
	// raises assurance. It is emitted when PALISADE verified a browser event
	// sequence against its own bounded event store rather than trusting a
	// client-supplied count.
	EvidenceVerifiedBrowserSequence = "BROWSER_SEQUENCE_PRESENT"
	// EvidenceServerSessionVerified links page views through a signed
	// first-party cookie. It is recorded for explanation but never raises a
	// level: cookie integrity establishes continuity, not humanity.
	EvidenceServerSessionVerified = "SERVER_SESSION_VERIFIED"

	// disqualifyingConfidence is the confidence at which suspicious automation
	// evidence contradicts a human-presence claim. This is not "absence of bot
	// evidence is human evidence"; it is the converse, which is sound: a client
	// that looks automated must not simultaneously be asserted as present.
	disqualifyingConfidence = 0.60

	reasonVerifiedBrowserSequence = "verified_browser_sequence"
	reasonServerSessionVerified   = "server_session_verified"
	reasonAutomationContradiction = "automation_evidence_contradicts_presence"
	reasonNoVerifiedInteraction   = "no_verified_interaction_evidence"
)

// Result is the derived assurance view of one decision.
type Result struct {
	Level       int
	Sources     []string
	ReasonCodes []string
}

// Derive computes the assurance level backed by a decision's evidence. It
// returns at most palisadeassurance.MaximumSupportedLevel, because no mechanism
// in this repository verifies interactive liveness, device attestation, issuer
// credentials or uniqueness.
func Derive(decision core.Decision) Result {
	verifiedSequence := false
	verifiedSession := false
	contradicted := false

	for _, item := range decision.Evidence {
		switch {
		case item.Code == EvidenceVerifiedBrowserSequence && item.Direction == core.DirectionBenign:
			verifiedSequence = true
		case item.Code == EvidenceServerSessionVerified && item.Direction == core.DirectionBenign:
			verifiedSession = true
		case item.Dimension == core.DimensionAutomation &&
			item.Direction == core.DirectionSuspicious &&
			item.Confidence >= disqualifyingConfidence:
			contradicted = true
		}
	}

	reasons := make([]string, 0, 3)
	if verifiedSession {
		reasons = append(reasons, reasonServerSessionVerified)
	}

	switch {
	case contradicted:
		reasons = append(reasons, reasonAutomationContradiction)
		return finish(palisadeassurance.LevelUnattributed, nil, reasons)
	case verifiedSequence:
		reasons = append(reasons, reasonVerifiedBrowserSequence)
		return finish(palisadeassurance.LevelBehavioral, []string{"behavioral"}, reasons)
	default:
		reasons = append(reasons, reasonNoVerifiedInteraction)
		return finish(palisadeassurance.LevelUnattributed, nil, reasons)
	}
}

// Payload turns a derived result into the signable assertion payload for one
// audience, leaving the timestamps and nonce to the signer.
func (r Result) Payload(binding palisadeassurance.Binding, policyVersion, modelVersion string) palisadeassurance.Payload {
	return palisadeassurance.Payload{
		AssuranceLevel:   r.Level,
		AssuranceSources: r.Sources,
		ReasonCodes:      r.ReasonCodes,
		UniquenessScope:  "none",
		AgentProvenance:  "none",
		Binding:          binding,
		PolicyVersion:    policyVersion,
		ModelVersion:     modelVersion,
	}
}

func finish(level int, sources, reasons []string) Result {
	if level > palisadeassurance.MaximumSupportedLevel {
		level = palisadeassurance.MaximumSupportedLevel
	}
	if sources == nil {
		sources = []string{}
	}
	sort.Strings(sources)
	sort.Strings(reasons)
	return Result{Level: level, Sources: sources, ReasonCodes: reasons}
}
