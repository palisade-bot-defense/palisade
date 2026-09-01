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

	"github.com/palisade-human-trust/palisade/internal/agentprovenance"
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
	reasonInteractiveLiveness     = "interactive_liveness_completed"
	reasonAttestedDevice          = "attested_device_credential_verified"
	reasonLevelPendingMeasurement = "level_withheld_pending_measurement"
	reasonServerSessionVerified   = "server_session_verified"
	reasonAutomationContradiction = "automation_evidence_contradicts_presence"
	reasonNoVerifiedInteraction   = "no_verified_interaction_evidence"
)

// Withheld reports that the evidence supported a higher level than this build
// states. A relying service and the local measurement both need the difference
// between a level that was not earned and one that was earned and withheld.
func (r Result) Withheld() bool {
	for _, code := range r.ReasonCodes {
		if code == reasonLevelPendingMeasurement {
			return true
		}
	}
	return false
}

// Result is the derived assurance view of one decision.
type Result struct {
	Level       int
	Sources     []string
	ReasonCodes []string
}

// Evidence is the verified, non-decision input to a derivation. Each field is
// set only after the caller verified the corresponding proof for this exact
// session, action and endpoint class; this package trusts, and never re-checks,
// that verification.
type Evidence struct {
	// LivenessVerified reports a completed interactive liveness challenge.
	LivenessVerified bool
	// DeviceAttested reports a verified assertion from a registered
	// device-bound credential. Possession of a device is not presence of a
	// person, so it never substitutes for interaction evidence.
	DeviceAttested bool
}

// Derive computes the assurance level backed by a decision's evidence and the
// verified proofs the caller presents.
//
// The result is clamped to palisadeassurance.MaximumSupportedLevel. Interactive
// liveness and device attestation are both implemented, so the computed level
// can reach H3, but the ceiling stays at H1 until a confirmed-human
// false-positive and abandonment interval exists per level. Withholding a level
// the evidence supports is the deliberate choice: gating a surface on an
// unmeasured level would harm people before anyone knows how often it does.
//
// The order is cumulative rather than substitutable. A device credential never
// stands in for interaction evidence, because possession of a device is not
// presence of a person, and neither ever overrides an automation contradiction.
func Derive(decision core.Decision, evidence Evidence) Result {
	livenessVerified := evidence.LivenessVerified
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
	case verifiedSequence && livenessVerified && evidence.DeviceAttested:
		reasons = append(reasons, reasonVerifiedBrowserSequence, reasonInteractiveLiveness, reasonAttestedDevice)
		return finish(palisadeassurance.LevelAttestedDevice,
			[]string{"behavioral", "challenge", "device"}, reasons)
	case verifiedSequence && livenessVerified:
		reasons = append(reasons, reasonVerifiedBrowserSequence, reasonInteractiveLiveness)
		return finish(palisadeassurance.LevelInteractive, []string{"behavioral", "challenge"}, reasons)
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
//
// The agent provenance is carried through unchanged: an assertion should say
// how an automated participant identified itself rather than hide it.
// Provenance never raises the assurance level, because identifying as an agent
// is not evidence that a human is present.
func (r Result) Payload(
	binding palisadeassurance.Binding,
	provenance agentprovenance.Result,
	policyVersion, modelVersion string,
) palisadeassurance.Payload {
	reasons := append(append([]string(nil), r.ReasonCodes...), provenance.ReasonCodes...)
	sort.Strings(reasons)
	declared := provenance.Provenance
	if declared == "" {
		declared = agentprovenance.None
	}
	return palisadeassurance.Payload{
		AssuranceLevel:   r.Level,
		AssuranceSources: r.Sources,
		ReasonCodes:      dedupe(reasons),
		UniquenessScope:  "none",
		AgentProvenance:  declared,
		Binding:          binding,
		PolicyVersion:    policyVersion,
		ModelVersion:     modelVersion,
	}
}

func dedupe(values []string) []string {
	result := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if _, duplicate := seen[value]; duplicate {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func finish(level int, sources, reasons []string) Result {
	if level > palisadeassurance.MaximumSupportedLevel {
		// The evidence supports more than this build will state. Say so in the
		// assertion rather than silently reporting a lower level, so an operator
		// can see that measurement, not evidence, is the binding constraint.
		level = palisadeassurance.MaximumSupportedLevel
		reasons = append(reasons, reasonLevelPendingMeasurement)
		sources = sourcesUpTo(sources, level)
	}
	if sources == nil {
		sources = []string{}
	}
	sort.Strings(sources)
	sort.Strings(reasons)
	return Result{Level: level, Sources: sources, ReasonCodes: reasons}
}

// sourcesUpTo drops evidence classes that belong to a level this build refuses
// to state. An assertion must not name evidence for a level it does not claim.
func sourcesUpTo(sources []string, level int) []string {
	allowed := map[string]struct{}{}
	for _, source := range palisadeassurance.RequiredSources(level) {
		allowed[source] = struct{}{}
	}
	result := make([]string, 0, len(sources))
	for _, source := range sources {
		if _, permitted := allowed[source]; permitted {
			result = append(result, source)
		}
	}
	return result
}
