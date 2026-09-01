package assurance

import (
	"crypto/ed25519"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/palisade-human-trust/palisade/internal/agentprovenance"
	"github.com/palisade-human-trust/palisade/internal/core"
	"github.com/palisade-human-trust/palisade/pkg/palisadeassurance"
)

func benign(code string, dimension core.Dimension, confidence float64) core.Evidence {
	return core.Evidence{
		Code: code, Detector: "test", Dimension: dimension,
		Direction: core.DirectionBenign, Strength: .3, Confidence: confidence,
	}
}

func suspicious(code string, dimension core.Dimension, confidence float64) core.Evidence {
	return core.Evidence{
		Code: code, Detector: "test", Dimension: dimension,
		Direction: core.DirectionSuspicious, Strength: .6, Confidence: confidence,
	}
}

func decisionWith(evidence ...core.Evidence) core.Decision {
	return core.Decision{Evidence: evidence, PolicyVersion: "default-v5", ModelVersion: "transparent-baseline-v13"}
}

func TestVerifiedBrowserSequenceReachesBehavioralAssurance(t *testing.T) {
	result := Derive(decisionWith(benign(EvidenceVerifiedBrowserSequence, core.DimensionContinuity, .64)), false)
	if result.Level != palisadeassurance.LevelBehavioral {
		t.Fatalf("expected behavioral assurance, got %d", result.Level)
	}
	if !reflect.DeepEqual(result.Sources, []string{"behavioral"}) {
		t.Fatalf("unexpected evidence classes: %v", result.Sources)
	}
	if !reflect.DeepEqual(result.ReasonCodes, []string{reasonVerifiedBrowserSequence}) {
		t.Fatalf("unexpected reason codes: %v", result.ReasonCodes)
	}
}

func TestAbsenceOfAutomationEvidenceIsNeverHumanEvidence(t *testing.T) {
	// An empty decision carries no positive evidence at all. A system that
	// treated "nothing looked automated" as human presence would fail here.
	result := Derive(decisionWith(), false)
	if result.Level != palisadeassurance.LevelUnattributed {
		t.Fatalf("an evidence-free decision produced assurance %d", result.Level)
	}
	if len(result.Sources) != 0 {
		t.Fatalf("an evidence-free decision named evidence classes: %v", result.Sources)
	}
}

func TestSignalsThatMustNotRaiseAssurance(t *testing.T) {
	cases := map[string]core.Decision{
		"signed session cookie alone": decisionWith(
			benign(EvidenceServerSessionVerified, core.DimensionContinuity, .95)),
		"completed proof of work": decisionWith(
			benign("CHALLENGE_PASSED", core.DimensionAutomation, .9)),
		"benign network reputation": decisionWith(
			benign("NETWORK_REPUTATION_LOW", core.DimensionAutomation, .8)),
		"verified public crawler": decisionWith(
			benign("VERIFIED_PUBLIC_CRAWLER", core.DimensionAutomation, .92)),
		"client claimed events": decisionWith(
			benign("BROWSER_EVENTS_CLAIMED", core.DimensionContinuity, .5)),
	}
	for name, decision := range cases {
		if result := Derive(decision, false); result.Level != palisadeassurance.LevelUnattributed {
			t.Fatalf("%s raised assurance to %d", name, result.Level)
		}
	}
}

func TestAutomationEvidenceContradictsPresence(t *testing.T) {
	result := Derive(decisionWith(
		benign(EvidenceVerifiedBrowserSequence, core.DimensionContinuity, .64),
		suspicious("BROWSER_PROTOCOL_CONTRADICTION", core.DimensionAutomation, .9),
	), false)
	if result.Level != palisadeassurance.LevelUnattributed {
		t.Fatalf("a contradicted decision produced assurance %d", result.Level)
	}
	if !contains(result.ReasonCodes, reasonAutomationContradiction) {
		t.Fatalf("the contradiction was not explained: %v", result.ReasonCodes)
	}

	// Weak automation evidence must not silently erase verified interaction.
	weak := Derive(decisionWith(
		benign(EvidenceVerifiedBrowserSequence, core.DimensionContinuity, .64),
		suspicious("NETWORK_HOSTING_CONTEXT", core.DimensionAutomation, .40),
	), false)
	if weak.Level != palisadeassurance.LevelBehavioral {
		t.Fatalf("low-confidence automation evidence disqualified presence: %+v", weak)
	}

	// Suspicion about intent is not suspicion about being automated.
	intent := Derive(decisionWith(
		benign(EvidenceVerifiedBrowserSequence, core.DimensionContinuity, .64),
		suspicious("SESSION_VOLUME_HIGH", core.DimensionIntent, .9),
	), false)
	if intent.Level != palisadeassurance.LevelBehavioral {
		t.Fatalf("abuse-intent evidence was treated as an automation contradiction: %+v", intent)
	}
}

func TestDerivationNeverExceedsTheSupportedCeiling(t *testing.T) {
	// Every evidence code the baseline detectors can emit, at maximum
	// confidence in both directions, must still land at or below the ceiling.
	codes := []string{
		"UA_MISSING", "BROWSER_PROTOCOL_CONTRADICTION", EvidenceVerifiedBrowserSequence,
		EvidenceServerSessionVerified, "SESSION_VOLUME_HIGH", "SESSION_BURST_FAST",
		"SEQUENCE_GAP_HIGH", "SESSION_SEQUENCE_STABLE", "NAVIGATION_SURFACE_SWEEP",
		"HONEYPOT_INTERACTION", "DECOY_CAPABILITY_REDEEMED", "CHALLENGE_VERDICT_SUSPICIOUS",
		"EXTERNAL_RISK", "POLICY_ALERT", "VERIFIED_PUBLIC_CRAWLER", "EDGE_AUTOMATION_PROFILE",
	}
	dimensions := []core.Dimension{core.DimensionAutomation, core.DimensionIntent, core.DimensionContinuity}
	for _, code := range codes {
		for _, dimension := range dimensions {
			for _, evidence := range []core.Evidence{
				benign(code, dimension, 1),
				suspicious(code, dimension, 1),
			} {
				if level := Derive(decisionWith(evidence), false).Level; level > palisadeassurance.MaximumSupportedLevel {
					t.Fatalf("%s in %v produced assurance %d", code, dimension, level)
				}
			}
		}
	}
}

func TestDerivedPayloadSignsAndVerifies(t *testing.T) {
	raw := make([]byte, ed25519.SeedSize)
	for index := range raw {
		raw[index] = 21
	}
	private := ed25519.NewKeyFromSeed(raw)
	public := private.Public().(ed25519.PublicKey)
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)

	binding, err := palisadeassurance.SessionBinding(
		[]byte("palisade-assurance-binding-secret-32b"), "session-identifier-value", "relying.example")
	if err != nil {
		t.Fatalf("derive session binding: %v", err)
	}
	decision := decisionWith(benign(EvidenceVerifiedBrowserSequence, core.DimensionContinuity, .64))
	payload := Derive(decision, false).Payload(palisadeassurance.Binding{
		SessionBinding: binding,
		RequestAction:  "login",
		EndpointClass:  "login",
		Audience:       "relying.example",
	}, agentprovenance.Result{}, decision.PolicyVersion, decision.ModelVersion)

	encoded, err := palisadeassurance.Sign(payload, time.Minute, now, private)
	if err != nil {
		t.Fatalf("sign derived payload: %v", err)
	}
	verifier, err := palisadeassurance.NewVerifier(public, "relying.example")
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	verified, err := verifier.Verify(encoded, now)
	if err != nil {
		t.Fatalf("verify derived assertion: %v", err)
	}
	if !verified.Satisfies(palisadeassurance.LevelBehavioral, false) {
		t.Fatal("a derived behavioral assertion did not satisfy its own level")
	}

	// The same derivation for an unattributed decision must also be signable:
	// level 0 is a legitimate statement, not an error.
	empty := Derive(decisionWith(), false).Payload(palisadeassurance.Binding{
		SessionBinding: binding,
		RequestAction:  "read",
		EndpointClass:  "public_content",
		Audience:       "relying.example",
	}, agentprovenance.Result{}, decision.PolicyVersion, decision.ModelVersion)
	if _, err := palisadeassurance.Sign(empty, time.Minute, now, private); err != nil {
		t.Fatalf("sign unattributed payload: %v", err)
	}
}

func TestAgentProvenanceIsCarriedButNeverRaisesAssurance(t *testing.T) {
	// A verified crawler is a legitimate participant whose identity belongs in
	// the assertion. It is still not a human, so the level must stay at zero.
	verified := agentprovenance.Derive(core.Observations{
		VerifiedBot:         true,
		CrawlerClass:        core.CrawlerClassSearchIndexer,
		CrawlerVerification: core.CrawlerVerification("ip_ua_registry"),
	}, "public_content")
	if verified.Provenance != agentprovenance.VerifiedPurpose {
		t.Fatalf("the control case did not verify: %+v", verified)
	}

	payload := Derive(decisionWith(), false).Payload(palisadeassurance.Binding{
		SessionBinding: strings.Repeat("A", 43),
		RequestAction:  "read",
		EndpointClass:  "public_content",
		Audience:       "relying.example",
	}, verified, "default-v5", "transparent-baseline-v13")

	if payload.AgentProvenance != agentprovenance.VerifiedPurpose {
		t.Fatalf("provenance was not carried into the assertion: %+v", payload)
	}
	if payload.AssuranceLevel != palisadeassurance.LevelUnattributed {
		t.Fatalf("a verified agent raised assurance to %d", payload.AssuranceLevel)
	}
	if !contains(payload.ReasonCodes, agentprovenance.ReasonVerifiedPurpose) {
		t.Fatalf("the provenance reason was dropped: %v", payload.ReasonCodes)
	}
	// An empty provenance must still produce a valid closed value.
	fallback := Derive(decisionWith(), false).Payload(palisadeassurance.Binding{
		SessionBinding: strings.Repeat("A", 43),
		RequestAction:  "read",
		EndpointClass:  "public_content",
		Audience:       "relying.example",
	}, agentprovenance.Result{}, "default-v5", "transparent-baseline-v13")
	if fallback.AgentProvenance != agentprovenance.None {
		t.Fatalf("an empty provenance produced %q", fallback.AgentProvenance)
	}
}

func contains(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

func TestInteractiveLivenessIsComputedButWithheldPendingMeasurement(t *testing.T) {
	decision := decisionWith(benign(EvidenceVerifiedBrowserSequence, core.DimensionContinuity, .64))
	withLiveness := Derive(decision, true)

	// The evidence supports H2. This build refuses to state it until a
	// confirmed-human false-positive and abandonment interval exists per level.
	if withLiveness.Level != palisadeassurance.MaximumSupportedLevel {
		t.Fatalf("liveness produced level %d rather than the supported ceiling", withLiveness.Level)
	}
	if !contains(withLiveness.ReasonCodes, reasonLevelPendingMeasurement) {
		t.Fatalf("the withheld level was not explained: %v", withLiveness.ReasonCodes)
	}
	if !contains(withLiveness.ReasonCodes, reasonInteractiveLiveness) {
		t.Fatalf("the completed liveness challenge was not recorded: %v", withLiveness.ReasonCodes)
	}
	// An assertion must not cite evidence for a level it does not claim.
	if contains(withLiveness.Sources, "challenge") {
		t.Fatalf("a withheld level still named its evidence class: %v", withLiveness.Sources)
	}
	if !reflect.DeepEqual(withLiveness.Sources, []string{"behavioral"}) {
		t.Fatalf("unexpected evidence classes: %v", withLiveness.Sources)
	}

	// Liveness alone, without verified interaction evidence, changes nothing.
	if alone := Derive(decisionWith(), true); alone.Level != palisadeassurance.LevelUnattributed {
		t.Fatalf("liveness alone produced level %d", alone.Level)
	}
	// Automation evidence still contradicts presence even with liveness.
	contradicted := Derive(decisionWith(
		benign(EvidenceVerifiedBrowserSequence, core.DimensionContinuity, .64),
		suspicious("BROWSER_PROTOCOL_CONTRADICTION", core.DimensionAutomation, .9),
	), true)
	if contradicted.Level != palisadeassurance.LevelUnattributed {
		t.Fatalf("liveness overrode an automation contradiction: %+v", contradicted)
	}
}
