package policy

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/palisade-bot-defense/palisade/internal/core"
	"github.com/palisade-bot-defense/palisade/internal/localartifact"
)

func TestDefaultPolicyBundleExampleMatchesRuntime(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "policies", "defaults", "policy-bundle.json"))
	if err != nil {
		t.Fatal(err)
	}
	var bundle Bundle
	if err := decodeBundleTest(data, &bundle); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(bundle, DefaultBundle()) {
		t.Fatalf("example=%+v runtime=%+v", bundle, DefaultBundle())
	}
}

func TestSignedPolicyBundleChangesOnlyBoundedThresholds(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	bundle := DefaultBundle()
	bundle.PolicyVersion = "operator-policy-v1"
	bundle.AutomationElevated = .60
	encoded, err := localartifact.Sign(localartifact.Metadata{
		ArtifactType: localartifact.TypePolicy, ArtifactID: bundle.PolicyVersion, Revision: 1,
		IssuedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339),
	}, bundle, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	engine, verified, err := NewSigned(encoded, publicKey, now)
	if err != nil {
		t.Fatal(err)
	}
	if engine.Version() != bundle.PolicyVersion || verified.Metadata.ArtifactID != bundle.PolicyVersion {
		t.Fatalf("engine=%s metadata=%+v", engine.Version(), verified.Metadata)
	}
	result, err := engine.Evaluate(Input{Scores: core.Scores{AutomationRisk: .55, AbuseIntentRisk: .1, AccountContinuity: .5}})
	if err != nil || result.Action != core.ActionAllow {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	result, err = engine.Evaluate(Input{Scores: core.Scores{AutomationRisk: .61, AbuseIntentRisk: .1, AccountContinuity: .5}})
	if err != nil || result.Action != core.ActionDelay {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}

func TestPolicyBundleRejectsThresholdAndSchemaPoisoning(t *testing.T) {
	tests := []Bundle{
		func() Bundle { b := DefaultBundle(); b.AutomationStepUp = b.AutomationElevated; return b }(),
		func() Bundle { b := DefaultBundle(); b.IntentHigh = 1.1; return b }(),
		func() Bundle { b := DefaultBundle(); b.Profile = "load-plugin"; return b }(),
		func() Bundle { b := DefaultBundle(); b.PolicyVersion = "free text"; return b }(),
	}
	for index, bundle := range tests {
		if err := bundle.Validate(); err == nil {
			t.Fatalf("poisoned bundle %d accepted: %+v", index, bundle)
		}
	}

	now := time.Unix(1_800_000_000, 0).UTC()
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	bundle := DefaultBundle()
	bundle.PolicyVersion = "operator-policy-v1"
	payload, _ := json.Marshal(bundle)
	var fields map[string]any
	_ = json.Unmarshal(payload, &fields)
	fields["expression"] = "load('https://example.invalid/policy')"
	encoded, err := localartifact.Sign(localartifact.Metadata{
		ArtifactType: localartifact.TypePolicy, ArtifactID: bundle.PolicyVersion, Revision: 1,
		IssuedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339),
	}, fields, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := NewSigned(encoded, publicKey, now); err == nil {
		t.Fatal("signed free-form policy field was accepted")
	}
}

func decodeBundleTest(data []byte, target any) error {
	return json.Unmarshal(data, target)
}
