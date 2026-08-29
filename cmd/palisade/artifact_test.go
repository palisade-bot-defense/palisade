package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/palisade-bot-defense/palisade/internal/detector"
	"github.com/palisade-bot-defense/palisade/internal/localartifact"
	"github.com/palisade-bot-defense/palisade/internal/policy"
)

func TestArtifactKeygenAndPreparePolicyRoundTrip(t *testing.T) {
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	privatePath := filepath.Join(directory, "config.private")
	publicPath := filepath.Join(directory, "config.public")
	if err := artifactKeygen([]string{"--private-key", privatePath, "--public-key", publicPath}); err != nil {
		t.Fatal(err)
	}
	payloadPath := filepath.Join(directory, "policy.json")
	payload := `{"schema_version":"palisade.policy-bundle.v1","policy_version":"operator-policy-v1","profile":"transparent-progressive-v1","automation_elevated":0.52,"automation_step_up":0.68,"automation_high":0.88,"intent_elevated":0.52,"intent_step_up":0.68,"intent_high":0.9,"continuity_step_up_below":0.2}`
	if err := os.WriteFile(payloadPath, []byte(payload), 0o600); err != nil {
		t.Fatal(err)
	}
	outputPath := filepath.Join(directory, "policy.signed.json")
	if err := prepareLocalArtifact([]string{
		"--type", localartifact.TypePolicy, "--payload", payloadPath, "--private-key", privatePath,
		"--output", outputPath, "--revision", "3", "--lifetime", "1h",
	}); err != nil {
		t.Fatal(err)
	}
	encoded, err := localartifact.ReadDocument(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := localartifact.ReadPublicKey(publicPath)
	if err != nil {
		t.Fatal(err)
	}
	engine, verified, err := policy.NewSigned(encoded, publicKey, time.Now().UTC())
	if err != nil || engine.Version() != "operator-policy-v1" || verified.Metadata.Revision != 3 {
		t.Fatalf("engine=%v verified=%+v err=%v", engine, verified, err)
	}
	if err := verifyLocalArtifact([]string{"--type", localartifact.TypePolicy, "--artifact", outputPath, "--public-key", publicPath}); err != nil {
		t.Fatal(err)
	}
	if err := prepareLocalArtifact([]string{
		"--type", localartifact.TypePolicy, "--payload", payloadPath, "--private-key", privatePath,
		"--output", outputPath, "--revision", "4", "--lifetime", "1h",
	}); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("overwrite error=%v", err)
	}
}

func TestRuntimeArtifactSetUsesExactVersionsAndEarliestExpiry(t *testing.T) {
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	privatePath := filepath.Join(directory, "config.private")
	publicPath := filepath.Join(directory, "config.public")
	if err := artifactKeygen([]string{"--private-key", privatePath, "--public-key", publicPath}); err != nil {
		t.Fatal(err)
	}
	privateKey, err := localartifact.ReadPrivateKey(privatePath)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0).UTC()
	policyBundle := policy.DefaultBundle()
	policyBundle.PolicyVersion = "operator-policy-v1"
	policyDocument, err := localartifact.Sign(localartifact.Metadata{
		ArtifactType: localartifact.TypePolicy, ArtifactID: policyBundle.PolicyVersion, Revision: 2,
		IssuedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(2 * time.Hour).Format(time.RFC3339),
	}, policyBundle, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	policyPath := filepath.Join(directory, "policy.signed.json")
	if err := localartifact.WriteDocument(policyPath, policyDocument); err != nil {
		t.Fatal(err)
	}
	detectorBundle := detector.DefaultBundle()
	detectorBundle.ModelVersion = "operator-model-v1"
	detectorDocument, err := localartifact.Sign(localartifact.Metadata{
		ArtifactType: localartifact.TypeDetector, ArtifactID: detectorBundle.ModelVersion, Revision: 5,
		IssuedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339),
	}, detectorBundle, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	detectorPath := filepath.Join(directory, "detector.signed.json")
	if err := localartifact.WriteDocument(detectorPath, detectorDocument); err != nil {
		t.Fatal(err)
	}
	loaded, err := loadRuntimeArtifacts(policyPath, publicPath, detectorPath, publicPath, now)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.policy.Version() != policyBundle.PolicyVersion || loaded.detectors.Version() != detectorBundle.ModelVersion ||
		!loaded.expiresAt.Equal(now.Add(time.Hour)) || loaded.policyStatus == nil || loaded.detectorStatus == nil ||
		loaded.policyStatus.Revision != 2 || loaded.detectorStatus.Revision != 5 {
		t.Fatalf("loaded=%+v", loaded)
	}
}

func TestPrepareLocalArtifactRejectsExecutableOrUnknownPayload(t *testing.T) {
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	payloadPath := filepath.Join(directory, "poison.json")
	if err := os.WriteFile(payloadPath, []byte(`{"schema_version":"palisade.policy-bundle.v1","expression":"fetch('https://example.invalid')"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := validateArtifactPayload(localartifact.TypePolicy, mustReadTest(t, payloadPath)); err == nil {
		t.Fatal("executable policy payload was accepted")
	}
	if _, err := validateArtifactPayload("plugin_bundle", []byte(`{}`)); err == nil {
		t.Fatal("unknown artifact type was accepted")
	}
	linkPath := filepath.Join(directory, "payload-link.json")
	if err := os.Symlink(payloadPath, linkPath); err != nil {
		t.Fatal(err)
	}
	if _, err := readBoundedPayload(linkPath); err == nil {
		t.Fatal("symlinked signing payload was accepted")
	}
}

func mustReadTest(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
