package detector

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/palisade-human-trust/palisade/internal/localartifact"
)

func TestDefaultDetectorBundleExampleMatchesRuntime(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "detectors", "defaults", "detector-bundle.json"))
	if err != nil {
		t.Fatal(err)
	}
	var bundle Bundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(bundle, DefaultBundle()) {
		t.Fatalf("example=%+v runtime=%+v", bundle, DefaultBundle())
	}
}

func TestSignedDetectorBundleSelectsOnlyCompiledDetectors(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	bundle := DefaultBundle()
	bundle.ModelVersion = "operator-model-v1"
	bundle.EnabledDetectors = []string{"protocol_consistency_v2", "edge_intelligence_v1"}
	encoded, err := localartifact.Sign(localartifact.Metadata{
		ArtifactType: localartifact.TypeDetector, ArtifactID: bundle.ModelVersion, Revision: 7,
		IssuedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339),
	}, bundle, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	registry, verified, err := NewSignedRegistry(encoded, publicKey, now)
	if err != nil {
		t.Fatal(err)
	}
	if registry.Version() != bundle.ModelVersion || len(registry.detectors) != 2 || verified.Metadata.Revision != 7 {
		t.Fatalf("registry=%+v verified=%+v", registry, verified)
	}
	if registry.detectors[0].ID() != "protocol_consistency_v2" || registry.detectors[1].ID() != "edge_intelligence_v1" {
		t.Fatalf("unexpected detector set: %+v", registry.detectors)
	}
}

func TestDetectorBundleRejectsUnknownDuplicateAndArtifactIDMismatch(t *testing.T) {
	for _, enabled := range [][]string{{}, {"runtime_plugin_v1"}, {"edge_intelligence_v1", "edge_intelligence_v1"}} {
		bundle := DefaultBundle()
		bundle.EnabledDetectors = enabled
		if err := bundle.Validate(); err == nil {
			t.Fatalf("invalid detector set accepted: %v", enabled)
		}
	}

	now := time.Unix(1_800_000_000, 0).UTC()
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	bundle := DefaultBundle()
	bundle.ModelVersion = "operator-model-v1"
	encoded, err := localartifact.Sign(localartifact.Metadata{
		ArtifactType: localartifact.TypeDetector, ArtifactID: "different-model-v1", Revision: 1,
		IssuedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339),
	}, bundle, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := NewSignedRegistry(encoded, publicKey, now); err == nil {
		t.Fatal("artifact ID and model version mismatch was accepted")
	}
}
