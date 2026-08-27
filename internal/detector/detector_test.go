package detector

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/palisade-bot-defense/palisade/internal/core"
)

type testSource struct {
	id       string
	evidence []core.Evidence
}

func (source testSource) ID() string { return source.id }

func (source testSource) Evaluate(context.Context, core.DetectorInput) ([]core.Evidence, error) {
	return source.evidence, nil
}

func TestRegistryAcceptsValidNormalizedSource(t *testing.T) {
	source := testSource{id: "example_source_v1", evidence: []core.Evidence{{
		Code: "EXAMPLE_SIGNAL", Detector: "example_source_v1", Dimension: core.DimensionIntent,
		Direction: core.DirectionSuspicious, Strength: .6, Confidence: .8, TTL: time.Minute,
	}}}
	registry := NewRegistry(source)
	if err := registry.Err(); err != nil {
		t.Fatal(err)
	}
	evidence, err := registry.Evaluate(context.Background(), core.DetectorInput{})
	if err != nil || len(evidence) != 1 || evidence[0].Code != "EXAMPLE_SIGNAL" {
		t.Fatalf("evidence=%+v err=%v", evidence, err)
	}
}

func TestRegistryRejectsDuplicateIDsAtStartup(t *testing.T) {
	registry := NewRegistry(testSource{id: "example_source_v1"}, testSource{id: "example_source_v1"})
	if err := registry.Err(); err == nil || !strings.Contains(err.Error(), "duplicate detector ID") {
		t.Fatalf("registry error=%v", err)
	}
}

func TestRegistryRejectsMalformedEvidence(t *testing.T) {
	registry := NewRegistry(testSource{id: "example_source_v1", evidence: []core.Evidence{{
		Code: "dynamic free text", Detector: "other_source_v1", Dimension: "identity",
		Direction: 0, Strength: 2, Confidence: 2, TTL: 0,
	}}})
	_, err := registry.Evaluate(context.Background(), core.DetectorInput{})
	if err == nil {
		t.Fatal("malformed evidence was accepted")
	}
}

func TestRegistryBoundsEvidence(t *testing.T) {
	evidence := make([]core.Evidence, maxEvidencePerDetector+1)
	registry := NewRegistry(testSource{id: "example_source_v1", evidence: evidence})
	_, err := registry.Evaluate(context.Background(), core.DetectorInput{})
	if err == nil || !strings.Contains(err.Error(), "evidence budget") {
		t.Fatalf("evidence budget error=%v", err)
	}
}
