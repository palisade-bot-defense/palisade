package detector

import (
	"context"
	"errors"
	"fmt"
	"math"
	"regexp"
	"time"

	"github.com/palisade-bot-defense/palisade/internal/core"
)

const (
	maxDetectors           = 32
	maxEvidencePerDetector = 32
	maxEvidenceTotal       = 128
)

var (
	errInvalidRegistry  = errors.New("invalid detector registry")
	detectorIDPattern   = regexp.MustCompile(`^[a-z][a-z0-9_]{2,63}$`)
	evidenceCodePattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]{2,63}$`)
)

type Detector interface {
	ID() string
	Evaluate(context.Context, core.DetectorInput) ([]core.Evidence, error)
}

type Registry struct {
	detectors []Detector
	err       error
}

func NewRegistry(detectors ...Detector) *Registry {
	registry := &Registry{detectors: append([]Detector(nil), detectors...)}
	registry.err = validateRegistry(registry.detectors)
	return registry
}

// NewDefaultRegistry returns the immutable detector set used by both the live
// decision service and deterministic replay. Performance gates use the same
// constructor so a production detector cannot silently escape the measured
// hot path.
func NewDefaultRegistry() *Registry {
	return NewRegistry(
		ProtocolConsistency{}, SequenceVelocity{}, NavigationGraph{},
		DecoyInteraction{}, CampaignSurface{}, ExternalVerdicts{}, EdgeIntelligence{},
	)
}

// Err reports configuration errors detected when the immutable registry was
// constructed. Call it during startup so invalid source adapters fail before
// the service begins accepting traffic.
func (r *Registry) Err() error {
	if r == nil {
		return fmt.Errorf("%w: nil registry", errInvalidRegistry)
	}
	return r.err
}

func (r *Registry) Evaluate(ctx context.Context, input core.DetectorInput) ([]core.Evidence, error) {
	if err := r.Err(); err != nil {
		return nil, err
	}
	var all []core.Evidence
	for _, current := range r.detectors {
		evidence, err := current.Evaluate(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("detector %s: %w", current.ID(), err)
		}
		if len(evidence) > maxEvidencePerDetector || len(all)+len(evidence) > maxEvidenceTotal {
			return nil, fmt.Errorf("detector %s exceeded evidence budget", current.ID())
		}
		for _, item := range evidence {
			if err := validateEvidence(current.ID(), item); err != nil {
				return nil, err
			}
		}
		all = append(all, evidence...)
	}
	return all, nil
}

func validateRegistry(detectors []Detector) error {
	if len(detectors) > maxDetectors {
		return fmt.Errorf("%w: detector count exceeds %d", errInvalidRegistry, maxDetectors)
	}
	seen := make(map[string]struct{}, len(detectors))
	for _, current := range detectors {
		if current == nil {
			return fmt.Errorf("%w: nil detector", errInvalidRegistry)
		}
		id := current.ID()
		if !detectorIDPattern.MatchString(id) {
			return fmt.Errorf("%w: invalid detector ID %q", errInvalidRegistry, id)
		}
		if _, exists := seen[id]; exists {
			return fmt.Errorf("%w: duplicate detector ID %q", errInvalidRegistry, id)
		}
		seen[id] = struct{}{}
	}
	return nil
}

func validateEvidence(detectorID string, item core.Evidence) error {
	if item.Detector != detectorID {
		return fmt.Errorf("detector %s emitted evidence for %q", detectorID, item.Detector)
	}
	if !evidenceCodePattern.MatchString(item.Code) {
		return fmt.Errorf("detector %s emitted invalid evidence code %q", detectorID, item.Code)
	}
	if item.Dimension != core.DimensionAutomation && item.Dimension != core.DimensionIntent && item.Dimension != core.DimensionContinuity {
		return fmt.Errorf("detector %s emitted invalid dimension %q", detectorID, item.Dimension)
	}
	if item.Direction != core.DirectionBenign && item.Direction != core.DirectionSuspicious {
		return fmt.Errorf("detector %s emitted invalid direction %d", detectorID, item.Direction)
	}
	if math.IsNaN(item.Strength) || math.IsInf(item.Strength, 0) || item.Strength < 0 || item.Strength > 1 {
		return fmt.Errorf("detector %s emitted invalid strength", detectorID)
	}
	if math.IsNaN(item.Confidence) || math.IsInf(item.Confidence, 0) || item.Confidence < 0 || item.Confidence > 1 {
		return fmt.Errorf("detector %s emitted invalid confidence", detectorID)
	}
	if item.TTL <= 0 || item.TTL > 24*time.Hour {
		return fmt.Errorf("detector %s emitted invalid TTL", detectorID)
	}
	return nil
}
