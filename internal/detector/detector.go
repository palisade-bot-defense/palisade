package detector

import (
	"context"

	"github.com/palisade-bot-defense/palisade/internal/core"
)

type Detector interface {
	ID() string
	Evaluate(context.Context, core.DetectorInput) ([]core.Evidence, error)
}

type Registry struct {
	detectors []Detector
}

func NewRegistry(detectors ...Detector) *Registry {
	return &Registry{detectors: append([]Detector(nil), detectors...)}
}

func (r *Registry) Evaluate(ctx context.Context, input core.DetectorInput) ([]core.Evidence, error) {
	var all []core.Evidence
	for _, current := range r.detectors {
		evidence, err := current.Evaluate(ctx, input)
		if err != nil {
			return nil, err
		}
		all = append(all, evidence...)
	}
	return all, nil
}
