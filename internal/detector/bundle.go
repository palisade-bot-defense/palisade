package detector

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"time"

	"github.com/palisade-bot-defense/palisade/internal/localartifact"
)

const BundleSchemaVersion = "palisade.detector-bundle.v1"

var modelVersionPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_.:-]{2,63}$`)

type Bundle struct {
	SchemaVersion    string   `json:"schema_version"`
	ModelVersion     string   `json:"model_version"`
	Profile          string   `json:"profile"`
	EnabledDetectors []string `json:"enabled_detectors"`
}

func DefaultBundle() Bundle {
	return Bundle{
		SchemaVersion: BundleSchemaVersion, ModelVersion: DefaultVersion, Profile: DefaultProfile,
		EnabledDetectors: []string{
			"protocol_consistency_v2", "sequence_velocity_v2", "navigation_graph_v1",
			"decoy_interaction_v2", "campaign_surface_v1", "external_verdicts_v3", "edge_intelligence_v1",
		},
	}
}

func (b Bundle) Validate() error {
	if b.SchemaVersion != BundleSchemaVersion || b.Profile != DefaultProfile || !modelVersionPattern.MatchString(b.ModelVersion) ||
		len(b.EnabledDetectors) == 0 || len(b.EnabledDetectors) > maxDetectors {
		return errors.New("invalid closed detector bundle")
	}
	seen := make(map[string]struct{}, len(b.EnabledDetectors))
	for _, id := range b.EnabledDetectors {
		if _, valid := detectorByID(id); !valid {
			return errors.New("invalid closed detector bundle")
		}
		if _, duplicate := seen[id]; duplicate {
			return errors.New("invalid closed detector bundle")
		}
		seen[id] = struct{}{}
	}
	return nil
}

func NewSignedRegistry(encoded []byte, publicKey ed25519.PublicKey, now time.Time) (*Registry, localartifact.Verified, error) {
	verifier, err := localartifact.NewVerifier(publicKey, localartifact.TypeDetector)
	if err != nil {
		return nil, localartifact.Verified{}, err
	}
	verified, err := verifier.VerifyAndAdvance(encoded, now)
	if err != nil {
		return nil, localartifact.Verified{}, err
	}
	var bundle Bundle
	decoder := json.NewDecoder(bytes.NewReader(verified.Payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&bundle); err != nil {
		return nil, localartifact.Verified{}, errors.New("invalid closed detector bundle")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) || bundle.ModelVersion != verified.Metadata.ArtifactID {
		return nil, localartifact.Verified{}, errors.New("invalid closed detector bundle")
	}
	if err := bundle.Validate(); err != nil {
		return nil, localartifact.Verified{}, err
	}
	detectors := make([]Detector, 0, len(bundle.EnabledDetectors))
	for _, id := range bundle.EnabledDetectors {
		current, _ := detectorByID(id)
		detectors = append(detectors, current)
	}
	registry := newRegistry(bundle.ModelVersion, detectors...)
	if err := registry.Err(); err != nil {
		return nil, localartifact.Verified{}, err
	}
	return registry, verified, nil
}

func detectorByID(id string) (Detector, bool) {
	switch id {
	case "protocol_consistency_v2":
		return ProtocolConsistency{}, true
	case "sequence_velocity_v2":
		return SequenceVelocity{}, true
	case "navigation_graph_v1":
		return NavigationGraph{}, true
	case "decoy_interaction_v2":
		return DecoyInteraction{}, true
	case "campaign_surface_v1":
		return CampaignSurface{}, true
	case "external_verdicts_v3":
		return ExternalVerdicts{}, true
	case "edge_intelligence_v1":
		return EdgeIntelligence{}, true
	default:
		return nil, false
	}
}
