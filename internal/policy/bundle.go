package policy

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"math"
	"regexp"
	"time"

	"github.com/palisade-bot-defense/palisade/internal/localartifact"
)

const BundleSchemaVersion = "palisade.policy-bundle.v1"

var policyVersionPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_.:-]{2,63}$`)

type Bundle struct {
	SchemaVersion         string  `json:"schema_version"`
	PolicyVersion         string  `json:"policy_version"`
	Profile               string  `json:"profile"`
	AutomationElevated    float64 `json:"automation_elevated"`
	AutomationStepUp      float64 `json:"automation_step_up"`
	AutomationHigh        float64 `json:"automation_high"`
	IntentElevated        float64 `json:"intent_elevated"`
	IntentStepUp          float64 `json:"intent_step_up"`
	IntentHigh            float64 `json:"intent_high"`
	ContinuityStepUpBelow float64 `json:"continuity_step_up_below"`
}

func DefaultBundle() Bundle {
	return Bundle{
		SchemaVersion: BundleSchemaVersion, PolicyVersion: DefaultVersion, Profile: DefaultProfile,
		AutomationElevated: .52, AutomationStepUp: .68, AutomationHigh: .88,
		IntentElevated: .52, IntentStepUp: .68, IntentHigh: .90, ContinuityStepUpBelow: .20,
	}
}

func (b Bundle) Validate() error {
	if b.SchemaVersion != BundleSchemaVersion || b.Profile != DefaultProfile || !policyVersionPattern.MatchString(b.PolicyVersion) ||
		!orderedThresholds(b.AutomationElevated, b.AutomationStepUp, b.AutomationHigh) ||
		!orderedThresholds(b.IntentElevated, b.IntentStepUp, b.IntentHigh) || !boundedThreshold(b.ContinuityStepUpBelow) {
		return errors.New("invalid closed policy bundle")
	}
	return nil
}

func NewSigned(encoded []byte, publicKey ed25519.PublicKey, now time.Time) (*Engine, localartifact.Verified, error) {
	verifier, err := localartifact.NewVerifier(publicKey, localartifact.TypePolicy)
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
		return nil, localartifact.Verified{}, errors.New("invalid closed policy bundle")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) || bundle.PolicyVersion != verified.Metadata.ArtifactID {
		return nil, localartifact.Verified{}, errors.New("invalid closed policy bundle")
	}
	engine, err := newEngine(bundle)
	if err != nil {
		return nil, localartifact.Verified{}, err
	}
	return engine, verified, nil
}

func orderedThresholds(low, middle, high float64) bool {
	return boundedThreshold(low) && boundedThreshold(middle) && boundedThreshold(high) && low < middle && middle < high
}

func boundedThreshold(value float64) bool {
	return !math.IsNaN(value) && !math.IsInf(value, 0) && value >= .05 && value <= .99
}
