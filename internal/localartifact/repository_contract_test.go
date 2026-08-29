package localartifact

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRepositorySchemasTrackClosedArtifactContract(t *testing.T) {
	root := filepath.Join("..", "..")
	tests := []struct {
		path     string
		required []string
	}{
		{
			path: filepath.Join(root, "schemas", "local-artifact-v1.schema.json"),
			required: []string{
				`"palisade.local-artifact.v1"`, `"policy_bundle"`, `"detector_bundle"`,
				`"revision"`, `"issued_at"`, `"expires_at"`, `"key_id"`,
			},
		},
		{
			path: filepath.Join(root, "schemas", "policy-bundle-v1.schema.json"),
			required: []string{
				`"palisade.policy-bundle.v1"`, `"transparent-progressive-v1"`,
				`"automation_elevated"`, `"automation_step_up"`, `"automation_high"`,
				`"intent_elevated"`, `"intent_step_up"`, `"intent_high"`, `"continuity_step_up_below"`,
			},
		},
		{
			path: filepath.Join(root, "schemas", "detector-bundle-v1.schema.json"),
			required: []string{
				`"palisade.detector-bundle.v1"`, `"transparent-baseline-v1"`,
				`"protocol_consistency_v2"`, `"sequence_velocity_v2"`, `"navigation_graph_v1"`,
				`"decoy_interaction_v2"`, `"campaign_surface_v1"`, `"external_verdicts_v3"`, `"edge_intelligence_v1"`,
			},
		},
	}
	for _, test := range tests {
		data, err := os.ReadFile(test.path)
		if err != nil {
			t.Fatal(err)
		}
		for _, required := range test.required {
			if !strings.Contains(string(data), required) {
				t.Errorf("%s is missing %s", test.path, required)
			}
		}
	}
}
