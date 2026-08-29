package localsequence

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
)

func TestAdversarialHoldoutSuiteIsClosedAndSynthetic(t *testing.T) {
	_, current, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate adversarial contract test")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(current), "..", ".."))
	content, err := os.ReadFile(filepath.Join(root, "examples", "holdout", "adversarial-scenarios-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var suite struct {
		SchemaVersion string `json:"schema_version"`
		Scope         string `json:"scope"`
		SyntheticOnly bool   `json:"synthetic_only"`
		Scenarios     []struct {
			ID       string `json:"id"`
			Expected string `json:"expected"`
		} `json:"scenarios"`
	}
	if err := json.Unmarshal(content, &suite); err != nil {
		t.Fatal(err)
	}
	if suite.SchemaVersion != "palisade.adversarial-holdout-suite.v1" || suite.Scope != "local_holdout_contract" || !suite.SyntheticOnly {
		t.Fatalf("unsafe adversarial suite header: %+v", suite)
	}
	want := map[string]string{
		"random_split_leakage":         "predeclared_chronological_only",
		"boundary_window_leakage":      "exclude_crossing_window",
		"unknown_as_human":             "retain_unknown_denominator",
		"conflicting_confirmed_labels": "count_ambiguous",
		"collection_failure_bias":      "retain_collection_artifact",
		"seen_family_leakage":          "isolate_unseen_family",
		"annotation_poisoning":         "reject_duplicate_assignment",
		"challenge_humanity_inference": "never_promote_to_human",
		"resource_exhaustion":          "fail_closed_on_budget",
	}
	got := make(map[string]string, len(suite.Scenarios))
	for _, scenario := range suite.Scenarios {
		if _, duplicate := got[scenario.ID]; duplicate {
			t.Fatalf("duplicate adversarial scenario %q", scenario.ID)
		}
		got[scenario.ID] = scenario.Expected
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("adversarial scenarios = %#v, want %#v", got, want)
	}
}
