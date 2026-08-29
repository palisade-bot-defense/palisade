package sovereignty

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type adversarialSuite struct {
	SchemaVersion string `json:"schema_version"`
	Scope         string `json:"scope"`
	SyntheticOnly bool   `json:"synthetic_only"`
	Scenarios     []struct {
		ID       string   `json:"id"`
		Category string   `json:"category"`
		Expected string   `json:"expected"`
		TestRefs []string `json:"test_refs"`
	} `json:"scenarios"`
}

func TestPublicAdversarialSuiteIsClosedSyntheticAndExecutable(t *testing.T) {
	root := repositoryRoot(t)
	var suite adversarialSuite
	readRepositoryJSON(t, root, "examples/adversarial/suite-v1.json", &suite)
	if suite.SchemaVersion != "palisade.adversarial-suite.v1" || suite.Scope != "roadmap_v0_3_public_conformance" || !suite.SyntheticOnly {
		t.Fatalf("unsafe adversarial suite header: %+v", suite)
	}

	want := map[string]struct {
		category string
		expected string
	}{
		"deterministic_replay":                     {"replay", "byte_identical_output"},
		"challenge_redemption_replay":              {"replay", "reject_second_redemption"},
		"proof_token_replay":                       {"replay", "reject_consumed_proof"},
		"coverage_counter_poisoning":               {"poisoning", "reject_counter_regression_or_conflict"},
		"family_annotation_poisoning":              {"poisoning", "reject_duplicate_family_assignment"},
		"detector_evidence_poisoning":              {"poisoning", "reject_malformed_or_unbounded_evidence"},
		"unverified_browser_sequence":              {"missing_signals", "ignore_unverified_browser_evidence"},
		"missing_trusted_transport_signal":         {"missing_signals", "retain_unknown_transport_state"},
		"partial_collection_signal":                {"missing_signals", "retain_collection_artifact"},
		"direct_forwarding_header_spoof":           {"spoofed_headers", "ignore_headers_from_untrusted_peer"},
		"crawler_identity_header_spoof":            {"spoofed_headers", "do_not_verify_crawler_from_forwarded_spoof"},
		"raw_edge_intelligence_spoof":              {"spoofed_headers", "reject_raw_or_unpaired_edge_values"},
		"reduced_motion_cohort_preserved":          {"accessibility", "preserve_closed_accessibility_cohort"},
		"accessible_fallback_closes_pending_state": {"accessibility", "record_fallback_and_invalidate_pending_grant"},
		"challenge_pass_not_human_label":           {"accessibility", "never_promote_challenge_to_human"},
		"explicit_adapter_failure_modes":           {"adapter_failures", "apply_declared_fail_open_or_fail_closed"},
		"risky_shadow_adapter_response":            {"adapter_failures", "reject_risky_shadow_contract"},
		"unsafe_method_challenge_replay":           {"adapter_failures", "never_buffer_or_replay_unsafe_body"},
	}

	got := make(map[string]struct {
		category string
		expected string
	}, len(suite.Scenarios))
	categoryCounts := map[string]int{}
	for _, scenario := range suite.Scenarios {
		if _, duplicate := got[scenario.ID]; duplicate {
			t.Fatalf("duplicate adversarial scenario %q", scenario.ID)
		}
		got[scenario.ID] = struct {
			category string
			expected string
		}{scenario.Category, scenario.Expected}
		categoryCounts[scenario.Category]++
		if len(scenario.TestRefs) == 0 {
			t.Fatalf("scenario %q has no executable test", scenario.ID)
		}
		for _, reference := range scenario.TestRefs {
			assertGoTestReferenceExists(t, root, scenario.ID, reference)
		}
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("adversarial scenarios = %#v, want %#v", got, want)
	}
	wantCategoryCounts := map[string]int{
		"replay": 3, "poisoning": 3, "missing_signals": 3,
		"spoofed_headers": 3, "accessibility": 3, "adapter_failures": 3,
	}
	if !reflect.DeepEqual(categoryCounts, wantCategoryCounts) {
		t.Fatalf("adversarial category counts = %#v, want %#v", categoryCounts, wantCategoryCounts)
	}
}

func assertGoTestReferenceExists(t *testing.T, root, scenarioID, reference string) {
	t.Helper()
	path, function, ok := strings.Cut(reference, "#")
	cleanPath := filepath.Clean(filepath.FromSlash(path))
	if !ok || filepath.IsAbs(cleanPath) || cleanPath == "." || strings.HasPrefix(cleanPath, ".."+string(filepath.Separator)) ||
		!strings.HasSuffix(cleanPath, "_test.go") || !strings.HasPrefix(function, "Test") {
		t.Fatalf("scenario %q has unsafe test reference %q", scenarioID, reference)
	}
	parsed, err := parser.ParseFile(token.NewFileSet(), filepath.Join(root, cleanPath), nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("scenario %q parse %q: %v", scenarioID, reference, err)
	}
	for _, declaration := range parsed.Decls {
		functionDeclaration, isFunction := declaration.(*ast.FuncDecl)
		if isFunction && functionDeclaration.Recv == nil && functionDeclaration.Name.Name == function {
			return
		}
	}
	t.Fatalf("scenario %q references missing test %q", scenarioID, reference)
}
