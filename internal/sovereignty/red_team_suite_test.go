package sovereignty

import (
	"reflect"
	"testing"
)

type redTeamSuite struct {
	SchemaVersion string `json:"schema_version"`
	Scope         string `json:"scope"`
	SyntheticOnly bool   `json:"synthetic_only"`
	NetworkPolicy string `json:"network_policy"`
	Scenarios     []struct {
		ID       string   `json:"id"`
		Category string   `json:"category"`
		Asset    string   `json:"asset"`
		Expected string   `json:"expected"`
		TestRefs []string `json:"test_refs"`
	} `json:"scenarios"`
}

func TestSyntheticRedTeamSuiteIsClosedCompleteAndExecutable(t *testing.T) {
	root := repositoryRoot(t)
	var suite redTeamSuite
	readRepositoryJSON(t, root, "examples/redteam/suite-v1.json", &suite)
	if suite.SchemaVersion != "palisade.red-team-suite.v1" || suite.Scope != "roadmap_v0_9_synthetic_baseline" ||
		!suite.SyntheticOnly || suite.NetworkPolicy != "module_downloads_disabled" {
		t.Fatalf("unsafe red-team suite header: %+v", suite)
	}

	type contract struct {
		category string
		asset    string
		expected string
	}
	want := map[string]contract{
		"browser_challenge_humanity_evasion": {"evasion", "decision_integrity", "challenge_pass_never_confirms_human"},
		"verified_crawler_intent_evasion":    {"evasion", "decision_integrity", "verified_identity_cannot_override_abuse_intent"},
		"signed_edge_payload_poisoning":      {"poisoning", "trusted_signal_boundary", "reject_noncanonical_or_inconsistent_signal"},
		"signed_policy_threshold_poisoning":  {"poisoning", "trusted_signal_boundary", "reject_uncompiled_or_invalid_policy"},
		"native_challenge_redemption_relay":  {"proof_relay", "challenge_capability", "reject_replay_or_binding_mismatch"},
		"origin_flow_binding_relay":          {"proof_relay", "challenge_capability", "bind_grant_to_target_sequence_session_and_instance"},
		"anonymous_session_reset":            {"session_reset", "session_continuity", "new_session_is_isolated_and_not_verified"},
		"expired_event_receipt_reset":        {"session_reset", "session_continuity", "expire_receipt_and_start_fresh_sequence"},
		"session_store_capacity_exhaustion":  {"resource_exhaustion", "bounded_availability", "evict_within_fixed_capacity"},
		"offline_import_budget_exhaustion":   {"resource_exhaustion", "bounded_availability", "fail_closed_without_published_output"},
		"signed_rollout_tampering":           {"rollout_compromise", "rollout_authority", "reject_tampered_or_mismatched_rollout"},
		"expired_rollout_reuse":              {"rollout_compromise", "rollout_authority", "downgrade_expired_rollout_to_shadow"},
	}

	got := make(map[string]contract, len(suite.Scenarios))
	categoryCounts := make(map[string]int)
	for _, scenario := range suite.Scenarios {
		if _, duplicate := got[scenario.ID]; duplicate {
			t.Fatalf("duplicate red-team scenario %q", scenario.ID)
		}
		got[scenario.ID] = contract{scenario.Category, scenario.Asset, scenario.Expected}
		categoryCounts[scenario.Category]++
		if len(scenario.TestRefs) == 0 {
			t.Fatalf("red-team scenario %q has no executable test", scenario.ID)
		}
		for _, reference := range scenario.TestRefs {
			assertGoTestReferenceExists(t, root, scenario.ID, reference)
		}
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("red-team scenarios = %#v, want %#v", got, want)
	}
	wantCategoryCounts := map[string]int{
		"evasion": 2, "poisoning": 2, "proof_relay": 2,
		"session_reset": 2, "resource_exhaustion": 2, "rollout_compromise": 2,
	}
	if !reflect.DeepEqual(categoryCounts, wantCategoryCounts) {
		t.Fatalf("red-team category counts = %#v, want %#v", categoryCounts, wantCategoryCounts)
	}
}
