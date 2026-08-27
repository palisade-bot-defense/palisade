package main

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/palisade-bot-defense/palisade/internal/core"
	"github.com/palisade-bot-defense/palisade/internal/replay"
)

func TestReplayEngineOutputIsDeterministic(t *testing.T) {
	const input = `{"observed_at":"2026-01-15T12:00:00Z","request":{"session_id":"session-12345678","action":"read","endpoint_class":"account","sequence":1,"observations":{"honeypot_hits":1,"policy_alert":true}},"expected_action":"observe","expected_computed_action":"block"}` + "\n"

	first := runReplayForTest(t, input)
	second := runReplayForTest(t, input)
	if first != second {
		t.Fatalf("replay output differs between identical runs:\nfirst:  %s\nsecond: %s", first, second)
	}
	if !strings.Contains(first, `"decision_id":"replay-000001"`) || !strings.Contains(first, `"expires_at":"2026-01-15T12:00:30Z"`) {
		t.Fatalf("replay did not use deterministic identity and time: %s", first)
	}
}

func TestReplayObservationTimeDrivesSessionTTLAndExpiry(t *testing.T) {
	const input = `{"observed_at":"2026-01-15T12:00:00Z","request":{"session_id":"session-12345678","action":"read","endpoint_class":"account","sequence":1,"observations":{"user_agent_present":true}}}` + "\n" +
		`{"observed_at":"2026-01-15T12:01:00Z","request":{"session_id":"session-12345678","action":"read","endpoint_class":"account","sequence":50,"observations":{"user_agent_present":true}}}` + "\n" +
		`{"observed_at":"2026-01-15T12:07:00Z","request":{"session_id":"session-12345678","action":"read","endpoint_class":"account","sequence":100,"observations":{"user_agent_present":true}}}` + "\n"

	first := runReplayForTest(t, input)
	if second := runReplayForTest(t, input); first != second {
		t.Fatal("multi-record replay output is not byte deterministic")
	}
	lines := strings.Split(strings.TrimSpace(first), "\n")
	if len(lines) != 3 {
		t.Fatalf("got %d output lines, want 3", len(lines))
	}
	type replayOutput struct {
		ObservedAt time.Time     `json:"observed_at"`
		Decision   core.Decision `json:"decision"`
	}
	outputs := make([]replayOutput, len(lines))
	for index, line := range lines {
		if err := json.Unmarshal([]byte(line), &outputs[index]); err != nil {
			t.Fatal(err)
		}
		if want := outputs[index].ObservedAt.Add(30 * time.Second); !outputs[index].Decision.ExpiresAt.Equal(want) {
			t.Fatalf("line %d expiry = %s, want %s", index+1, outputs[index].Decision.ExpiresAt, want)
		}
	}
	if !decisionHasEvidence(outputs[1].Decision, "SEQUENCE_GAP_HIGH") {
		t.Fatalf("second record did not retain the pre-TTL session: %+v", outputs[1].Decision.Evidence)
	}
	if decisionHasEvidence(outputs[2].Decision, "SEQUENCE_GAP_HIGH") {
		t.Fatalf("third record did not expire the session after five minutes: %+v", outputs[2].Decision.Evidence)
	}
}

func TestRuntimeModeParsingRequiresExplicitEnforce(t *testing.T) {
	if mode, err := parseRuntimeMode("enforce"); err != nil || mode != core.RuntimeModeEnforce {
		t.Fatalf("parse enforce: mode=%s err=%v", mode, err)
	}
	if _, err := parseRuntimeMode(""); err == nil {
		t.Fatal("empty runtime mode was accepted")
	}
}

func TestNoindexCompareComputesStepUpButRemainsShadowObserve(t *testing.T) {
	engine, _, err := buildReplayEngine(core.RuntimeModeShadow)
	if err != nil {
		t.Fatal(err)
	}
	decision, err := engine.DecideAt(context.Background(), core.DecisionRequest{
		SessionID:     "campaign-surface-session",
		Action:        "read",
		EndpointClass: "compare_noindex",
		Sequence:      1,
		Observations:  core.Observations{UserAgentPresent: true},
	}, time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if decision.Action != core.ActionObserve || decision.ComputedAction != core.ActionChallenge {
		t.Fatalf("decision = action %s computed %s, want observe/challenge", decision.Action, decision.ComputedAction)
	}
	if !decisionHasEvidence(decision, "COMPARE_NOINDEX_CAMPAIGN_SURFACE") {
		t.Fatalf("missing campaign-surface evidence: %+v", decision.Evidence)
	}
}

func TestOfflineImportRejectsFutureProvenance(t *testing.T) {
	err := runOfflineImport([]string{
		"--input-dir", "synthetic-input",
		"--output-dir", "synthetic-output",
		"--pseudonym-key-file", "synthetic-key",
		"--dataset-id", "synthetic-dataset",
		"--pilot-id", "synthetic-pilot",
		"--provenance", "deployment_local",
	})
	if err == nil || !strings.Contains(err.Error(), "only offline_export") {
		t.Fatalf("future provenance was not rejected: %v", err)
	}
}

func TestServeRequiresBothShadowLogPaths(t *testing.T) {
	err := serve([]string{"--dev", "--shadow-log-dir", "synthetic-shadow-dir"})
	if err == nil || !strings.Contains(err.Error(), "configured together") {
		t.Fatalf("partial shadow log configuration error = %v", err)
	}
}

func TestAdminListenerIsLoopbackOnly(t *testing.T) {
	for _, address := range []string{"0.0.0.0:8081", "[::]:8081", "localhost:8081", "127.0.0.1:0", "invalid"} {
		if err := validateAdminListen(address); err == nil {
			t.Fatalf("unsafe admin listener %q was accepted", address)
		}
	}
	for _, address := range []string{"127.0.0.1:8081", "[::1]:8081"} {
		if err := validateAdminListen(address); err != nil {
			t.Fatalf("loopback admin listener %q was rejected: %v", address, err)
		}
	}
}

func TestAdminSecretIsRequiredAndDistinct(t *testing.T) {
	t.Setenv("PALISADE_ADMIN_KEY", "")
	if key, err := adminSecret(true, "development-only"); err != nil || key != "development-only-admin" {
		t.Fatalf("development admin key = %q, %v", key, err)
	}
	if _, err := adminSecret(false, "api-key"); err == nil {
		t.Fatal("production accepted missing admin key")
	}
	const shared = "0123456789abcdef0123456789abcdef"
	t.Setenv("PALISADE_ADMIN_KEY", shared)
	if _, err := adminSecret(false, shared); err == nil {
		t.Fatal("production accepted shared API and admin credential")
	}
	t.Setenv("PALISADE_ADMIN_KEY", "abcdef0123456789abcdef0123456789")
	if _, err := adminSecret(false, shared); err != nil {
		t.Fatalf("distinct production admin key was rejected: %v", err)
	}
}

func TestServeEventShadowEvaluationRequiresCompleteSafeConfiguration(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{name: "paired profile", args: []string{"--dev", "--event-shadow-action", "read"}, want: "configured together"},
		{name: "encrypted sink", args: []string{"--dev", "--event-shadow-action", "read", "--event-shadow-endpoint-class", "public_content", "--require-session-cookie"}, want: "encrypted shadow log"},
		{name: "signed session", args: []string{"--dev", "--event-shadow-action", "read", "--event-shadow-endpoint-class", "public_content", "--shadow-log-dir", "synthetic", "--shadow-log-key-file", "synthetic-key"}, want: "require-session-cookie"},
		{name: "closed profile", args: []string{"--dev", "--event-shadow-action", "unbounded", "--event-shadow-endpoint-class", "public_content", "--shadow-log-dir", "synthetic", "--shadow-log-key-file", "synthetic-key", "--require-session-cookie"}, want: "invalid event shadow evaluation profile"},
		{name: "shadow only", args: []string{"--dev", "--event-shadow-action", "read", "--event-shadow-endpoint-class", "public_content", "--shadow-log-dir", "synthetic", "--shadow-log-key-file", "synthetic-key", "--require-session-cookie", "--rollout-plan", "synthetic-plan", "--rollout-public-key", "synthetic-public-key"}, want: "shadow-only"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := serve(test.args)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("serve error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestServeRejectsUnsignedEnforcement(t *testing.T) {
	err := serve([]string{"--dev", "--mode", "enforce"})
	if err == nil || !strings.Contains(err.Error(), "signed rollout plan") {
		t.Fatalf("unsigned enforcement error=%v", err)
	}
}

func TestServeRejectsSignedRolloutInDevelopmentMode(t *testing.T) {
	err := serve([]string{"--dev", "--rollout-plan", "synthetic-plan", "--rollout-public-key", "synthetic-key"})
	if err == nil || !strings.Contains(err.Error(), "stable production secrets") {
		t.Fatalf("development rollout error=%v", err)
	}
}

func TestServeRolloutRequiresStableSessionAndMeasurementSink(t *testing.T) {
	err := serve([]string{
		"--rollout-plan", "synthetic-plan", "--rollout-public-key", "synthetic-key",
		"--shadow-log-dir", "synthetic-logs", "--shadow-log-key-file", "synthetic-log-key",
	})
	if err == nil || !strings.Contains(err.Error(), "require-session-cookie") {
		t.Fatalf("missing session gate error=%v", err)
	}
	err = serve([]string{
		"--rollout-plan", "synthetic-plan", "--rollout-public-key", "synthetic-key", "--require-session-cookie",
	})
	if err == nil || !strings.Contains(err.Error(), "encrypted shadow log") {
		t.Fatalf("missing measurement sink error=%v", err)
	}
}

func TestRolloutPathsMustBeConfiguredTogether(t *testing.T) {
	_, err := loadRollout("synthetic-plan", "", []byte("0123456789abcdef0123456789abcdef"), time.Now())
	if err == nil || !strings.Contains(err.Error(), "configured together") {
		t.Fatalf("partial rollout error=%v", err)
	}
}

func TestEnforcementPreparationRequiresNamedPredecessorCanary(t *testing.T) {
	err := prepareRollout([]string{
		"--analysis", "synthetic-analysis", "--private-key", "synthetic-key", "--output", "synthetic-plan",
		"--rollout-id", "enforce-test", "--approval-id", "review-test", "--stage", "enforce", "--endpoints", "public_content",
	})
	if err == nil || !strings.Contains(err.Error(), "predecessor-rollout-id") {
		t.Fatalf("missing predecessor error=%v", err)
	}
}

func runReplayForTest(t *testing.T, input string) string {
	t.Helper()
	engine, _, err := buildReplayEngine(core.RuntimeModeShadow)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := replay.Run(context.Background(), strings.NewReader(input), &output, engine); err != nil {
		t.Fatal(err)
	}
	return output.String()
}

func decisionHasEvidence(decision core.Decision, code string) bool {
	for _, evidence := range decision.Evidence {
		if evidence.Code == code {
			return true
		}
	}
	return false
}
