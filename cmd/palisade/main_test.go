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
