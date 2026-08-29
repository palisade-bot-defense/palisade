package shadowanalysis

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/palisade-bot-defense/palisade/internal/core"
	"github.com/palisade-bot-defense/palisade/internal/shadowlog"
)

func TestShadowHoldoutPartitionsByDecisionTimeAndKeepsDelayedLabelsExact(t *testing.T) {
	report := syntheticShadowHoldoutReport(t)
	if report.Readiness.State != "chronological_ready" || report.Readiness.AutomaticEnforcement {
		t.Fatalf("readiness = %+v", report.Readiness)
	}
	if report.Baseline.Decisions != 2 || report.Baseline.ConfirmedHuman != 1 || report.Baseline.ConfirmedAbuse != 1 ||
		report.Holdout.Decisions != 3 || report.Holdout.ConfirmedHuman != 1 || report.Holdout.ConfirmedAbuse != 1 || report.Holdout.UnlabeledDecisions != 1 {
		t.Fatalf("baseline=%+v holdout=%+v", report.Baseline, report.Holdout)
	}
	if report.Baseline.Evaluation.Confusion.FalsePositive != 1 || report.Baseline.Evaluation.Confusion.FalseNegative != 1 ||
		report.Holdout.Evaluation.Confusion.TrueNegative != 1 || report.Holdout.Evaluation.Confusion.TruePositive != 1 {
		t.Fatalf("baseline confusion=%+v holdout confusion=%+v", report.Baseline.Evaluation.Confusion, report.Holdout.Evaluation.Confusion)
	}
	if report.Linkage.MatchedOutcomeEvents != 4 || report.Linkage.ConfirmedDecisionLabels != 4 || report.Linkage.ConfirmedLabelCoverage.Count != 4 ||
		report.Linkage.ConfirmedLabelCoverage.Total != 5 {
		t.Fatalf("linkage = %+v", report.Linkage)
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"baseline-human", "baseline-abuse", "holdout-human", "holdout-abuse", `"decision_id":`, `"session_id":`} {
		if bytes.Contains(encoded, []byte(forbidden)) {
			t.Fatalf("private linkage leaked into report: %q", forbidden)
		}
	}
}

func TestShadowHoldoutRejectsPostHocOrInvalidContracts(t *testing.T) {
	for _, cutoff := range []string{"", "2026-08-29T12:00:00+02:00", "2026-08-29T12:00:00.123Z", "not-a-time"} {
		if _, _, err := normalizeShadowHoldoutConfig(ShadowHoldoutConfig{HoldoutStart: cutoff}); !errors.Is(err, ErrInvalidHoldout) {
			t.Fatalf("cutoff %q error = %v", cutoff, err)
		}
	}
	report := syntheticShadowHoldoutReport(t)
	report.Readiness.AutomaticEnforcement = true
	if !errors.Is(ValidateShadowHoldoutReport(report), ErrInvalidHoldout) {
		t.Fatal("automatic enforcement was accepted")
	}
	report = syntheticShadowHoldoutReport(t)
	report.Holdout.UnlabeledDecisions++
	if !errors.Is(ValidateShadowHoldoutReport(report), ErrInvalidHoldout) {
		t.Fatal("broken unknown-label accounting was accepted")
	}
}

func TestShadowHoldoutReportsDuplicateUnknownMismatchAndAmbiguousLinks(t *testing.T) {
	config, cutoff, err := normalizeShadowHoldoutConfig(ShadowHoldoutConfig{
		HoldoutStart: "2026-08-29T12:00:00Z", MinConfirmedHuman: 1, MinConfirmedAbuse: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	analyzer := &shadowHoldoutAnalyzer{config: config, cutoff: cutoff, links: make(map[[32]byte]*linkedDecision)}
	for _, id := range []string{"duplicate", "duplicate", "mismatch", "ambiguous"} {
		record := decisionRecord(id, core.ActionObserve, core.ActionAllow, "SYNTHETIC")
		record.RecordedAt = "2026-08-29T10:00:00Z"
		if err := analyzer.observe(record); err != nil {
			t.Fatal(err)
		}
	}
	for _, item := range []struct{ id, endpoint, outcome string }{
		{"unknown-decision", "account", "human_confirmed"},
		{"mismatch", "checkout", "operator_confirmed_abuse"},
		{"ambiguous", "account", "human_confirmed"},
		{"ambiguous", "account", "operator_confirmed_abuse"},
	} {
		record := linkedOutcomeRecord(item.id, item.endpoint, item.outcome)
		record.RecordedAt = "2026-08-29T13:00:00Z"
		if err := analyzer.observe(record); err != nil {
			t.Fatal(err)
		}
	}
	report := analyzer.finish(shadowlog.Verification{
		Files: 1, Records: 8, Decisions: 4, Outcomes: 4, EncryptedBytes: 4096,
		FirstAt: "2026-08-29T10:00:00Z", LastAt: "2026-08-29T13:00:00Z",
	})
	if err := ValidateShadowHoldoutReport(report); err != nil {
		t.Fatal(err)
	}
	if report.Linkage.DuplicateDecisionIDs != 1 || report.Linkage.DuplicateDecisionRecords != 1 ||
		report.Linkage.UnknownDecisionOutcomeEvents != 1 || report.Linkage.EndpointMismatchOutcomeEvents != 1 ||
		report.Linkage.AmbiguousGroundTruthDecisions != 1 || report.Baseline.Decisions != 2 ||
		report.Baseline.UnlabeledDecisions != 1 || report.Baseline.Evaluation.AmbiguousGroundTruth != 1 {
		t.Fatalf("linkage=%+v baseline=%+v", report.Linkage, report.Baseline)
	}
}

func TestEvaluateShadowHoldoutDirectoryAuthenticatesEncryptedInput(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("owner-only mode semantics require a Unix filesystem")
	}
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	logDirectory := filepath.Join(root, "shadow")
	keyFile := filepath.Join(root, "shadow.key")
	if err := os.WriteFile(keyFile, []byte(strings.Repeat("h", 32)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(keyFile, 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 29, 10, 0, 0, 0, time.UTC)
	sink, err := shadowlog.New(shadowlog.Config{Directory: logDirectory, KeyFile: keyFile, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	request := core.DecisionRequest{SessionID: "session-12345678", Action: "read", EndpointClass: "account"}
	decisionIDs := []string{"encrypted-baseline", "encrypted-holdout"}
	for index, observedAt := range []time.Time{now, now.Add(2 * time.Hour)} {
		decision := core.Decision{
			DecisionID: decisionIDs[index], Action: core.ActionObserve,
			ComputedAction: core.ActionAllow, Mode: core.RuntimeModeShadow, Scores: core.Scores{AutomationRisk: .4, AbuseIntentRisk: .3, AccountContinuity: .8},
			ReasonCodes: []string{"BASELINE"}, PolicyVersion: "default-v5", ModelVersion: "transparent-baseline-v11",
		}
		if err := sink.RecordDecision(request, decision, observedAt); err != nil {
			t.Fatal(err)
		}
	}
	for index, decisionID := range decisionIDs {
		if err := sink.RecordOutcome(shadowlog.OutcomeRequest{
			SessionID: request.SessionID, DecisionID: decisionID, EndpointClass: "account",
			Outcome: "human_confirmed", Provenance: "authenticated_account", Confidence: "confirmed",
		}, now.Add(4*time.Hour+time.Duration(index)*time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
	report, err := EvaluateShadowHoldoutDirectory(logDirectory, keyFile, ShadowHoldoutConfig{
		HoldoutStart: "2026-08-29T11:00:00Z", MinConfirmedHuman: 1, MinConfirmedAbuse: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Baseline.ConfirmedHuman != 1 || report.Holdout.ConfirmedHuman != 1 || report.Readiness.State != "insufficient_confirmed_labels" {
		t.Fatalf("report = %+v", report)
	}
}

func TestWriteShadowHoldoutReportIsOwnerOnlyCreateOnlyAndOutsideGit(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("owner-only mode semantics require a Unix filesystem")
	}
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "shadow-holdout.json")
	report := syntheticShadowHoldoutReport(t)
	if err := WriteShadowHoldoutReport(path, report); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("report mode = %v", info.Mode().Perm())
	}
	if err := WriteShadowHoldoutReport(path, report); err == nil {
		t.Fatal("existing report was overwritten")
	}
	if err := WriteShadowHoldoutReport(filepath.Join("..", "shadow-holdout.json"), report); err == nil {
		t.Fatal("Git worktree report was accepted")
	}
}

func syntheticShadowHoldoutReport(t *testing.T) ShadowHoldoutReport {
	t.Helper()
	config, cutoff, err := normalizeShadowHoldoutConfig(ShadowHoldoutConfig{
		HoldoutStart: "2026-08-29T12:00:00Z", MinConfirmedHuman: 1, MinConfirmedAbuse: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	analyzer := &shadowHoldoutAnalyzer{config: config, cutoff: cutoff, links: make(map[[32]byte]*linkedDecision)}
	decisions := []struct {
		id       string
		at       string
		computed core.Action
	}{
		{"baseline-human", "2026-08-29T10:00:00Z", core.ActionChallenge},
		{"baseline-abuse", "2026-08-29T11:00:00Z", core.ActionAllow},
		{"holdout-human", "2026-08-29T12:00:00Z", core.ActionAllow},
		{"holdout-abuse", "2026-08-29T13:00:00Z", core.ActionBlock},
		{"holdout-unlabeled", "2026-08-29T13:30:00Z", core.ActionObserve},
	}
	for _, item := range decisions {
		record := decisionRecord(item.id, core.ActionObserve, item.computed, "SYNTHETIC")
		record.RecordedAt = item.at
		if err := analyzer.observe(record); err != nil {
			t.Fatal(err)
		}
	}
	for _, item := range []struct{ id, outcome string }{
		{"baseline-human", "human_confirmed"}, {"baseline-abuse", "operator_confirmed_abuse"},
		{"holdout-human", "human_confirmed"}, {"holdout-abuse", "operator_confirmed_abuse"},
	} {
		record := linkedOutcomeRecord(item.id, "account", item.outcome)
		record.RecordedAt = "2026-08-30T00:00:00Z"
		if err := analyzer.observe(record); err != nil {
			t.Fatal(err)
		}
	}
	report := analyzer.finish(shadowlog.Verification{
		Files: 1, Records: 9, Decisions: 5, Outcomes: 4, EncryptedBytes: 4096,
		FirstAt: "2026-08-29T10:00:00Z", LastAt: "2026-08-30T00:00:00Z",
	})
	if err := ValidateShadowHoldoutReport(report); err != nil {
		t.Fatal(err)
	}
	return report
}
