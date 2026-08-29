package localsequence

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

	"github.com/palisade-bot-defense/palisade/internal/offlineimport"
)

func TestAnalyzerSeparatesEvidenceLanesAndEmitsOnlyAggregates(t *testing.T) {
	config, err := normalizeConfig(Config{})
	if err != nil {
		t.Fatal(err)
	}
	a := newAnalyzer(config)
	base := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	events := []offlineimport.LocalEvent{
		localEvent(base, "subject-secret", "session-secret", "public_content"),
		localEvent(base.Add(10*time.Second), "subject-secret", "session-secret", "account"),
		localEvent(base.Add(20*time.Second), "subject-secret", "session-secret", "decoy"),
		localEvent(base.Add(30*time.Second), "subject-secret", "session-secret", "authentication"),
	}
	events[1].Evidence.CollectionStatus = "partial"
	events[1].Evidence.AutomationEvidence = "high"
	events[1].Label = offlineimport.LocalLabel{Class: "human_confirmed", Provenance: "authenticated_account", Confidence: "confirmed"}
	events[2].Evidence.AbuseIntentEvidence = "medium"
	events[2].Evidence.DecoyInteraction = "touched"
	events[2].Evidence.ChallengeLifecycle = "issued"
	events[2].Label = offlineimport.LocalLabel{Class: "operator_confirmed_abuse", Provenance: "operator_review", Confidence: "confirmed"}
	events[3].Evidence.ContinuityEvidence = "high"
	events[3].Evidence.ChallengeLifecycle = "passed"
	for _, event := range events {
		if err := a.observe(event); err != nil {
			t.Fatal(err)
		}
	}
	if err := a.finish(); err != nil {
		t.Fatal(err)
	}
	a.report.Source.Shards = 1
	a.report.Source.Events = uint64(len(events))
	a.report.Source.Bytes = 400
	a.report.Source.FirstAt = events[0].ObservedAt
	a.report.Source.LastAt = events[len(events)-1].ObservedAt
	if err := ValidateReport(a.report); err != nil {
		t.Fatal(err)
	}
	if a.report.Windows.Total != 1 || a.report.BurstShapes.Sparse != 1 || a.report.PeakMinuteEvents.TwoToFive != 1 {
		t.Fatalf("unexpected window classification: %+v %+v", a.report.Windows, a.report.BurstShapes)
	}
	if got := a.report.EndpointTransitions; got.Total != 3 || got.CrossClass != 3 || got.SensitiveEscalation != 2 || got.DecoyEntry != 1 {
		t.Fatalf("transitions = %+v", got)
	}
	if a.report.Collection.WindowsWithArtifact != 1 || a.report.Evidence.Automation.High != 1 || a.report.Evidence.AbuseIntent.Medium != 1 || a.report.Evidence.Continuity.High != 1 {
		t.Fatalf("evidence lanes collapsed or misclassified: %+v %+v", a.report.Collection, a.report.Evidence)
	}
	if a.report.Decoys.Touched != 1 || a.report.Challenges.Passed != 1 || a.report.Labels.Ambiguous != 1 {
		t.Fatalf("decoy, challenge or label aggregation is wrong: %+v %+v %+v", a.report.Decoys, a.report.Challenges, a.report.Labels)
	}
	encoded, err := json.Marshal(a.report)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"subject-secret", "session-secret", "subject_id", "session_id", "observed_at"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("row-level data leaked into aggregate report: %q", forbidden)
		}
	}
}

func TestAnalyzerUsesBoundedWindowsAndOneHeapEntryPerActiveKey(t *testing.T) {
	config, _ := normalizeConfig(Config{MaxActiveSequences: 2})
	a := newAnalyzer(config)
	base := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	for minute := 0; minute <= 12; minute += 4 {
		if err := a.observe(localEvent(base.Add(time.Duration(minute)*time.Minute), "subject-a", "session-a", "api")); err != nil {
			t.Fatal(err)
		}
		if len(a.expirations) != 1 {
			t.Fatalf("heap entries = %d, want one per active key", len(a.expirations))
		}
	}
	if err := a.observe(localEvent(base.Add(15*time.Minute), "subject-a", "session-a", "api")); err != nil {
		t.Fatal(err)
	}
	if err := a.finish(); err != nil {
		t.Fatal(err)
	}
	if a.report.Windows.MaxDuration != 1 || a.report.Windows.EndOfInput != 1 || a.report.Windows.Total != 2 {
		t.Fatalf("window closure = %+v", a.report.Windows)
	}
}

func TestAnalyzerExpiresBeforeApplyingActiveWindowBudget(t *testing.T) {
	config, _ := normalizeConfig(Config{MaxActiveSequences: 1})
	a := newAnalyzer(config)
	base := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	if err := a.observe(localEvent(base, "subject-a", "", "other")); err != nil {
		t.Fatal(err)
	}
	if err := a.observe(localEvent(base.Add(time.Second), "subject-b", "", "other")); !errors.Is(err, ErrActiveSequenceBudget) {
		t.Fatalf("error = %v, want active-window budget", err)
	}
	if err := a.observe(localEvent(base.Add(InactivityWindow), "subject-b", "", "other")); err != nil {
		t.Fatalf("expired sequence still consumed budget: %v", err)
	}
}

func TestAnalyzerOutputIsDeterministic(t *testing.T) {
	build := func() []byte {
		config, _ := normalizeConfig(Config{})
		a := newAnalyzer(config)
		event := localEvent(time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC), "subject-a", "session-a", "public_content")
		if err := a.observe(event); err != nil {
			t.Fatal(err)
		}
		if err := a.finish(); err != nil {
			t.Fatal(err)
		}
		a.report.Source.Events = 1
		a.report.Source.FirstAt = event.ObservedAt
		a.report.Source.LastAt = event.ObservedAt
		encoded, err := json.Marshal(a.report)
		if err != nil {
			t.Fatal(err)
		}
		return encoded
	}
	if string(build()) != string(build()) {
		t.Fatal("aggregate report is not deterministic")
	}
}

func TestAnalyzeDirectoryEndToEnd(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("owner-only mode semantics require a Unix filesystem")
	}
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	inputPath := filepath.Join(root, "authorized-input.txt")
	keyPath := filepath.Join(root, "key.bin")
	outputDir := filepath.Join(root, "normalized")
	row := offlineimport.LocalInputEvent{
		SchemaVersion: offlineimport.LocalInputSchemaVersion,
		ObservedAt:    "2026-08-29T12:00:00Z",
		SubjectRef:    "synthetic-subject",
		SessionRef:    "synthetic-session",
		Source:        "access_gateway",
		EndpointClass: "public_content",
		ActionClass:   "read",
		StatusClass:   "success",
		Evidence: offlineimport.LocalEvidence{
			CollectionStatus: "complete", AutomationEvidence: "low", AbuseIntentEvidence: "none",
			ContinuityEvidence: "medium", DecoyInteraction: "none", ChallengeLifecycle: "none",
		},
		Label: offlineimport.LocalLabel{Class: "unknown", Provenance: "none", Confidence: "unknown"},
	}
	first, err := json.Marshal(row)
	if err != nil {
		t.Fatal(err)
	}
	row.ObservedAt = "2026-08-29T12:00:01Z"
	row.EndpointClass = "api"
	second, err := json.Marshal(row)
	if err != nil {
		t.Fatal(err)
	}
	content := append(append(append([]byte{}, first...), '\n'), second...)
	content = append(content, '\n')
	if err := os.WriteFile(inputPath, content, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, bytes.Repeat([]byte{0x44}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := offlineimport.RunLocal(offlineimport.LocalConfig{
		InputFile: inputPath, OutputDir: outputDir, PseudonymKeyFile: keyPath,
		DatasetID: "synthetic-dataset", PilotID: "synthetic-pilot",
	}); err != nil {
		t.Fatal(err)
	}
	report, err := AnalyzeDirectory(outputDir, Config{})
	if err != nil {
		t.Fatal(err)
	}
	if report.Source.Events != 2 || report.Source.Shards != 1 || report.Source.Sequences != 1 || report.EndpointTransitions.CrossClass != 1 {
		t.Fatalf("report = %+v", report)
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte(row.SubjectRef)) || bytes.Contains(encoded, []byte(row.SessionRef)) || bytes.Contains(encoded, []byte("subject_id")) {
		t.Fatal("direct or pseudonymous linkage leaked into end-to-end report")
	}
}

func TestValidateReportRejectsBrokenTotalsAndConfig(t *testing.T) {
	config, _ := normalizeConfig(Config{})
	a := newAnalyzer(config)
	if err := ValidateReport(a.report); err != nil {
		t.Fatalf("empty report should be valid: %v", err)
	}
	a.report.Windows.Total = 1
	if err := ValidateReport(a.report); err == nil {
		t.Fatal("inconsistent report totals were accepted")
	}
	if _, err := normalizeConfig(Config{MaxActiveSequences: MaximumMaxActiveSequences + 1}); err == nil {
		t.Fatal("oversized active-window budget was accepted")
	}
}

func localEvent(at time.Time, subject, session, endpoint string) offlineimport.LocalEvent {
	return offlineimport.LocalEvent{
		SchemaVersion: offlineimport.LocalEventSchemaVersion,
		Provenance:    offlineimport.ProvenanceOperatorExport,
		ObservedAt:    at.Format(time.RFC3339Nano),
		SubjectID:     subject,
		SessionID:     session,
		Source:        "access_gateway",
		EndpointClass: endpoint,
		ActionClass:   "read",
		StatusClass:   "success",
		Evidence: offlineimport.LocalEvidence{
			CollectionStatus: "complete", AutomationEvidence: "none", AbuseIntentEvidence: "none",
			ContinuityEvidence: "none", DecoyInteraction: "none", ChallengeLifecycle: "none",
		},
		Label: offlineimport.LocalLabel{Class: "unknown", Provenance: "none", Confidence: "unknown"},
	}
}
