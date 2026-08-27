package analysisfeed

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/palisade-bot-defense/palisade/internal/rollout"
	"github.com/palisade-bot-defense/palisade/internal/shadowanalysis"
	"github.com/palisade-bot-defense/palisade/internal/shadowlog"
)

func TestFeedKeepsLastValidReportAfterInvalidReplacement(t *testing.T) {
	directory := privateTempDir(t)
	path := filepath.Join(directory, "analysis.json")
	first := validReport(1)
	if err := rollout.ReplaceAnalysisReport(path, first); err != nil {
		t.Fatal(err)
	}
	feed, err := New(path, time.Second, nil)
	if err != nil {
		t.Fatal(err)
	}
	initial := feed.Snapshot()
	if initial.State != StateReady || initial.Report == nil || initial.Report.Decisions.Total != 1 {
		t.Fatalf("initial snapshot = %+v", initial)
	}
	if err := os.WriteFile(path, []byte(`{"schema_version":"invalid"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := feed.reload(); err == nil {
		t.Fatal("invalid replacement was accepted")
	}
	stale := feed.Snapshot()
	if stale.State != StateInvalidUpdate || stale.Report == nil || stale.Report.Decisions.Total != 1 {
		t.Fatalf("last valid snapshot was not retained: %+v", stale)
	}
	if err := rollout.ReplaceAnalysisReport(path, validReport(2)); err != nil {
		t.Fatal(err)
	}
	if err := feed.reload(); err != nil {
		t.Fatal(err)
	}
	recovered := feed.Snapshot()
	if recovered.State != StateReady || recovered.Report == nil || recovered.Report.Decisions.Total != 2 {
		t.Fatalf("feed did not recover after a valid publication: %+v", recovered)
	}
}

func TestFeedRunStopsWithContext(t *testing.T) {
	directory := privateTempDir(t)
	path := filepath.Join(directory, "analysis.json")
	if err := rollout.ReplaceAnalysisReport(path, validReport(0)); err != nil {
		t.Fatal(err)
	}
	feed, err := New(path, time.Second, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); feed.Run(ctx) }()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("feed did not stop")
	}
}

func privateTempDir(t *testing.T) string {
	t.Helper()
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	return directory
}

func validReport(decisions uint64) shadowanalysis.Report {
	report := shadowanalysis.Report{
		SchemaVersion: shadowanalysis.SchemaVersion,
		Source:        shadowlog.Verification{Files: 1, Records: decisions, Decisions: decisions},
		Decisions: shadowanalysis.DecisionSummary{
			Total: decisions, Enforced: shadowanalysis.ActionCounts{Allow: decisions}, Computed: shadowanalysis.ActionCounts{Allow: decisions},
			Modes: shadowanalysis.ModeCounts{Shadow: decisions},
		},
	}
	if decisions > 0 {
		report.Scores = shadowanalysis.ScoreSummaries{}
		report.Endpoints = []shadowanalysis.EndpointSummary{{EndpointClass: "public_content", Decisions: decisions}}
		report.PolicyVersions = []shadowanalysis.CountedValue{{Value: "default-v3", Count: decisions}}
		report.ModelVersions = []shadowanalysis.CountedValue{{Value: "transparent-baseline-v6", Count: decisions}}
	}
	report.Readiness = shadowanalysis.Readiness{
		State: "collecting", OperatorAction: "remain_shadow", AutomaticEnforcement: false,
		ReasonCodes: []string{"COLLECT_MORE_DECISIONS", "IMPROVE_OUTCOME_COVERAGE", "EXPAND_CONFIRMED_HUMANS", "EXPAND_CONFIRMED_ABUSE"},
	}
	report.Recommendations = []shadowanalysis.Recommendation{
		{Code: "COLLECT_MORE_DECISIONS", Priority: "high", Disposition: "required", Metric: "decisions", Observed: float64(decisions), Threshold: 1000, Unit: "count", Message: "Collect a larger local shadow sample across a complete traffic cycle."},
		{Code: "IMPROVE_OUTCOME_COVERAGE", Priority: "high", Disposition: "required", Metric: "outcome_coverage", Observed: 0, Threshold: 0.1, Unit: "ratio", Message: "Increase normalized delayed-outcome coverage before estimating operational harm."},
		{Code: "EXPAND_CONFIRMED_HUMANS", Priority: "high", Disposition: "required", Metric: "human_confirmed", Observed: 0, Threshold: 100, Unit: "count", Message: "Add authenticated or operator-reviewed human outcomes; challenge completion is not a human label."},
		{Code: "EXPAND_CONFIRMED_ABUSE", Priority: "medium", Disposition: "required", Metric: "operator_confirmed_abuse", Observed: 0, Threshold: 100, Unit: "count", Message: "Add operator-confirmed abuse outcomes to measure precision without treating automation as abuse."},
		{Code: "KEEP_SHADOW_MODE", Priority: "high", Disposition: "hold", Metric: "automatic_enforcement", Observed: 0, Threshold: 0, Unit: "boolean", Message: "Keep enforcement disabled until the listed evidence and safety gaps are resolved and reviewed by an operator."},
	}
	return report
}
