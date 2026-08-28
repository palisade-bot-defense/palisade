package palisadehttp

import (
	"reflect"
	"testing"
	"time"
)

func TestCoverageReporterRetriesExactSnapshotThenAdvancesCumulatively(t *testing.T) {
	reporter, err := newCoverageReporter(Config{
		CoverageReporting: true, CoverageReportEvery: 1, CoverageReportInterval: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.August, 28, 12, 0, 0, 0, time.UTC)
	first := reporter.complete("public_content", coverageEvaluated, now)
	if first == nil || first.Sequence != 1 || first.Endpoints[0].Protected != 1 || first.Endpoints[0].Evaluated != 1 {
		t.Fatalf("first report = %+v", first)
	}
	if next := reporter.finish(first, false, now); next != nil {
		t.Fatalf("failed report scheduled immediate retry: %+v", next)
	}
	if retry := reporter.complete("/raw/private", coverageRejected, now.Add(500*time.Millisecond)); retry != nil {
		t.Fatalf("retry ignored backoff: %+v", retry)
	}
	retry := reporter.complete("login", coverageBypassed, now.Add(time.Second))
	if retry == nil || retry.Sequence != first.Sequence || !reflect.DeepEqual(retry.Endpoints, first.Endpoints) {
		t.Fatalf("retry was not byte-equivalent state: first=%+v retry=%+v", first, retry)
	}
	second := reporter.finish(retry, true, now.Add(time.Second))
	if second == nil || second.Sequence != 2 || second.Endpoints[6].Bypassed != 1 || second.Endpoints[8].Rejected != 1 || coverageReportTotal(second.Endpoints) != 3 {
		t.Fatalf("second cumulative report = %+v", second)
	}
}

func TestCoverageReporterCountsBoundRetryAsCoveredWithoutFreshEvaluation(t *testing.T) {
	reporter, err := newCoverageReporter(Config{
		CoverageReporting: true, CoverageReportEvery: 1, CoverageReportInterval: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	report := reporter.complete("checkout", coverageGrantedRetry, time.Date(2026, time.August, 28, 12, 0, 0, 0, time.UTC))
	if report == nil || report.Endpoints[7].Protected != 1 || report.Endpoints[7].GrantedRetries != 1 || report.Endpoints[7].Evaluated != 0 {
		t.Fatalf("granted retry report = %+v", report)
	}
}

func TestCoverageReporterFlushesBelowThresholdAndRejectsConcurrentFlush(t *testing.T) {
	reporter, err := newCoverageReporter(Config{
		CoverageReporting: true, CoverageReportEvery: 100, CoverageReportInterval: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.August, 28, 12, 0, 0, 0, time.UTC)
	first := reporter.complete("public_content", coverageEvaluated, now)
	if first == nil {
		t.Fatal("initial report missing")
	}
	if next := reporter.finish(first, true, now); next != nil {
		t.Fatalf("unexpected automatic follow-up: %+v", next)
	}
	if automatic := reporter.complete("public_content", coverageEvaluated, now.Add(time.Second)); automatic != nil {
		t.Fatalf("below-threshold report was automatic: %+v", automatic)
	}
	flush, err := reporter.flush(now.Add(time.Second))
	if err != nil || flush == nil || flush.Sequence != 2 || flush.Endpoints[0].Protected != 2 {
		t.Fatalf("flush report/error = %+v/%v", flush, err)
	}
	if _, err := reporter.flush(now.Add(time.Second)); err != ErrCoverageBusy {
		t.Fatalf("concurrent flush error = %v", err)
	}
}

func TestCoverageReporterFlushDrainsNewerCountersAfterPendingRetry(t *testing.T) {
	reporter, err := newCoverageReporter(Config{
		CoverageReporting: true, CoverageReportEvery: 100, CoverageReportInterval: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.August, 28, 12, 0, 0, 0, time.UTC)
	first := reporter.complete("public_content", coverageEvaluated, now)
	if first == nil {
		t.Fatal("initial report missing")
	}
	reporter.finish(first, false, now)
	if retry := reporter.complete("login", coverageRejected, now.Add(time.Second)); retry != nil {
		t.Fatalf("pending report ignored retry interval: %+v", retry)
	}
	pending, err := reporter.flush(now.Add(time.Second))
	if err != nil || pending == nil || pending.Sequence != 1 || coverageReportTotal(pending.Endpoints) != 1 {
		t.Fatalf("pending flush = %+v/%v", pending, err)
	}
	if next := reporter.finish(pending, true, now.Add(time.Second)); next != nil {
		t.Fatalf("normal scheduler unexpectedly drained below threshold: %+v", next)
	}
	latest, err := reporter.flush(now.Add(time.Second))
	if err != nil || latest == nil || latest.Sequence != 2 || coverageReportTotal(latest.Endpoints) != 2 || latest.Endpoints[6].Rejected != 1 {
		t.Fatalf("latest flush = %+v/%v", latest, err)
	}
}
