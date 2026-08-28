package palisadehttp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"sync"
	"time"
)

const (
	coverageSchemaVersion = "palisade.origin-coverage.v1"
	maxCoverageCounter    = uint64(1_000_000_000_000_000)
)

type coverageDisposition uint8

const (
	coverageEvaluated coverageDisposition = iota + 1
	coverageBypassed
	coverageRejected
	coverageGrantedRetry
)

type coverageCounter struct {
	EndpointClass  string `json:"endpoint_class"`
	Protected      uint64 `json:"protected_requests"`
	Evaluated      uint64 `json:"evaluated_requests"`
	Bypassed       uint64 `json:"bypassed_requests"`
	Rejected       uint64 `json:"rejected_requests"`
	GrantedRetries uint64 `json:"granted_retries"`
}

type coverageReport struct {
	SchemaVersion string            `json:"schema_version"`
	SourceID      string            `json:"source_id"`
	SourceStarted time.Time         `json:"source_started_at"`
	Sequence      uint64            `json:"sequence"`
	CompletedAt   time.Time         `json:"completed_at"`
	Endpoints     []coverageCounter `json:"endpoints"`
}

type coverageReporter struct {
	mu             sync.Mutex
	sourceID       string
	startedAt      time.Time
	sequence       uint64
	counters       [9]coverageCounter
	reportEvery    uint64
	reportInterval time.Duration
	completed      uint64
	reported       uint64
	lastAttempt    time.Time
	pending        *coverageReport
	inflight       bool
}

var coverageEndpointClasses = [...]string{"public_content", "compare_index", "compare_noindex", "challenge_worker", "other_public", "account", "login", "checkout", "other"}

func newCoverageReporter(config Config) (*coverageReporter, error) {
	if !config.CoverageReporting {
		if config.CoverageReportEvery != 0 || config.CoverageReportInterval != 0 {
			return nil, ErrInvalidConfig
		}
		return nil, nil
	}
	if config.CoverageReportEvery == 0 {
		config.CoverageReportEvery = DefaultCoverageEvery
	}
	if config.CoverageReportInterval == 0 {
		config.CoverageReportInterval = DefaultCoverageInterval
	}
	if config.CoverageReportEvery < 1 || config.CoverageReportEvery > 100_000 ||
		config.CoverageReportInterval < time.Second || config.CoverageReportInterval > 5*time.Minute {
		return nil, ErrInvalidConfig
	}
	var source [16]byte
	if _, err := rand.Read(source[:]); err != nil {
		return nil, ErrInvalidConfig
	}
	reporter := &coverageReporter{
		sourceID: hex.EncodeToString(source[:]), reportEvery: config.CoverageReportEvery,
		reportInterval: config.CoverageReportInterval,
	}
	for index, endpoint := range coverageEndpointClasses {
		reporter.counters[index].EndpointClass = endpoint
	}
	return reporter, nil
}

func (m *Middleware) recordOriginCoverage(endpoint string, disposition coverageDisposition) {
	if m.coverage == nil {
		return
	}
	report := m.coverage.complete(endpoint, disposition, m.now().UTC())
	if report != nil {
		go m.sendOriginCoverage(report)
	}
}

func (m *Middleware) sendOriginCoverage(report *coverageReport) {
	for report != nil {
		timeout := m.client.Timeout
		if timeout <= 0 || timeout > 10*time.Second {
			timeout = 3 * time.Second
		}
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		status, err := m.postJSON(ctx, "/v1/origin-coverage", report, nil, true, nil)
		cancel()
		success := err == nil && status == http.StatusAccepted
		if !success {
			m.logger.Warn("PALISADE coverage report unavailable")
		}
		report = m.coverage.finish(report, success, m.now().UTC())
	}
}

// FlushCoverage synchronously sends the latest completed-request snapshot.
// Call it from a bounded graceful-shutdown context. Normal request handling is
// never coupled to this method, and concurrent automatic delivery fails with
// ErrCoverageBusy instead of sending a conflicting sequence.
func (m *Middleware) FlushCoverage(ctx context.Context) error {
	if ctx == nil {
		return ErrInvalidConfig
	}
	if m.coverage == nil {
		return nil
	}
	report, err := m.coverage.flush(m.now().UTC())
	if err != nil {
		return err
	}
	for report != nil {
		status, postErr := m.postJSON(ctx, "/v1/origin-coverage", report, nil, true, nil)
		if postErr != nil || status != http.StatusAccepted {
			m.coverage.finish(report, false, m.now().UTC())
			if postErr != nil {
				return postErr
			}
			return apiStatusError{status: status, op: "coverage reporting"}
		}
		report = m.coverage.finish(report, true, m.now().UTC())
		if report == nil {
			// A successful retry may have acknowledged an older exact snapshot
			// while newer completions accumulated below the normal threshold.
			// Flush must drain that latest cumulative state as well.
			report, err = m.coverage.flush(m.now().UTC())
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (r *coverageReporter) complete(endpoint string, disposition coverageDisposition, now time.Time) *coverageReport {
	r.mu.Lock()
	defer r.mu.Unlock()
	index := coverageEndpointIndex(endpoint)
	if index < 0 {
		index = coverageEndpointIndex("other")
	}
	counter := &r.counters[index]
	if counter.Protected < maxCoverageCounter {
		counter.Protected++
		switch disposition {
		case coverageEvaluated:
			counter.Evaluated++
		case coverageBypassed:
			counter.Bypassed++
		case coverageGrantedRetry:
			counter.GrantedRetries++
		default:
			counter.Rejected++
		}
		r.completed++
	}
	if r.startedAt.IsZero() {
		r.startedAt = now.UTC().Truncate(time.Second)
	}
	return r.scheduleLocked(now)
}

func (r *coverageReporter) finish(report *coverageReport, success bool, now time.Time) *coverageReport {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.pending == nil || r.pending.Sequence != report.Sequence {
		return nil
	}
	r.inflight = false
	if !success {
		return nil
	}
	r.reported = coverageReportTotal(report.Endpoints)
	r.pending = nil
	return r.scheduleLocked(now)
}

func (r *coverageReporter) flush(now time.Time) (*coverageReport, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.inflight {
		return nil, ErrCoverageBusy
	}
	if r.pending != nil {
		r.inflight = true
		r.lastAttempt = now
		return cloneCoverageReport(r.pending), nil
	}
	if r.completed == r.reported {
		return nil, nil
	}
	return r.buildLocked(now), nil
}

func (r *coverageReporter) scheduleLocked(now time.Time) *coverageReport {
	if r.inflight {
		return nil
	}
	if r.pending != nil {
		if now.Sub(r.lastAttempt) < r.reportInterval {
			return nil
		}
		r.inflight = true
		r.lastAttempt = now
		return cloneCoverageReport(r.pending)
	}
	dueCount := r.completed-r.reported >= r.reportEvery
	dueTime := r.lastAttempt.IsZero() || (r.completed > r.reported && now.Sub(r.lastAttempt) >= r.reportInterval)
	if !dueCount && !dueTime {
		return nil
	}
	return r.buildLocked(now)
}

func (r *coverageReporter) buildLocked(now time.Time) *coverageReport {
	r.sequence++
	report := &coverageReport{
		SchemaVersion: coverageSchemaVersion, SourceID: r.sourceID, SourceStarted: r.startedAt,
		Sequence: r.sequence, CompletedAt: now.UTC().Truncate(time.Second), Endpoints: make([]coverageCounter, len(r.counters)),
	}
	copy(report.Endpoints, r.counters[:])
	r.pending = report
	r.inflight = true
	r.lastAttempt = now
	return cloneCoverageReport(report)
}

func coverageEndpointIndex(endpoint string) int {
	for index, candidate := range coverageEndpointClasses {
		if endpoint == candidate {
			return index
		}
	}
	return -1
}

func coverageReportTotal(counters []coverageCounter) uint64 {
	var total uint64
	for _, counter := range counters {
		total += counter.Protected
	}
	return total
}

func cloneCoverageReport(report *coverageReport) *coverageReport {
	if report == nil {
		return nil
	}
	copy := *report
	copy.Endpoints = append([]coverageCounter(nil), report.Endpoints...)
	return &copy
}
