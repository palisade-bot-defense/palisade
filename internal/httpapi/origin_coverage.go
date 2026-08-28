package httpapi

import (
	"errors"
	"reflect"
	"sync"
	"time"
)

const (
	originCoverageSchemaVersion = "palisade.origin-coverage.v1"
	maxOriginCoverageSources    = 1024
	maxOriginCoverageCounter    = uint64(1_000_000_000_000_000)
)

var (
	errInvalidOriginCoverage  = errors.New("invalid origin coverage report")
	errOriginCoverageConflict = errors.New("conflicting origin coverage report")
	errOriginCoverageCapacity = errors.New("origin coverage source capacity exceeded")
)

type originCoverageReport struct {
	SchemaVersion string                  `json:"schema_version"`
	SourceID      string                  `json:"source_id"`
	SourceStarted time.Time               `json:"source_started_at"`
	Sequence      uint64                  `json:"sequence"`
	CompletedAt   time.Time               `json:"completed_at"`
	Endpoints     []originCoverageCounter `json:"endpoints"`
}

type originCoverageCounter struct {
	EndpointClass  string `json:"endpoint_class"`
	Protected      uint64 `json:"protected_requests"`
	Evaluated      uint64 `json:"evaluated_requests"`
	Bypassed       uint64 `json:"bypassed_requests"`
	Rejected       uint64 `json:"rejected_requests"`
	GrantedRetries uint64 `json:"granted_retries"`
}

type originCoverageSource struct {
	latest   originCoverageReport
	baseline []originCoverageCounter
}

type originCoverageStore struct {
	mu        sync.Mutex
	startedAt time.Time
	sources   map[string]originCoverageSource
}

type originCoverageSnapshot struct {
	Sources        uint64
	ObservedSince  *time.Time
	LastReportedAt *time.Time
	Endpoints      []originCoverageCounter
}

func newOriginCoverageStore(now time.Time) *originCoverageStore {
	return &originCoverageStore{
		// Keep sub-second server start precision. Reports deliberately use whole
		// seconds, so a source in the same second is conservatively baselined
		// instead of accidentally importing pre-restart counters.
		startedAt: now.UTC(),
		sources:   make(map[string]originCoverageSource),
	}
}

func (s *originCoverageStore) observe(report originCoverageReport, now time.Time) error {
	now = now.UTC()
	if !validOriginCoverageReport(report, now) {
		return errInvalidOriginCoverage
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	previous, exists := s.sources[report.SourceID]
	if exists {
		if report.SourceStarted != previous.latest.SourceStarted || report.Sequence < previous.latest.Sequence || report.CompletedAt.Before(previous.latest.CompletedAt) {
			return errOriginCoverageConflict
		}
		if report.Sequence == previous.latest.Sequence {
			if reflect.DeepEqual(report, previous.latest) {
				return nil
			}
			return errOriginCoverageConflict
		}
		if !coverageCountersNondecreasing(previous.latest.Endpoints, report.Endpoints) {
			return errOriginCoverageConflict
		}
		previous.latest = cloneOriginCoverageReport(report)
		s.sources[report.SourceID] = previous
		return nil
	}
	if len(s.sources) >= maxOriginCoverageSources {
		return errOriginCoverageCapacity
	}
	baseline := zeroOriginCoverageCounters()
	if report.SourceStarted.Before(s.startedAt) {
		baseline = cloneOriginCoverageCounters(report.Endpoints)
	}
	s.sources[report.SourceID] = originCoverageSource{latest: cloneOriginCoverageReport(report), baseline: baseline}
	return nil
}

func (s *originCoverageStore) snapshot() originCoverageSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := originCoverageSnapshot{Sources: uint64(len(s.sources)), Endpoints: zeroOriginCoverageCounters()}
	for _, source := range s.sources {
		observedSince := source.latest.SourceStarted
		if observedSince.Before(s.startedAt) {
			observedSince = s.startedAt
		}
		if result.ObservedSince == nil || observedSince.Before(*result.ObservedSince) {
			copy := observedSince
			result.ObservedSince = &copy
		}
		if result.LastReportedAt == nil || source.latest.CompletedAt.After(*result.LastReportedAt) {
			copy := source.latest.CompletedAt
			result.LastReportedAt = &copy
		}
		for index := range result.Endpoints {
			addCoverageDelta(&result.Endpoints[index], source.latest.Endpoints[index], source.baseline[index])
		}
	}
	return result
}

func validOriginCoverageReport(report originCoverageReport, now time.Time) bool {
	if report.SchemaVersion != originCoverageSchemaVersion || !validCoverageSourceID(report.SourceID) || report.Sequence == 0 ||
		report.SourceStarted.IsZero() || report.CompletedAt.IsZero() || report.SourceStarted.Nanosecond() != 0 || report.CompletedAt.Nanosecond() != 0 ||
		report.SourceStarted.Location() != time.UTC || report.CompletedAt.Location() != time.UTC || report.CompletedAt.Before(report.SourceStarted) ||
		report.CompletedAt.After(now.Add(time.Minute)) || len(report.Endpoints) != len(adminEndpointClasses) {
		return false
	}
	for index, counter := range report.Endpoints {
		if counter.EndpointClass != adminEndpointClasses[index] || !validOriginCoverageCounter(counter) {
			return false
		}
	}
	return true
}

func validCoverageSourceID(value string) bool {
	if len(value) != 32 {
		return false
	}
	for _, character := range value {
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return false
		}
	}
	return true
}

func validOriginCoverageCounter(counter originCoverageCounter) bool {
	values := [...]uint64{counter.Protected, counter.Evaluated, counter.Bypassed, counter.Rejected, counter.GrantedRetries}
	for _, value := range values {
		if value > maxOriginCoverageCounter {
			return false
		}
	}
	return counter.Evaluated+counter.Bypassed+counter.Rejected+counter.GrantedRetries == counter.Protected
}

func coverageCountersNondecreasing(previous, next []originCoverageCounter) bool {
	if len(previous) != len(next) {
		return false
	}
	for index := range previous {
		if previous[index].EndpointClass != next[index].EndpointClass || previous[index].Protected > next[index].Protected ||
			previous[index].Evaluated > next[index].Evaluated || previous[index].Bypassed > next[index].Bypassed ||
			previous[index].Rejected > next[index].Rejected || previous[index].GrantedRetries > next[index].GrantedRetries {
			return false
		}
	}
	return true
}

func zeroOriginCoverageCounters() []originCoverageCounter {
	result := make([]originCoverageCounter, len(adminEndpointClasses))
	for index, endpoint := range adminEndpointClasses {
		result[index].EndpointClass = endpoint
	}
	return result
}

func cloneOriginCoverageCounters(values []originCoverageCounter) []originCoverageCounter {
	return append([]originCoverageCounter(nil), values...)
}

func cloneOriginCoverageReport(report originCoverageReport) originCoverageReport {
	report.Endpoints = cloneOriginCoverageCounters(report.Endpoints)
	return report
}

func addCoverageDelta(target *originCoverageCounter, latest, baseline originCoverageCounter) {
	target.Protected += latest.Protected - baseline.Protected
	target.Evaluated += latest.Evaluated - baseline.Evaluated
	target.Bypassed += latest.Bypassed - baseline.Bypassed
	target.Rejected += latest.Rejected - baseline.Rejected
	target.GrantedRetries += latest.GrantedRetries - baseline.GrantedRetries
}
