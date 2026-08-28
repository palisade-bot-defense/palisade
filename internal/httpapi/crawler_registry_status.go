package httpapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"sync"
	"time"
)

const (
	crawlerRegistryStatusSchemaVersion = "palisade.crawler-registry-status.v1"
	maxCrawlerRegistryStatusSources    = 1024
)

var (
	errInvalidCrawlerRegistryStatus  = errors.New("invalid crawler registry status report")
	errCrawlerRegistryStatusConflict = errors.New("conflicting crawler registry status report")
	errCrawlerRegistryStatusCapacity = errors.New("crawler registry status source capacity exceeded")
)

type crawlerRegistryStatusReport struct {
	SchemaVersion string                `json:"schema_version"`
	SourceID      string                `json:"source_id"`
	Sequence      uint64                `json:"sequence"`
	ReportedAt    time.Time             `json:"reported_at"`
	ValidUntil    time.Time             `json:"valid_until"`
	Status        crawlerRegistryStatus `json:"status"`
}

type crawlerRegistryStatus struct {
	State         string    `json:"state"`
	Revision      uint64    `json:"revision"`
	IssuedAt      time.Time `json:"issued_at,omitempty"`
	ExpiresAt     time.Time `json:"expires_at,omitempty"`
	DigestSHA256  string    `json:"digest_sha256,omitempty"`
	IdentityCount int       `json:"identity_count"`
	PrefixCount   int       `json:"prefix_count"`
}

func (s *crawlerRegistryStatus) UnmarshalJSON(encoded []byte) error {
	type wireStatus struct {
		State         *string    `json:"state"`
		Revision      *uint64    `json:"revision"`
		IssuedAt      *time.Time `json:"issued_at"`
		ExpiresAt     *time.Time `json:"expires_at"`
		DigestSHA256  *string    `json:"digest_sha256"`
		IdentityCount *int       `json:"identity_count"`
		PrefixCount   *int       `json:"prefix_count"`
	}
	var wire wireStatus
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil {
		return errInvalidCrawlerRegistryStatus
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errInvalidCrawlerRegistryStatus
	}
	if wire.State == nil || wire.Revision == nil || wire.IssuedAt == nil || wire.ExpiresAt == nil ||
		wire.DigestSHA256 == nil || wire.IdentityCount == nil || wire.PrefixCount == nil {
		return errInvalidCrawlerRegistryStatus
	}
	*s = crawlerRegistryStatus{
		State: *wire.State, Revision: *wire.Revision, IssuedAt: *wire.IssuedAt, ExpiresAt: *wire.ExpiresAt,
		DigestSHA256: *wire.DigestSHA256, IdentityCount: *wire.IdentityCount, PrefixCount: *wire.PrefixCount,
	}
	return nil
}

type crawlerRegistryStatusStore struct {
	mu      sync.Mutex
	sources map[string]crawlerRegistryStatusReport
}

type AdminCrawlerRegistryStatus struct {
	State             string     `json:"state"`
	Scope             string     `json:"scope"`
	Sources           uint64     `json:"sources"`
	CurrentSources    uint64     `json:"current_sources"`
	ExpiredSources    uint64     `json:"expired_sources"`
	EmptySources      uint64     `json:"empty_sources"`
	StaticSources     uint64     `json:"static_sources"`
	MinimumRevision   uint64     `json:"minimum_revision"`
	MaximumRevision   uint64     `json:"maximum_revision"`
	DistinctDigests   uint64     `json:"distinct_digests"`
	EarliestExpiresAt *time.Time `json:"earliest_expires_at"`
	LastReportedAt    *time.Time `json:"last_reported_at"`
}

func newCrawlerRegistryStatusStore() *crawlerRegistryStatusStore {
	return &crawlerRegistryStatusStore{sources: make(map[string]crawlerRegistryStatusReport)}
}

func (s *crawlerRegistryStatusStore) observe(report crawlerRegistryStatusReport, now time.Time) error {
	now = now.UTC()
	if !validCrawlerRegistryStatusReport(report, now) {
		return errInvalidCrawlerRegistryStatus
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneExpiredLocked(now)
	previous, exists := s.sources[report.SourceID]
	if exists {
		if report.Sequence < previous.Sequence || report.ReportedAt.Before(previous.ReportedAt) {
			return errCrawlerRegistryStatusConflict
		}
		if report.Sequence == previous.Sequence {
			if reflect.DeepEqual(report, previous) {
				return nil
			}
			return errCrawlerRegistryStatusConflict
		}
	} else if len(s.sources) >= maxCrawlerRegistryStatusSources {
		return errCrawlerRegistryStatusCapacity
	}
	s.sources[report.SourceID] = report
	return nil
}

func (s *crawlerRegistryStatusStore) snapshot(now time.Time) AdminCrawlerRegistryStatus {
	now = now.UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneExpiredLocked(now)
	result := AdminCrawlerRegistryStatus{State: "unavailable", Scope: "authenticated_origin_registry_reports", Sources: uint64(len(s.sources))}
	digests := make(map[string]struct{})
	for _, report := range s.sources {
		state := report.Status.State
		if state == "current" && !now.Before(report.Status.ExpiresAt) {
			state = "expired"
		}
		switch state {
		case "current":
			result.CurrentSources++
		case "expired":
			result.ExpiredSources++
		case "empty":
			result.EmptySources++
		case "static":
			result.StaticSources++
		}
		if report.Status.Revision > 0 {
			if result.MinimumRevision == 0 || report.Status.Revision < result.MinimumRevision {
				result.MinimumRevision = report.Status.Revision
			}
			if report.Status.Revision > result.MaximumRevision {
				result.MaximumRevision = report.Status.Revision
			}
		}
		if report.Status.DigestSHA256 != "" {
			digests[report.Status.DigestSHA256] = struct{}{}
		}
		if !report.Status.ExpiresAt.IsZero() && (result.EarliestExpiresAt == nil || report.Status.ExpiresAt.Before(*result.EarliestExpiresAt)) {
			value := report.Status.ExpiresAt
			result.EarliestExpiresAt = &value
		}
		if result.LastReportedAt == nil || report.ReportedAt.After(*result.LastReportedAt) {
			value := report.ReportedAt
			result.LastReportedAt = &value
		}
	}
	result.DistinctDigests = uint64(len(digests))
	if result.Sources > 0 {
		result.State = "attention"
	}
	if result.Sources > 0 && result.CurrentSources == result.Sources && result.DistinctDigests == 1 && result.MinimumRevision == result.MaximumRevision {
		result.State = "current"
	}
	return result
}

func (s *crawlerRegistryStatusStore) pruneExpiredLocked(now time.Time) {
	for sourceID, report := range s.sources {
		if !now.Before(report.ValidUntil) {
			delete(s.sources, sourceID)
		}
	}
}

func validCrawlerRegistryStatusReport(report crawlerRegistryStatusReport, now time.Time) bool {
	if report.SchemaVersion != crawlerRegistryStatusSchemaVersion || !validCoverageSourceID(report.SourceID) || report.Sequence == 0 ||
		report.ReportedAt.IsZero() || report.ValidUntil.IsZero() || report.ReportedAt.Location() != time.UTC || report.ValidUntil.Location() != time.UTC ||
		report.ReportedAt.Nanosecond() != 0 || report.ValidUntil.Nanosecond() != 0 || report.ReportedAt.After(now.Add(time.Minute)) ||
		!report.ValidUntil.After(now) || report.ValidUntil.Sub(report.ReportedAt) < time.Minute || report.ValidUntil.Sub(report.ReportedAt) > 25*time.Hour {
		return false
	}
	status := report.Status
	switch status.State {
	case "empty":
		return status.Revision == 0 && status.IssuedAt.IsZero() && status.ExpiresAt.IsZero() && status.DigestSHA256 == "" && status.IdentityCount == 0 && status.PrefixCount == 0
	case "static":
		return status.Revision == 0 && status.IssuedAt.IsZero() && status.ExpiresAt.IsZero() && status.DigestSHA256 == "" && validCrawlerRegistryCounts(status)
	case "current", "expired":
		if status.Revision == 0 || status.IssuedAt.IsZero() || status.ExpiresAt.IsZero() ||
			status.IssuedAt.Location() != time.UTC || status.ExpiresAt.Location() != time.UTC ||
			status.IssuedAt.Nanosecond() != 0 || status.ExpiresAt.Nanosecond() != 0 || !status.ExpiresAt.After(status.IssuedAt) ||
			status.IssuedAt.After(report.ReportedAt.Add(5*time.Minute)) || status.ExpiresAt.Sub(status.IssuedAt) > 31*24*time.Hour ||
			!validLowerHex(status.DigestSHA256, 64) || !validCrawlerRegistryCounts(status) {
			return false
		}
		return status.State == "current" && status.ExpiresAt.After(report.ReportedAt) || status.State == "expired" && !status.ExpiresAt.After(report.ReportedAt)
	default:
		return false
	}
}

func validCrawlerRegistryCounts(status crawlerRegistryStatus) bool {
	return status.IdentityCount >= 1 && status.IdentityCount <= 128 && status.PrefixCount >= 1 && status.PrefixCount <= 4096
}

func validLowerHex(value string, length int) bool {
	if len(value) != length {
		return false
	}
	for _, character := range value {
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return false
		}
	}
	return true
}
