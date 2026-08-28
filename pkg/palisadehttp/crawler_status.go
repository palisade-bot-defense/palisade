package palisadehttp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"sync"
	"time"
)

const crawlerStatusSchemaVersion = "palisade.crawler-registry-status.v1"

type crawlerStatusReport struct {
	SchemaVersion string                `json:"schema_version"`
	SourceID      string                `json:"source_id"`
	Sequence      uint64                `json:"sequence"`
	ReportedAt    time.Time             `json:"reported_at"`
	ValidUntil    time.Time             `json:"valid_until"`
	Status        CrawlerRegistryStatus `json:"status"`
}

type crawlerStatusReporter struct {
	mu       sync.Mutex
	sourceID string
	sequence uint64
	ttl      time.Duration
}

func newCrawlerStatusReporter(config Config) (*crawlerStatusReporter, error) {
	if !config.CrawlerRegistryReporting {
		if config.CrawlerRegistryReportTTL != 0 {
			return nil, ErrInvalidConfig
		}
		return nil, nil
	}
	if config.CrawlerRegistry == nil {
		return nil, ErrInvalidConfig
	}
	if config.CrawlerRegistryReportTTL == 0 {
		config.CrawlerRegistryReportTTL = DefaultCrawlerRegistryReportTTL
	}
	if config.CrawlerRegistryReportTTL < time.Minute || config.CrawlerRegistryReportTTL > 25*time.Hour {
		return nil, ErrInvalidConfig
	}
	var source [16]byte
	if _, err := rand.Read(source[:]); err != nil {
		return nil, ErrInvalidConfig
	}
	return &crawlerStatusReporter{sourceID: hex.EncodeToString(source[:]), ttl: config.CrawlerRegistryReportTTL}, nil
}

func (r *crawlerStatusReporter) nextReport(registry *CrawlerRegistry, now time.Time) crawlerStatusReport {
	r.sequence++
	return crawlerStatusReport{
		SchemaVersion: crawlerStatusSchemaVersion,
		SourceID:      r.sourceID,
		Sequence:      r.sequence,
		ReportedAt:    now,
		ValidUntil:    now.Add(r.ttl),
		Status:        registry.Status(now),
	}
}

// ReportCrawlerRegistryStatus sends one authenticated, closed operational
// snapshot. It contains no registry entries, addresses, user-agent values,
// vendor labels or local paths. Call it after initial load and watcher polls;
// it is never invoked from the request hot path automatically.
func (m *Middleware) ReportCrawlerRegistryStatus(ctx context.Context) error {
	if m == nil || m.crawlerStatus == nil || m.crawlers == nil || ctx == nil {
		return ErrInvalidConfig
	}
	now := m.now().UTC().Truncate(time.Second)
	m.crawlerStatus.mu.Lock()
	defer m.crawlerStatus.mu.Unlock()
	report := m.crawlerStatus.nextReport(m.crawlers, now)
	status, err := m.postJSON(ctx, "/v1/crawler-registry-status", report, nil, true, nil)
	if err != nil {
		return err
	}
	if status != http.StatusAccepted {
		return apiStatusError{status: status, op: "crawler registry status"}
	}
	return nil
}
