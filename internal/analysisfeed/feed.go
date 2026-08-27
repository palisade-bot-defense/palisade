package analysisfeed

import (
	"context"
	"crypto/sha256"
	"errors"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/palisade-bot-defense/palisade/internal/rollout"
	"github.com/palisade-bot-defense/palisade/internal/shadowanalysis"
)

const (
	StateReady         = "ready"
	StateInvalidUpdate = "invalid_update"
)

type Snapshot struct {
	Report        *shadowanalysis.Report
	State         string
	LoadedAt      time.Time
	LastAttemptAt time.Time
}

type storedSnapshot struct {
	Snapshot
	digest [sha256.Size]byte
}

// Feed reloads one owner-only aggregate report without ever opening the raw
// encrypted log or its key. Invalid replacements leave the last valid report
// available and mark the feed unhealthy for the operator.
type Feed struct {
	path     string
	interval time.Duration
	logger   *slog.Logger
	now      func() time.Time
	state    atomic.Pointer[storedSnapshot]
}

func New(path string, interval time.Duration, logger *slog.Logger) (*Feed, error) {
	if path == "" || interval < time.Second || interval > time.Hour {
		return nil, errors.New("analysis report feed configuration is invalid")
	}
	if logger == nil {
		logger = slog.Default()
	}
	feed := &Feed{path: path, interval: interval, logger: logger, now: func() time.Time { return time.Now().UTC() }}
	if err := feed.reload(); err != nil {
		return nil, err
	}
	return feed, nil
}

func (f *Feed) Snapshot() Snapshot {
	current := f.state.Load()
	if current == nil {
		return Snapshot{}
	}
	return current.Snapshot
}

func (f *Feed) Run(ctx context.Context) {
	ticker := time.NewTicker(f.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := f.reload(); err != nil {
				f.logger.Warn("analysis report reload rejected", "status", StateInvalidUpdate)
			}
		}
	}
}

func (f *Feed) reload() error {
	attemptedAt := f.now()
	encoded, report, err := rollout.ReadAnalysisReport(f.path)
	if err == nil {
		err = shadowanalysis.ValidateReport(report)
	}
	if err != nil {
		if previous := f.state.Load(); previous != nil {
			next := *previous
			next.State = StateInvalidUpdate
			next.LastAttemptAt = attemptedAt
			f.state.Store(&next)
		}
		return errors.New("analysis report update failed validation")
	}
	digest := sha256.Sum256(encoded)
	loadedAt := attemptedAt
	if previous := f.state.Load(); previous != nil && previous.digest == digest {
		loadedAt = previous.LoadedAt
	}
	reportCopy := report
	f.state.Store(&storedSnapshot{Snapshot: Snapshot{
		Report: &reportCopy, State: StateReady, LoadedAt: loadedAt, LastAttemptAt: attemptedAt,
	}, digest: digest})
	return nil
}
