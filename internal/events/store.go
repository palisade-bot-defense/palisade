package events

import (
	"errors"
	"math"
	"sync"
	"time"
)

const (
	MaxBatchSize = 64
	MaxSessions  = 100_000
)

var ErrInvalidBatch = errors.New("invalid event batch")

type BrowserEvent struct {
	Sequence        uint64 `json:"sequence"`
	ElapsedBucketMS uint64 `json:"elapsedBucketMs"`
	Kind            string `json:"kind"`
	ValueBucket     int    `json:"valueBucket"`
}

type Batch struct {
	SessionID     string         `json:"sessionId"`
	SensorVersion string         `json:"sensorVersion"`
	Events        []BrowserEvent `json:"events"`
}

type entry struct {
	count         int
	acceptedBatch uint64
	lastSeen      time.Time
	lastSeq       uint64
}

// IngestReceipt contains only server-owned bounded aggregates. BatchSequence
// is a contiguous sequence of accepted HTTP batches and must be used when an
// accepted browser-event flush triggers a shadow decision. Browser event
// sequence numbers describe events inside the batch and are not request
// sequence numbers.
type IngestReceipt struct {
	AcceptedEvents      int
	TotalAcceptedEvents int
	BatchSequence       uint64
}

type Store struct {
	mu       sync.Mutex
	ttl      time.Duration
	sessions map[string]entry
}

func NewStore(ttl time.Duration) *Store {
	return &Store{ttl: ttl, sessions: make(map[string]entry)}
}

func (s *Store) Ingest(batch Batch, now time.Time) error {
	_, err := s.IngestWithReceipt(batch, now)
	return err
}

// IngestWithReceipt validates and deduplicates a batch, then advances a
// server-owned batch sequence atomically with the event counters.
func (s *Store) IngestWithReceipt(batch Batch, now time.Time) (IngestReceipt, error) {
	if len(batch.SessionID) < 8 || len(batch.SessionID) > 128 || len(batch.SensorVersion) > 32 || len(batch.Events) == 0 || len(batch.Events) > MaxBatchSize {
		return IngestReceipt{}, ErrInvalidBatch
	}
	previous := uint64(0)
	for _, event := range batch.Events {
		if event.Sequence == 0 || event.Sequence <= previous || !validKind(event.Kind) || event.ElapsedBucketMS > 86_400_000 || event.ValueBucket < 0 || event.ValueBucket > 65_536 {
			return IngestReceipt{}, ErrInvalidBatch
		}
		previous = event.Sequence
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.prune(now)
	current := s.sessions[batch.SessionID]
	if current.acceptedBatch == math.MaxUint64 {
		return IngestReceipt{}, ErrInvalidBatch
	}
	accepted := 0
	for _, event := range batch.Events {
		if event.Sequence > current.lastSeq {
			accepted++
			current.lastSeq = event.Sequence
		}
	}
	current.count += accepted
	current.acceptedBatch++
	current.lastSeen = now
	s.sessions[batch.SessionID] = current
	return IngestReceipt{
		AcceptedEvents:      accepted,
		TotalAcceptedEvents: current.count,
		BatchSequence:       current.acceptedBatch,
	}, nil
}

func (s *Store) Count(sessionID string, now time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.sessions[sessionID]
	if !ok || now.Sub(current.lastSeen) > s.ttl {
		delete(s.sessions, sessionID)
		return 0
	}
	return current.count
}

func (s *Store) prune(now time.Time) {
	for sessionID, current := range s.sessions {
		if now.Sub(current.lastSeen) > s.ttl {
			delete(s.sessions, sessionID)
		}
	}
	if len(s.sessions) < MaxSessions {
		return
	}
	var oldestID string
	var oldestTime time.Time
	for sessionID, current := range s.sessions {
		if oldestID == "" || current.lastSeen.Before(oldestTime) {
			oldestID, oldestTime = sessionID, current.lastSeen
		}
	}
	delete(s.sessions, oldestID)
}

func validKind(kind string) bool {
	switch kind {
	case "pointer", "scroll", "visibility", "navigation", "performance":
		return true
	default:
		return false
	}
}
