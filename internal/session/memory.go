package session

import (
	"sync"
	"time"

	"github.com/palisade-bot-defense/palisade/internal/core"
)

type MemoryStore struct {
	mu         sync.Mutex
	entries    map[string]core.SessionSnapshot
	ttl        time.Duration
	maxEntries int
	ops        uint64
}

func NewMemoryStore(ttl time.Duration, maxEntries int) *MemoryStore {
	return &MemoryStore{
		entries:    make(map[string]core.SessionSnapshot),
		ttl:        ttl,
		maxEntries: maxEntries,
	}
}

func (m *MemoryStore) Observe(sessionID string, sequence uint64, now time.Time) core.SessionSnapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ops++
	if m.ops%256 == 0 || len(m.entries) >= m.maxEntries {
		m.cleanup(now)
	}
	snapshot, exists := m.entries[sessionID]
	if !exists || now.Sub(snapshot.LastSeen) > m.ttl {
		snapshot = core.SessionSnapshot{SessionID: sessionID, FirstSeen: now}
	}
	snapshot.RequestCount++
	if snapshot.LastSequence > 0 && sequence > snapshot.LastSequence+1 {
		gap := sequence - snapshot.LastSequence - 1
		if gap > snapshot.MaxSequenceGap {
			snapshot.MaxSequenceGap = gap
		}
	}
	if sequence > snapshot.LastSequence {
		snapshot.LastSequence = sequence
	}
	snapshot.LastSeen = now
	m.entries[sessionID] = snapshot
	return snapshot
}

func (m *MemoryStore) cleanup(now time.Time) {
	for id, snapshot := range m.entries {
		if now.Sub(snapshot.LastSeen) > m.ttl {
			delete(m.entries, id)
		}
	}
}
