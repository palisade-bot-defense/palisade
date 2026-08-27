package session

import (
	"math"
	"math/bits"
	"sync"
	"time"

	"github.com/palisade-bot-defense/palisade/internal/core"
)

type MemoryStore struct {
	mu         sync.Mutex
	entries    map[string]entry
	ttl        time.Duration
	maxEntries int
	ops        uint64
}

type entry struct {
	snapshot     core.SessionSnapshot
	endpointMask uint16
	lastEndpoint string
}

func NewMemoryStore(ttl time.Duration, maxEntries int) *MemoryStore {
	return &MemoryStore{
		entries:    make(map[string]entry),
		ttl:        ttl,
		maxEntries: maxEntries,
	}
}

func (m *MemoryStore) Observe(sessionID string, sequence uint64, endpointClass string, now time.Time) core.SessionSnapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ops++
	if m.ops%256 == 0 || len(m.entries) >= m.maxEntries {
		m.cleanup(now)
	}
	current, exists := m.entries[sessionID]
	if exists && now.Sub(current.snapshot.LastSeen) > m.ttl {
		delete(m.entries, sessionID)
		exists = false
	}
	if !exists {
		if len(m.entries) >= m.maxEntries {
			m.evictOldest()
		}
		current = entry{snapshot: core.SessionSnapshot{SessionID: sessionID, FirstSeen: now}}
	}
	snapshot := &current.snapshot
	snapshot.RequestCount = saturatingIncrement(snapshot.RequestCount)
	if snapshot.LastSequence > 0 && sequence > snapshot.LastSequence {
		gap := sequence - snapshot.LastSequence - 1
		if gap > snapshot.MaxSequenceGap {
			snapshot.MaxSequenceGap = gap
		}
	}
	if sequence > snapshot.LastSequence {
		if endpointBit := endpointClassBit(endpointClass); endpointBit != 0 {
			current.endpointMask |= endpointBit
			snapshot.DistinctEndpointClasses = uint8(bits.OnesCount16(current.endpointMask))
			if current.lastEndpoint != "" && current.lastEndpoint != endpointClass {
				snapshot.EndpointTransitions = saturatingIncrement(snapshot.EndpointTransitions)
			}
			current.lastEndpoint = endpointClass
		}
		snapshot.LastSequence = sequence
	}
	snapshot.LastSeen = now
	m.entries[sessionID] = current
	return *snapshot
}

func (m *MemoryStore) cleanup(now time.Time) {
	for id, current := range m.entries {
		if now.Sub(current.snapshot.LastSeen) > m.ttl {
			delete(m.entries, id)
		}
	}
}

func (m *MemoryStore) evictOldest() {
	var oldestID string
	var oldest time.Time
	for id, current := range m.entries {
		seen := current.snapshot.LastSeen
		if oldestID == "" || seen.Before(oldest) || (seen.Equal(oldest) && id < oldestID) {
			oldestID, oldest = id, seen
		}
	}
	if oldestID != "" {
		delete(m.entries, oldestID)
	}
}

func endpointClassBit(value string) uint16 {
	switch value {
	case "public_content":
		return 1 << 0
	case "compare_index":
		return 1 << 1
	case "compare_noindex":
		return 1 << 2
	case "challenge_worker":
		return 1 << 3
	case "other_public":
		return 1 << 4
	case "account":
		return 1 << 5
	case "login":
		return 1 << 6
	case "checkout":
		return 1 << 7
	case "other":
		return 1 << 8
	default:
		return 0
	}
}

func saturatingIncrement(value uint64) uint64 {
	if value == math.MaxUint64 {
		return value
	}
	return value + 1
}
