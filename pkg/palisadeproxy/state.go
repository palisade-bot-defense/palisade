package palisadeproxy

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"net/http"
	"sync"
	"time"
)

type sequenceEntry struct {
	sequence uint64
	expires  time.Time
}

type sequenceState struct {
	mu          sync.Mutex
	entries     map[[sha256.Size]byte]sequenceEntry
	maxSessions int
	ttl         time.Duration
	digestKey   [sha256.Size]byte
	ops         uint64
}

func newSequenceState(maxSessions int, ttl time.Duration) (*sequenceState, error) {
	state := &sequenceState{entries: make(map[[sha256.Size]byte]sequenceEntry), maxSessions: maxSessions, ttl: ttl}
	if _, err := io.ReadFull(rand.Reader, state.digestKey[:]); err != nil {
		return nil, err
	}
	return state, nil
}

func (s *sequenceState) next(cookieValue string, now time.Time) (uint64, error) {
	key := sha256.Sum256([]byte(cookieValue))
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ops++
	if s.ops%128 == 0 || len(s.entries) >= s.maxSessions {
		for digest, entry := range s.entries {
			if !entry.expires.After(now) {
				delete(s.entries, digest)
			}
		}
	}
	entry, exists := s.entries[key]
	if !exists {
		if len(s.entries) >= s.maxSessions {
			return 0, ErrStateCapacity
		}
		entry.sequence = 1
	} else {
		if entry.sequence == ^uint64(0) {
			return 0, ErrStateCapacity
		}
		entry.sequence++
	}
	entry.expires = now.Add(s.ttl)
	s.entries[key] = entry
	return entry.sequence, nil
}

func (s *sequenceState) challengeBinding(request *http.Request, classification Classification, session string, sequence uint64) [sha256.Size]byte {
	requestMAC := hmac.New(sha256.New, s.digestKey[:])
	_, _ = requestMAC.Write([]byte("palisade:proxy-request:v1\x00"))
	_, _ = requestMAC.Write([]byte(request.Method))
	_, _ = requestMAC.Write([]byte{0})
	_, _ = requestMAC.Write([]byte(request.URL.EscapedPath()))
	_, _ = requestMAC.Write([]byte{0})
	_, _ = requestMAC.Write([]byte(request.URL.RawQuery))
	requestDigest := requestMAC.Sum(nil)

	mac := hmac.New(sha256.New, s.digestKey[:])
	_, _ = mac.Write([]byte("palisade:origin-challenge-binding:v1\x00"))
	_, _ = mac.Write([]byte(session))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write(requestDigest)
	_, _ = mac.Write([]byte(classification.Action))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(classification.EndpointClass))
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], sequence)
	_, _ = mac.Write(encoded[:])
	var result [sha256.Size]byte
	copy(result[:], mac.Sum(nil))
	return result
}
