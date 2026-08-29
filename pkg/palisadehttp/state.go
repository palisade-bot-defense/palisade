package palisadehttp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
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

type grantEntry struct {
	action        string
	endpointClass string
	sessionDigest [sha256.Size]byte
	requestDigest [sha256.Size]byte
	expires       time.Time
}

type pendingEntry struct {
	action           string
	endpointClass    string
	challengeID      string
	sessionDigest    [sha256.Size]byte
	requestDigest    [sha256.Size]byte
	challengeBinding [sha256.Size]byte
	expires          time.Time
	reserved         bool
}

type boundedState struct {
	mu          sync.Mutex
	sequences   map[[sha256.Size]byte]sequenceEntry
	grants      map[[sha256.Size]byte]grantEntry
	pendings    map[[sha256.Size]byte]pendingEntry
	maxSessions int
	maxGrants   int
	stateTTL    time.Duration
	grantTTL    time.Duration
	pendingTTL  time.Duration
	ops         uint64
	random      io.Reader
	digestKey   [sha256.Size]byte
}

func newBoundedState(maxSessions, maxGrants int, stateTTL, grantTTL, pendingTTL time.Duration) (*boundedState, error) {
	state := &boundedState{
		sequences: make(map[[sha256.Size]byte]sequenceEntry), grants: make(map[[sha256.Size]byte]grantEntry), pendings: make(map[[sha256.Size]byte]pendingEntry),
		maxSessions: maxSessions, maxGrants: maxGrants, stateTTL: stateTTL, grantTTL: grantTTL, pendingTTL: pendingTTL, random: rand.Reader,
	}
	if _, err := io.ReadFull(rand.Reader, state.digestKey[:]); err != nil {
		return nil, err
	}
	return state, nil
}

func (s *boundedState) nextSequence(cookieValue string, now time.Time) (uint64, error) {
	key := sha256.Sum256([]byte(cookieValue))
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupLocked(now)
	entry, exists := s.sequences[key]
	if !exists {
		if len(s.sequences) >= s.maxSessions {
			return 0, ErrStateCapacity
		}
		entry.sequence = 1
	} else {
		if entry.sequence == ^uint64(0) {
			return 0, ErrStateCapacity
		}
		entry.sequence++
	}
	entry.expires = now.Add(s.stateTTL)
	s.sequences[key] = entry
	return entry.sequence, nil
}

func (s *boundedState) issuePending(request *http.Request, classification Classification, challengeID, sessionValue string, challengeBinding [sha256.Size]byte, now time.Time) (http.Cookie, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupLocked(now)
	if len(s.pendings) >= s.maxGrants {
		return http.Cookie{}, ErrStateCapacity
	}
	value, key, err := s.uniquePendingTokenLocked()
	if err != nil {
		return http.Cookie{}, err
	}
	expires := now.Add(s.pendingTTL)
	s.pendings[key] = pendingEntry{
		action: classification.Action, endpointClass: classification.EndpointClass, challengeID: challengeID,
		sessionDigest: sha256.Sum256([]byte(sessionValue)), requestDigest: s.requestDigest(request), challengeBinding: challengeBinding, expires: expires,
	}
	return http.Cookie{
		Name: PendingCookieName, Value: value, Path: "/", Expires: expires, MaxAge: int(s.pendingTTL.Seconds()),
		Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode,
	}, nil
}

func (s *boundedState) reserveGrant(pendingValue, challengeID, sessionValue, action, endpointClass string, now time.Time) (http.Cookie, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupLocked(now)
	pendingKey := sha256.Sum256([]byte(pendingValue))
	pending, exists := s.pendings[pendingKey]
	sessionDigest := sha256.Sum256([]byte(sessionValue))
	if !exists || !pending.expires.After(now) || pending.reserved || pending.challengeID != challengeID ||
		!hmac.Equal(pending.sessionDigest[:], sessionDigest[:]) || pending.action != action || pending.endpointClass != endpointClass {
		return http.Cookie{}, "", ErrInvalidPending
	}
	if len(s.grants) >= s.maxGrants {
		return http.Cookie{}, "", ErrStateCapacity
	}
	value, grantKey, err := s.uniqueGrantTokenLocked()
	if err != nil {
		return http.Cookie{}, "", err
	}
	expires := now.Add(s.grantTTL)
	s.grants[grantKey] = grantEntry{
		action: action, endpointClass: endpointClass, sessionDigest: pending.sessionDigest,
		requestDigest: pending.requestDigest, expires: expires,
	}
	pending.reserved = true
	s.pendings[pendingKey] = pending
	return http.Cookie{
		Name: RedemptionCookieName, Value: value, Path: "/", Expires: expires, MaxAge: int(s.grantTTL.Seconds()),
		Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode,
	}, base64.RawURLEncoding.EncodeToString(pending.challengeBinding[:]), nil
}

func (s *boundedState) challengeBinding(request *http.Request, classification Classification, sessionValue string, sequence uint64) [sha256.Size]byte {
	// This capability crosses only the adapter-to-PALISADE boundary. The browser
	// receives a random pending-map key, never this target- and sequence-bound MAC.
	requestDigest := s.requestDigest(request)
	mac := hmac.New(sha256.New, s.digestKey[:])
	_, _ = mac.Write([]byte("palisade:origin-challenge-binding:v1\x00"))
	_, _ = mac.Write([]byte(sessionValue))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write(requestDigest[:])
	_, _ = mac.Write([]byte(classification.Action))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(classification.EndpointClass))
	var encodedSequence [8]byte
	binary.BigEndian.PutUint64(encodedSequence[:], sequence)
	_, _ = mac.Write(encodedSequence[:])
	var result [sha256.Size]byte
	copy(result[:], mac.Sum(nil))
	return result
}

func (s *boundedState) consumeGrant(request *http.Request, classification Classification, now time.Time) bool {
	cookie, err := request.Cookie(RedemptionCookieName)
	if err != nil || cookie.Value == "" {
		return false
	}
	key := sha256.Sum256([]byte(cookie.Value))
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, exists := s.grants[key]
	if !exists {
		return false
	}
	if !entry.expires.After(now) {
		delete(s.grants, key)
		return false
	}
	digest := s.requestDigest(request)
	session, sessionErr := request.Cookie(SessionCookieName)
	var sessionDigest [sha256.Size]byte
	if sessionErr == nil {
		sessionDigest = sha256.Sum256([]byte(session.Value))
	}
	if sessionErr != nil || entry.action != classification.Action || entry.endpointClass != classification.EndpointClass ||
		!hmac.Equal(entry.sessionDigest[:], sessionDigest[:]) || !hmac.Equal(entry.requestDigest[:], digest[:]) {
		return false
	}
	delete(s.grants, key)
	return true
}

func (s *boundedState) releaseGrant(grantValue, pendingValue string) {
	if grantValue == "" || pendingValue == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.grants, sha256.Sum256([]byte(grantValue)))
	pendingKey := sha256.Sum256([]byte(pendingValue))
	pending, exists := s.pendings[pendingKey]
	if exists {
		pending.reserved = false
		s.pendings[pendingKey] = pending
	}
}

func (s *boundedState) commitPending(value string) {
	if value == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.pendings, sha256.Sum256([]byte(value)))
}

func (s *boundedState) closePending(value, challengeID, sessionValue string, now time.Time) bool {
	if value == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := sha256.Sum256([]byte(value))
	pending, exists := s.pendings[key]
	sessionDigest := sha256.Sum256([]byte(sessionValue))
	if !exists || !pending.expires.After(now) || pending.reserved || pending.challengeID != challengeID ||
		!hmac.Equal(pending.sessionDigest[:], sessionDigest[:]) {
		return false
	}
	delete(s.pendings, key)
	return true
}

func (s *boundedState) revokePending(value string) {
	s.commitPending(value)
}

func (s *boundedState) cleanupLocked(now time.Time) {
	s.ops++
	if s.ops%256 != 0 && len(s.sequences) < s.maxSessions && len(s.grants) < s.maxGrants && len(s.pendings) < s.maxGrants {
		return
	}
	for key, entry := range s.sequences {
		if !entry.expires.After(now) {
			delete(s.sequences, key)
		}
	}
	for key, entry := range s.grants {
		if !entry.expires.After(now) {
			delete(s.grants, key)
		}
	}
	for key, entry := range s.pendings {
		if !entry.expires.After(now) {
			delete(s.pendings, key)
		}
	}
}

func (s *boundedState) requestDigest(request *http.Request) [sha256.Size]byte {
	mac := hmac.New(sha256.New, s.digestKey[:])
	_, _ = mac.Write([]byte(request.Method))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(request.URL.EscapedPath()))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(request.URL.RawQuery))
	var result [sha256.Size]byte
	copy(result[:], mac.Sum(nil))
	return result
}

func (s *boundedState) uniqueGrantTokenLocked() (string, [sha256.Size]byte, error) {
	for range 3 {
		value, key, err := s.randomTokenLocked()
		if err != nil {
			return "", [sha256.Size]byte{}, err
		}
		if _, exists := s.grants[key]; !exists {
			return value, key, nil
		}
	}
	return "", [sha256.Size]byte{}, ErrStateCapacity
}

func (s *boundedState) uniquePendingTokenLocked() (string, [sha256.Size]byte, error) {
	for range 3 {
		value, key, err := s.randomTokenLocked()
		if err != nil {
			return "", [sha256.Size]byte{}, err
		}
		if _, exists := s.pendings[key]; !exists {
			return value, key, nil
		}
	}
	return "", [sha256.Size]byte{}, ErrStateCapacity
}

func (s *boundedState) randomTokenLocked() (string, [sha256.Size]byte, error) {
	buffer := make([]byte, 32)
	if _, err := io.ReadFull(s.random, buffer); err != nil {
		return "", [sha256.Size]byte{}, err
	}
	value := base64.RawURLEncoding.EncodeToString(buffer)
	return value, sha256.Sum256([]byte(value)), nil
}

func clearRedemptionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: RedemptionCookieName, Value: "", Path: "/", MaxAge: -1, Expires: time.Unix(1, 0).UTC(),
		Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode,
	})
}

func clearPendingCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: PendingCookieName, Value: "", Path: "/", MaxAge: -1, Expires: time.Unix(1, 0).UTC(),
		Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode,
	})
}
