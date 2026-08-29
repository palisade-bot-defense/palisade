// Package decoy implements a bounded, server-owned decoy capability lifecycle.
// It stores no URL, request content, network identifier or user-agent value.
package decoy

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/palisade-bot-defense/palisade/internal/core"
)

const (
	DefaultTTL        = 5 * time.Minute
	MaximumTTL        = 15 * time.Minute
	MinimumTTL        = 30 * time.Second
	PendingTTL        = 5 * time.Minute
	DefaultMaxEntries = 100_000
	MaximumHits       = 100
)

var (
	ErrInvalidRequest    = errors.New("invalid decoy request")
	ErrInvalidCapability = errors.New("invalid decoy capability")
	ErrExpired           = errors.New("decoy capability expired")
	ErrCapacity          = errors.New("decoy capacity exceeded")
)

type Surface string

const (
	SurfaceLink Surface = "link"
	SurfaceForm Surface = "form"
	SurfaceAPI  Surface = "api"
)

type Interaction string

const (
	InteractionTouched   Interaction = "touched"
	InteractionSubmitted Interaction = "submitted"
)

type Config struct {
	MaxEntries int
	Random     io.Reader
}

type IssueRequest struct {
	SessionID     string
	EndpointClass string
	Surface       Surface
	TTL           time.Duration
}

type Capability struct {
	Capability string    `json:"capability"`
	ExpiresAt  time.Time `json:"expires_at"`
}

type binding struct {
	sessionHash   [sha256.Size]byte
	endpointClass string
}

type issued struct {
	binding   binding
	surface   Surface
	expiresAt time.Time
}

type pending struct {
	hits      int
	expiresAt time.Time
}

type Service struct {
	mu         sync.Mutex
	maxEntries int
	random     io.Reader
	issued     map[[sha256.Size]byte]issued
	pending    map[binding]pending
}

func NewDefault() *Service {
	return &Service{
		maxEntries: DefaultMaxEntries,
		random:     rand.Reader,
		issued:     make(map[[sha256.Size]byte]issued),
		pending:    make(map[binding]pending),
	}
}

func New(config Config) (*Service, error) {
	if config.MaxEntries == 0 {
		config.MaxEntries = DefaultMaxEntries
	}
	if config.Random == nil {
		config.Random = rand.Reader
	}
	if config.MaxEntries < 1 || config.MaxEntries > 1_000_000 {
		return nil, ErrInvalidRequest
	}
	return &Service{
		maxEntries: config.MaxEntries,
		random:     config.Random,
		issued:     make(map[[sha256.Size]byte]issued),
		pending:    make(map[binding]pending),
	}, nil
}

func (s *Service) Issue(request IssueRequest, now time.Time) (Capability, error) {
	if request.TTL == 0 {
		request.TTL = DefaultTTL
	}
	if !validSession(request.SessionID) || !core.ValidEndpointClass(request.EndpointClass) ||
		!validSurface(request.Surface) || request.TTL < MinimumTTL || request.TTL > MaximumTTL {
		return Capability{}, ErrInvalidRequest
	}
	now = now.UTC()
	s.mu.Lock()
	s.sweepLocked(now)
	if len(s.issued)+len(s.pending) >= s.maxEntries {
		s.mu.Unlock()
		return Capability{}, ErrCapacity
	}
	var raw string
	var digest [sha256.Size]byte
	for range 3 {
		buffer := make([]byte, 32)
		if _, err := io.ReadFull(s.random, buffer); err != nil {
			s.mu.Unlock()
			return Capability{}, err
		}
		raw = base64.RawURLEncoding.EncodeToString(buffer)
		digest = sha256.Sum256([]byte(raw))
		if _, exists := s.issued[digest]; !exists {
			break
		}
		raw = ""
	}
	if raw == "" {
		s.mu.Unlock()
		return Capability{}, ErrCapacity
	}
	expiresAt := now.Add(request.TTL)
	s.issued[digest] = issued{
		binding: binding{sessionHash: sessionDigest(request.SessionID), endpointClass: request.EndpointClass},
		surface: request.Surface, expiresAt: expiresAt,
	}
	s.mu.Unlock()
	return Capability{Capability: raw, ExpiresAt: expiresAt}, nil
}

// Hit atomically consumes a capability and records one short-lived normalized
// hit for its original session and endpoint binding. Replays never add evidence.
func (s *Service) Hit(capability string, interaction Interaction, now time.Time) error {
	if len(capability) != 43 || !validInteraction(interaction) {
		return ErrInvalidRequest
	}
	digest := sha256.Sum256([]byte(capability))
	now = now.UTC()
	s.mu.Lock()
	entry, exists := s.issued[digest]
	if !exists {
		s.mu.Unlock()
		return ErrInvalidCapability
	}
	if !entry.expiresAt.After(now) {
		delete(s.issued, digest)
		s.mu.Unlock()
		return ErrExpired
	}
	if interaction == InteractionSubmitted && entry.surface != SurfaceForm {
		s.mu.Unlock()
		return ErrInvalidRequest
	}
	delete(s.issued, digest)
	s.sweepLocked(now)
	current := s.pending[entry.binding]
	if current.hits < MaximumHits {
		current.hits++
	}
	current.expiresAt = now.Add(PendingTTL)
	s.pending[entry.binding] = current
	s.mu.Unlock()
	return nil
}

// TakeHits returns and deletes verified pending evidence. It is intentionally
// at-most-once so a hit cannot poison every later decision in a session.
func (s *Service) TakeHits(sessionID, endpointClass string, now time.Time) int {
	if !validSession(sessionID) || !core.ValidEndpointClass(endpointClass) {
		return 0
	}
	key := binding{sessionHash: sessionDigest(sessionID), endpointClass: endpointClass}
	s.mu.Lock()
	current, exists := s.pending[key]
	if exists {
		delete(s.pending, key)
	}
	s.mu.Unlock()
	if !exists || !current.expiresAt.After(now.UTC()) {
		return 0
	}
	return current.hits
}

func (s *Service) Sweep(now time.Time) {
	s.mu.Lock()
	s.sweepLocked(now.UTC())
	s.mu.Unlock()
}

func (s *Service) sweepLocked(now time.Time) {
	for digest, entry := range s.issued {
		if !entry.expiresAt.After(now) {
			delete(s.issued, digest)
		}
	}
	for key, entry := range s.pending {
		if !entry.expiresAt.After(now) {
			delete(s.pending, key)
		}
	}
}

func sessionDigest(sessionID string) [sha256.Size]byte {
	return sha256.Sum256([]byte("palisade:decoy:v1:session\x00" + sessionID))
}

func validSession(value string) bool {
	return len(value) >= 8 && len(value) <= 128 && !strings.ContainsAny(value, "\r\n\x00")
}

func validSurface(value Surface) bool {
	return value == SurfaceLink || value == SurfaceForm || value == SurfaceAPI
}

func validInteraction(value Interaction) bool {
	return value == InteractionTouched || value == InteractionSubmitted
}
