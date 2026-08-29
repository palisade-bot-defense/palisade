package challenge

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/palisade-bot-defense/palisade/internal/core"
)

const (
	Family               = "timed_confirmation_v2"
	DefaultMaxEntries    = 100_000
	DefaultDelay         = 2 * time.Second
	DefaultMaxAttempts   = 5
	DefaultRedemptionTTL = time.Minute
	MaximumChallengeTTL  = 15 * time.Minute
)

var (
	ErrInvalidChallenge    = errors.New("invalid challenge")
	ErrNotFound            = errors.New("challenge not found")
	ErrSessionMismatch     = errors.New("challenge session mismatch")
	ErrNotReady            = errors.New("challenge is not ready")
	ErrInvalidVerification = errors.New("invalid challenge verification")
	ErrAttemptsExceeded    = errors.New("challenge attempts exceeded")
	ErrInvalidState        = errors.New("invalid challenge state")
	ErrExpired             = errors.New("challenge expired")
	ErrInvalidRedemption   = errors.New("invalid challenge redemption")
	ErrCapacity            = errors.New("challenge capacity exceeded")
)

type Config struct {
	Secret        []byte
	MaxEntries    int
	Delay         time.Duration
	MaxAttempts   int
	RedemptionTTL time.Duration
	Random        io.Reader
	Outcome       func(Outcome)
}

type Outcome struct {
	SessionID     string
	DecisionID    string
	EndpointClass string
	Kind          string
}

type Accessibility struct {
	NonVisual       bool `json:"non_visual"`
	KeyboardOnly    bool `json:"keyboard_only"`
	FallbackOffered bool `json:"fallback_offered"`
}

type Metadata struct {
	ChallengeID       string        `json:"challenge_id"`
	Family            string        `json:"family"`
	ReadyAt           time.Time     `json:"ready_at"`
	ExpiresAt         time.Time     `json:"expires_at"`
	AttemptsRemaining int           `json:"attempts_remaining"`
	VerificationToken string        `json:"verification_token"`
	Accessibility     Accessibility `json:"accessibility"`
}

type Verification struct {
	ChallengeID     string    `json:"challenge_id"`
	RedemptionToken string    `json:"redemption_token"`
	ExpiresAt       time.Time `json:"expires_at"`
}

type record struct {
	id               string
	sessionID        string
	decisionID       string
	action           string
	endpointClass    string
	rolloutID        string
	readyAt          time.Time
	expiresAt        time.Time
	attempts         int
	state            string
	redemptionHash   [sha256.Size]byte
	bindingHash      [sha256.Size]byte
	redemptionExpiry time.Time
}

type Service struct {
	mu            sync.Mutex
	key           []byte
	maxEntries    int
	delay         time.Duration
	maxAttempts   int
	redemptionTTL time.Duration
	random        io.Reader
	outcome       func(Outcome)
	records       map[string]*record
	byDecision    map[string]string
}

func New(config Config) (*Service, error) {
	if len(config.Secret) < 32 {
		return nil, errors.New("challenge secret must contain at least 32 bytes")
	}
	if config.MaxEntries == 0 {
		config.MaxEntries = DefaultMaxEntries
	}
	if config.Delay == 0 {
		config.Delay = DefaultDelay
	}
	if config.MaxAttempts == 0 {
		config.MaxAttempts = DefaultMaxAttempts
	}
	if config.RedemptionTTL == 0 {
		config.RedemptionTTL = DefaultRedemptionTTL
	}
	if config.Random == nil {
		config.Random = rand.Reader
	}
	if config.MaxEntries < 1 || config.MaxEntries > 1_000_000 || config.Delay < 0 || config.Delay > 30*time.Second ||
		config.MaxAttempts < 1 || config.MaxAttempts > 20 || config.RedemptionTTL < time.Second || config.RedemptionTTL > 5*time.Minute {
		return nil, errors.New("invalid challenge configuration")
	}
	derive := hmac.New(sha256.New, config.Secret)
	_, _ = derive.Write([]byte("palisade:challenge:v2:key"))
	return &Service{
		key: derive.Sum(nil), maxEntries: config.MaxEntries, delay: config.Delay, maxAttempts: config.MaxAttempts,
		redemptionTTL: config.RedemptionTTL, random: config.Random, outcome: config.Outcome,
		records: make(map[string]*record), byDecision: make(map[string]string),
	}, nil
}

func (s *Service) SetOutcomeHandler(handler func(Outcome)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.outcome = handler
}

func (s *Service) Issue(request core.DecisionRequest, decision core.Decision, redemptionBinding string, now time.Time) (Metadata, error) {
	now = now.UTC()
	if decision.Action != core.ActionChallenge || decision.Directive.Handling != "challenge" || decision.Directive.HTTPStatus != 403 ||
		(decision.Mode != core.RuntimeModeCanary && decision.Mode != core.RuntimeModeEnforce) || decision.DecisionID == "" || decision.RolloutID == "" ||
		!validBinding(request.SessionID, 8, 128) || !validBinding(request.Action, 1, 80) || !validBinding(request.EndpointClass, 1, 64) ||
		!validBinding(decision.DecisionID, 1, 128) || !validBinding(decision.RolloutID, 1, 128) || !validCapability(redemptionBinding) || !request.Observations.ServerSessionVerified || !decision.Directive.ExpiresAt.After(now) ||
		decision.Directive.ExpiresAt.After(now.Add(MaximumChallengeTTL)) {
		return Metadata{}, ErrInvalidChallenge
	}

	s.mu.Lock()
	expired := s.sweepLocked(now)
	if existingID := s.byDecision[decision.DecisionID]; existingID != "" {
		existing := s.records[existingID]
		bindingHash := sha256.Sum256([]byte(redemptionBinding))
		if existing == nil || existing.sessionID != request.SessionID || existing.action != request.Action || existing.endpointClass != request.EndpointClass || existing.rolloutID != decision.RolloutID ||
			!existing.expiresAt.Equal(decision.Directive.ExpiresAt.UTC()) || !hmac.Equal(existing.bindingHash[:], bindingHash[:]) {
			handler := s.outcome
			s.mu.Unlock()
			emit(handler, expired)
			return Metadata{}, ErrInvalidChallenge
		}
		if existing.state != "issued" {
			handler := s.outcome
			s.mu.Unlock()
			emit(handler, expired)
			return Metadata{}, ErrInvalidState
		}
		metadata := s.metadataLocked(existing)
		handler := s.outcome
		s.mu.Unlock()
		emit(handler, expired)
		return metadata, nil
	}
	if len(s.records) >= s.maxEntries {
		handler := s.outcome
		s.mu.Unlock()
		emit(handler, expired)
		return Metadata{}, ErrCapacity
	}
	var id string
	for range 3 {
		candidate, err := s.randomToken(24)
		if err != nil {
			s.mu.Unlock()
			return Metadata{}, fmt.Errorf("generate challenge id: %w", err)
		}
		if s.records[candidate] == nil {
			id = candidate
			break
		}
	}
	if id == "" {
		s.mu.Unlock()
		return Metadata{}, errors.New("generate unique challenge id")
	}
	record := &record{
		id: id, sessionID: request.SessionID, decisionID: decision.DecisionID, action: request.Action,
		endpointClass: request.EndpointClass, rolloutID: decision.RolloutID, readyAt: now.Add(s.delay),
		expiresAt: decision.Directive.ExpiresAt.UTC(), state: "issued", bindingHash: sha256.Sum256([]byte(redemptionBinding)),
	}
	if !record.readyAt.Before(record.expiresAt) {
		s.mu.Unlock()
		return Metadata{}, ErrInvalidChallenge
	}
	s.records[id] = record
	s.byDecision[decision.DecisionID] = id
	metadata := s.metadataLocked(record)
	handler := s.outcome
	s.mu.Unlock()
	emit(handler, expired)
	return metadata, nil
}

func (s *Service) View(id, sessionID string, now time.Time) (Metadata, error) {
	s.mu.Lock()
	record, outcome, err := s.lookupLocked(id, sessionID, now.UTC())
	if err != nil {
		handler := s.outcome
		s.mu.Unlock()
		emitOne(handler, outcome)
		return Metadata{}, err
	}
	if record.state != "issued" {
		s.mu.Unlock()
		return Metadata{}, ErrInvalidState
	}
	metadata := s.metadataLocked(record)
	s.mu.Unlock()
	return metadata, nil
}

func (s *Service) Verify(id, sessionID, verificationToken string, now time.Time) (Verification, error) {
	now = now.UTC()
	s.mu.Lock()
	record, outcome, err := s.lookupLocked(id, sessionID, now)
	if err != nil {
		handler := s.outcome
		s.mu.Unlock()
		emitOne(handler, outcome)
		return Verification{}, err
	}
	if record.state != "issued" {
		s.mu.Unlock()
		return Verification{}, ErrInvalidState
	}
	if now.Before(record.readyAt) {
		s.mu.Unlock()
		return Verification{}, ErrNotReady
	}
	expected := s.verificationToken(record)
	if !hmac.Equal([]byte(verificationToken), []byte(expected)) {
		record.attempts++
		if record.attempts >= s.maxAttempts {
			record.state = "failed"
			outcome := s.outcomeFor(record, "challenge_failed")
			handler := s.outcome
			s.mu.Unlock()
			emitOne(handler, &outcome)
			return Verification{}, ErrAttemptsExceeded
		}
		s.mu.Unlock()
		return Verification{}, ErrInvalidVerification
	}
	token, err := s.randomToken(32)
	if err != nil {
		s.mu.Unlock()
		return Verification{}, fmt.Errorf("generate redemption token: %w", err)
	}
	record.redemptionHash = sha256.Sum256([]byte(token))
	record.redemptionExpiry = now.Add(s.redemptionTTL)
	if record.redemptionExpiry.After(record.expiresAt) {
		record.redemptionExpiry = record.expiresAt
	}
	record.state = "verified"
	result := Verification{ChallengeID: id, RedemptionToken: token, ExpiresAt: record.redemptionExpiry}
	s.mu.Unlock()
	return result, nil
}

func (s *Service) Redeem(id, sessionID, redemptionToken, redemptionBinding, action, endpointClass string, now time.Time) error {
	now = now.UTC()
	s.mu.Lock()
	record, outcome, err := s.lookupLocked(id, sessionID, now)
	if err != nil {
		handler := s.outcome
		s.mu.Unlock()
		emitOne(handler, outcome)
		return err
	}
	if record.state != "verified" {
		s.mu.Unlock()
		return ErrInvalidState
	}
	if !record.redemptionExpiry.After(now) {
		record.state = "abandoned"
		outcome := s.outcomeFor(record, "challenge_abandoned")
		handler := s.outcome
		s.mu.Unlock()
		emitOne(handler, &outcome)
		return ErrExpired
	}
	presented := sha256.Sum256([]byte(redemptionToken))
	presentedBinding := sha256.Sum256([]byte(redemptionBinding))
	if !validCapability(redemptionBinding) || action != record.action || endpointClass != record.endpointClass ||
		!hmac.Equal(presented[:], record.redemptionHash[:]) || !hmac.Equal(presentedBinding[:], record.bindingHash[:]) {
		s.mu.Unlock()
		return ErrInvalidRedemption
	}
	record.state = "redeemed"
	completed := s.outcomeFor(record, "challenge_passed")
	handler := s.outcome
	s.mu.Unlock()
	emitOne(handler, &completed)
	return nil
}

func (s *Service) Fallback(id, sessionID string, now time.Time) error {
	s.mu.Lock()
	record, outcome, err := s.lookupLocked(id, sessionID, now.UTC())
	if err != nil {
		handler := s.outcome
		s.mu.Unlock()
		emitOne(handler, outcome)
		return err
	}
	if record.state != "issued" && record.state != "verified" {
		s.mu.Unlock()
		return ErrInvalidState
	}
	record.state = "fallback"
	completed := s.outcomeFor(record, "fallback_used")
	handler := s.outcome
	s.mu.Unlock()
	emitOne(handler, &completed)
	return nil
}

func (s *Service) RetryAfter(id, sessionID string, now time.Time) time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	record := s.records[id]
	if record == nil || record.sessionID != sessionID || !now.Before(record.readyAt) {
		return 0
	}
	return record.readyAt.Sub(now)
}

func (s *Service) Sweep(now time.Time) int {
	s.mu.Lock()
	outcomes := s.sweepLocked(now.UTC())
	handler := s.outcome
	s.mu.Unlock()
	emit(handler, outcomes)
	return len(outcomes)
}

func (s *Service) RunSweeper(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			s.Sweep(now)
		}
	}
}

func (s *Service) lookupLocked(id, sessionID string, now time.Time) (*record, *Outcome, error) {
	record := s.records[id]
	if record == nil {
		return nil, nil, ErrNotFound
	}
	if record.sessionID != sessionID {
		return nil, nil, ErrSessionMismatch
	}
	if !record.expiresAt.After(now) {
		if record.state == "issued" || record.state == "verified" {
			record.state = "abandoned"
			outcome := s.outcomeFor(record, "challenge_abandoned")
			return nil, &outcome, ErrExpired
		}
		return nil, nil, ErrExpired
	}
	return record, nil, nil
}

func (s *Service) sweepLocked(now time.Time) []Outcome {
	var outcomes []Outcome
	for id, record := range s.records {
		if record.expiresAt.After(now) {
			continue
		}
		if record.state == "issued" || record.state == "verified" {
			outcomes = append(outcomes, s.outcomeFor(record, "challenge_abandoned"))
		}
		delete(s.records, id)
		delete(s.byDecision, record.decisionID)
	}
	return outcomes
}

func (s *Service) metadataLocked(record *record) Metadata {
	return Metadata{
		ChallengeID: record.id, Family: Family, ReadyAt: record.readyAt, ExpiresAt: record.expiresAt,
		AttemptsRemaining: s.maxAttempts - record.attempts, VerificationToken: s.verificationToken(record),
		Accessibility: Accessibility{NonVisual: true, KeyboardOnly: true, FallbackOffered: true},
	}
}

func (s *Service) verificationToken(record *record) string {
	mac := hmac.New(sha256.New, s.key)
	for _, value := range []string{record.id, record.sessionID, record.decisionID, record.action, record.endpointClass, record.rolloutID,
		record.readyAt.UTC().Format(time.RFC3339Nano), record.expiresAt.UTC().Format(time.RFC3339Nano)} {
		_, _ = mac.Write([]byte{byte(len(value) >> 8), byte(len(value))})
		_, _ = mac.Write([]byte(value))
	}
	_, _ = mac.Write(record.bindingHash[:])
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (s *Service) randomToken(size int) (string, error) {
	buffer := make([]byte, size)
	if _, err := io.ReadFull(s.random, buffer); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}

func (s *Service) outcomeFor(record *record, kind string) Outcome {
	return Outcome{SessionID: record.sessionID, DecisionID: record.decisionID, EndpointClass: record.endpointClass, Kind: kind}
}

func emit(handler func(Outcome), outcomes []Outcome) {
	if handler == nil {
		return
	}
	for _, outcome := range outcomes {
		handler(outcome)
	}
}

func emitOne(handler func(Outcome), outcome *Outcome) {
	if handler != nil && outcome != nil {
		handler(*outcome)
	}
}

func validBinding(value string, minimum, maximum int) bool {
	return len(value) >= minimum && len(value) <= maximum && !strings.ContainsAny(value, "\r\n\x00")
}

func validCapability(value string) bool {
	if len(value) != 43 {
		return false
	}
	for _, character := range value {
		if !((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '_' || character == '-') {
			return false
		}
	}
	return true
}
