// Package liveness implements an interactive, multi-round challenge that
// evidences real-time human presence.
//
// What it establishes, precisely: the client stayed attached across several
// rounds, each round's prompt was revealed only at its own moment, and each
// response arrived inside a narrow window. That cannot be precomputed, batched
// or answered ahead of time, and a relay pays the round trip on every round
// rather than once.
//
// What it does not establish: that the client is human. Each prompt names the
// option to select, so a script that reads the prompt can answer it as well as
// a person can — it must merely stay attached and answer within the window,
// every round, in order. This is a live-attachment and throughput argument, not
// a humanity proof, and the naming matters: an earlier draft withheld the
// target, which made the challenge a one-in-four guess for a person and a
// script alike and therefore separated nothing while excluding almost every
// real user.
//
// It is still worth more than the existing proof-of-work challenge, which can
// be solved once and replayed, and which evidences no attachment at all. It is
// worth less than the assurance ladder's H2 label suggests, which is a further
// reason that level stays withheld until measured.
//
// It is separate from internal/challenge on purpose. That contract is frozen,
// and this mechanism belongs to the assurance surface rather than to
// enforcement: completing it never changes an enforcement action.
package liveness

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"io"
	"sync"
	"time"
)

const (
	// Family names this challenge contract.
	Family = "interactive_liveness_v1"

	// DefaultRounds is how many prompts must be answered. More rounds raise
	// attacker cost linearly but also raise abandonment, which is a budget the
	// deployment measures rather than a number to maximise.
	DefaultRounds = 3
	// Options is how many choices each round offers. A wrong answer ends the
	// attempt, so guessing succeeds with probability Options^-Rounds.
	Options = 4

	// MinimumResponse is a human reaction floor. Responses faster than this did
	// not react to a prompt that was only just revealed. It is deliberately
	// generous: assistive technology and practised users are fast, and
	// excluding them would be a worse failure than admitting a fast script.
	MinimumResponse = 120 * time.Millisecond
	// MaximumResponse bounds one round. It is long enough for a screen reader
	// to announce a prompt and for a person to consider it without hurrying.
	MaximumResponse = 20 * time.Second
	// MaximumTotal bounds a whole attempt including thinking time.
	MaximumTotal = 2 * time.Minute
	// AttestationTTL bounds how long a completed attempt may be presented.
	AttestationTTL = 2 * time.Minute

	// DefaultMaxEntries bounds concurrent attempts so the store cannot grow
	// without limit under load.
	DefaultMaxEntries = 50_000

	stateOpen      = "open"
	stateCompleted = "completed"
	stateFailed    = "failed"

	attestationContext = "PALISADE\x00LIVENESS-ATTESTATION\x00V1\x00"
)

var (
	ErrInvalid         = errors.New("invalid liveness challenge")
	ErrNotFound        = errors.New("liveness challenge not found")
	ErrExpired         = errors.New("liveness challenge expired")
	ErrTooFast         = errors.New("liveness response preceded the prompt")
	ErrWrongAnswer     = errors.New("liveness response did not match the prompt")
	ErrNotOpen         = errors.New("liveness challenge is not open")
	ErrCapacity        = errors.New("liveness capacity exceeded")
	ErrAttestation     = errors.New("invalid liveness attestation")
	ErrRoundOutOfOrder = errors.New("liveness round is out of order")
)

// Config configures the service. The secret authenticates attestations and
// never leaves the process.
type Config struct {
	Secret     []byte
	Rounds     int
	MaxEntries int
	Random     io.Reader
}

// Prompt is one round. Options are short words so a screen reader can announce
// them and a keyboard can select them: nothing here requires sight, a pointer,
// or a particular input device.
//
// Target names the option to select and is disclosed to the client. Withholding
// it would not make the challenge harder for a script — a script guesses as
// well as a person does — it would only make the round unanswerable, so the
// mechanism rests on the reveal timing rather than on secrecy.
type Prompt struct {
	Round   int      `json:"round"`
	Options []string `json:"options"`
	Target  string   `json:"target"`
	// Instruction is the sentence a client shows or announces. It names the
	// target, and it is the only thing that makes the round answerable.
	Instruction string    `json:"instruction"`
	RevealAt    time.Time `json:"reveal_at"`
	DeadlineAt  time.Time `json:"deadline_at"`
}

// Progress reports the state of an attempt after a round.
type Progress struct {
	ChallengeID string  `json:"challenge_id"`
	Completed   bool    `json:"completed"`
	Next        *Prompt `json:"next,omitempty"`
	// Attestation is present exactly once, when the final round is answered.
	Attestation string `json:"attestation,omitempty"`
}

type record struct {
	id            string
	sessionID     string
	action        string
	endpointClass string
	rounds        []Prompt
	answered      int
	state         string
	startedAt     time.Time
	expiresAt     time.Time
}

// Service holds open attempts. It performs no I/O and no network call.
type Service struct {
	mu         sync.Mutex
	secret     []byte
	rounds     int
	maxEntries int
	random     io.Reader
	entries    map[string]*record
}

// New builds a service. A short secret is refused rather than accepted with a
// weakened attestation.
func New(config Config) (*Service, error) {
	if len(config.Secret) < 32 {
		return nil, ErrInvalid
	}
	rounds := config.Rounds
	if rounds <= 0 {
		rounds = DefaultRounds
	}
	if rounds > 8 {
		return nil, ErrInvalid
	}
	maxEntries := config.MaxEntries
	if maxEntries <= 0 {
		maxEntries = DefaultMaxEntries
	}
	source := config.Random
	if source == nil {
		source = rand.Reader
	}
	return &Service{
		secret:     append([]byte(nil), config.Secret...),
		rounds:     rounds,
		maxEntries: maxEntries,
		random:     source,
		entries:    map[string]*record{},
	}, nil
}

// Begin opens an attempt bound to one session, action and endpoint class and
// returns its first prompt. Later prompts are not disclosed: each is revealed
// only when the previous round is answered, so an attempt cannot be solved
// ahead of time.
func (s *Service) Begin(sessionID, action, endpointClass string, now time.Time) (string, Prompt, error) {
	if len(sessionID) < 8 || len(sessionID) > 128 || action == "" || endpointClass == "" {
		return "", Prompt{}, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked(now)
	if len(s.entries) >= s.maxEntries {
		return "", Prompt{}, ErrCapacity
	}

	id, err := s.token(16)
	if err != nil {
		return "", Prompt{}, err
	}
	prompts := make([]Prompt, 0, s.rounds)
	for round := 0; round < s.rounds; round++ {
		prompt, err := s.newPrompt(round)
		if err != nil {
			return "", Prompt{}, err
		}
		prompts = append(prompts, prompt)
	}
	entry := &record{
		id: id, sessionID: sessionID, action: action, endpointClass: endpointClass,
		rounds: prompts, state: stateOpen, startedAt: now.UTC(),
		expiresAt: now.UTC().Add(MaximumTotal),
	}
	s.entries[id] = entry
	return id, s.revealLocked(entry, 0, now), nil
}

// Answer submits one round. A wrong answer, an answer that arrives before the
// prompt could have been read, or one that arrives after the round's deadline
// ends the attempt: retrying inside one attempt would let a client search the
// option space.
func (s *Service) Answer(id, sessionID, answer string, round int, now time.Time) (Progress, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked(now)

	entry, ok := s.entries[id]
	if !ok {
		return Progress{}, ErrNotFound
	}
	if subtle.ConstantTimeCompare([]byte(entry.sessionID), []byte(sessionID)) != 1 {
		return Progress{}, ErrInvalid
	}
	if entry.state != stateOpen {
		return Progress{}, ErrNotOpen
	}
	if !now.UTC().Before(entry.expiresAt) {
		entry.state = stateFailed
		return Progress{}, ErrExpired
	}
	if round != entry.answered {
		entry.state = stateFailed
		return Progress{}, ErrRoundOutOfOrder
	}

	prompt := entry.rounds[round]
	switch {
	case now.UTC().Before(prompt.RevealAt.Add(MinimumResponse)):
		entry.state = stateFailed
		return Progress{}, ErrTooFast
	case !now.UTC().Before(prompt.DeadlineAt):
		entry.state = stateFailed
		return Progress{}, ErrExpired
	case subtle.ConstantTimeCompare([]byte(answer), []byte(prompt.Target)) != 1:
		entry.state = stateFailed
		return Progress{}, ErrWrongAnswer
	}

	entry.answered++
	if entry.answered < len(entry.rounds) {
		next := s.revealLocked(entry, entry.answered, now)
		return Progress{ChallengeID: id, Next: &next}, nil
	}

	entry.state = stateCompleted
	attestation := s.attest(entry, now)
	delete(s.entries, id)
	return Progress{ChallengeID: id, Completed: true, Attestation: attestation}, nil
}

// VerifyAttestation checks that a completed attempt is being presented for the
// same session, action and endpoint class it was earned on, inside its short
// lifetime. It is stateless, so a caller must additionally consume it once:
// this package deletes the attempt on completion, and the assurance surface
// binds the attestation to a single request.
func (s *Service) VerifyAttestation(attestation, sessionID, action, endpointClass string, now time.Time) error {
	raw, err := base64.RawURLEncoding.DecodeString(attestation)
	if err != nil || len(raw) != sha256.Size+8 {
		return ErrAttestation
	}
	issued := time.Unix(int64(decodeUint64(raw[sha256.Size:])), 0).UTC()
	if issued.After(now.UTC().Add(time.Minute)) || !now.UTC().Before(issued.Add(AttestationTTL)) {
		return ErrAttestation
	}
	expected := s.attestationMAC(sessionID, action, endpointClass, issued)
	if subtle.ConstantTimeCompare(raw[:sha256.Size], expected) != 1 {
		return ErrAttestation
	}
	return nil
}

// Sweep drops expired attempts and reports how many were removed.
func (s *Service) Sweep(now time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sweepLocked(now)
}

// Open reports how many attempts are currently in flight.
func (s *Service) Open() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.entries)
}

func (s *Service) revealLocked(entry *record, round int, now time.Time) Prompt {
	prompt := entry.rounds[round]
	prompt.RevealAt = now.UTC()
	prompt.DeadlineAt = now.UTC().Add(MaximumResponse)
	entry.rounds[round] = prompt
	// The target is not disclosed to the caller: the transport layer strips it
	// before the prompt reaches the client.
	return prompt
}

// vocabulary is the closed word list a prompt draws from. Short, common,
// unambiguous when read aloud, and free of digits or punctuation a screen
// reader would spell out. It is English only: a deployment serving other
// languages needs its own list, and that localisation gap is real rather than
// something this list solves.
var vocabulary = []string{
	"anchor", "basket", "candle", "dolphin", "engine", "feather", "garden",
	"harbour", "island", "jacket", "kitchen", "lantern", "meadow", "needle",
	"orchard", "pillow", "quarry", "ribbon", "saddle", "tunnel", "umbrella",
	"village", "walnut", "yellow",
}

func (s *Service) newPrompt(round int) (Prompt, error) {
	options := make([]string, 0, Options)
	chosen := make(map[string]struct{}, Options)
	for len(options) < Options {
		index, err := s.index(len(vocabulary))
		if err != nil {
			return Prompt{}, err
		}
		word := vocabulary[index]
		// A repeated option would make one round ambiguous to answer.
		if _, taken := chosen[word]; taken {
			continue
		}
		chosen[word] = struct{}{}
		options = append(options, word)
	}
	choice, err := s.index(Options)
	if err != nil {
		return Prompt{}, err
	}
	target := options[choice]
	return Prompt{
		Round:       round,
		Options:     options,
		Target:      target,
		Instruction: "Select " + target + ".",
	}, nil
}

func (s *Service) attest(entry *record, now time.Time) string {
	issued := now.UTC().Truncate(time.Second)
	mac := s.attestationMAC(entry.sessionID, entry.action, entry.endpointClass, issued)
	raw := make([]byte, 0, sha256.Size+8)
	raw = append(raw, mac...)
	raw = append(raw, encodeUint64(uint64(issued.Unix()))...)
	return base64.RawURLEncoding.EncodeToString(raw)
}

func (s *Service) attestationMAC(sessionID, action, endpointClass string, issued time.Time) []byte {
	mac := hmac.New(sha256.New, s.secret)
	mac.Write([]byte(attestationContext))
	for _, part := range []string{sessionID, action, endpointClass} {
		mac.Write([]byte(part))
		mac.Write([]byte{0})
	}
	mac.Write(encodeUint64(uint64(issued.Unix())))
	return mac.Sum(nil)
}

func (s *Service) sweepLocked(now time.Time) int {
	removed := 0
	for id, entry := range s.entries {
		if !now.UTC().Before(entry.expiresAt) {
			delete(s.entries, id)
			removed++
		}
	}
	return removed
}

func (s *Service) token(size int) (string, error) {
	raw := make([]byte, size)
	if _, err := io.ReadFull(s.random, raw); err != nil {
		return "", ErrInvalid
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func (s *Service) index(bound int) (int, error) {
	raw := make([]byte, 1)
	if _, err := io.ReadFull(s.random, raw); err != nil {
		return 0, ErrInvalid
	}
	return int(raw[0]) % bound, nil
}

func encodeUint64(value uint64) []byte {
	raw := make([]byte, 8)
	for index := 7; index >= 0; index-- {
		raw[index] = byte(value)
		value >>= 8
	}
	return raw
}

func decodeUint64(raw []byte) uint64 {
	value := uint64(0)
	for _, part := range raw {
		value = value<<8 | uint64(part)
	}
	return value
}

// PromptForTest returns a revealed round including its target. It exists so the
// transport layer's tests can answer a challenge the transport deliberately
// never discloses the answer to. Nothing in the request path calls it, and a
// client can never reach it.
func (s *Service) PromptForTest(id string, round int) (Prompt, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.entries[id]
	if !ok || round < 0 || round >= len(entry.rounds) {
		return Prompt{}, false
	}
	return entry.rounds[round], true
}
