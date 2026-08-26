package engine

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/palisade-bot-defense/palisade/internal/core"
	"github.com/palisade-bot-defense/palisade/internal/detector"
	"github.com/palisade-bot-defense/palisade/internal/fusion"
	"github.com/palisade-bot-defense/palisade/internal/policy"
	"github.com/palisade-bot-defense/palisade/internal/session"
	"github.com/palisade-bot-defense/palisade/internal/token"
)

var (
	ErrProofRequired  = errors.New("proof token is required")
	ErrInvalidRequest = errors.New("invalid decision request")
)

type Engine struct {
	sessions     *session.MemoryStore
	detectors    *detector.Registry
	policy       *policy.Engine
	tokens       *token.Service
	requireProof bool
	now          func() time.Time
}

func New(sessions *session.MemoryStore, detectors *detector.Registry, policyEngine *policy.Engine, tokens *token.Service, requireProof bool) *Engine {
	return &Engine{sessions: sessions, detectors: detectors, policy: policyEngine, tokens: tokens, requireProof: requireProof, now: time.Now}
}

func (e *Engine) Decide(ctx context.Context, request core.DecisionRequest) (core.Decision, error) {
	if err := validateRequest(request); err != nil {
		return core.Decision{}, err
	}
	now := e.now().UTC()
	if e.requireProof {
		if request.ProofToken == "" {
			return core.Decision{}, ErrProofRequired
		}
		if _, err := e.tokens.VerifyAndConsume(request.ProofToken, request.SessionID, request.Action, now); err != nil {
			return core.Decision{}, fmt.Errorf("verify proof: %w", err)
		}
	}
	snapshot := e.sessions.Observe(request.SessionID, request.Sequence, now)
	evidence, err := e.detectors.Evaluate(ctx, core.DetectorInput{Request: request, Session: snapshot})
	if err != nil {
		return core.Decision{}, fmt.Errorf("evaluate detectors: %w", err)
	}
	scores := fusion.Calculate(evidence)
	result, err := e.policy.Evaluate(policy.Input{
		Scores: scores, EndpointClass: request.EndpointClass,
		HoneypotHits:  request.Observations.HoneypotHits,
		CrowdSecAlert: request.Observations.CrowdSecAlert,
		VerifiedBot:   request.Observations.VerifiedBot,
	})
	if err != nil {
		return core.Decision{}, err
	}
	reasons := []string{result.Reason}
	for _, item := range evidence {
		reasons = append(reasons, item.Code)
	}
	return core.Decision{
		DecisionID: newID(), Action: result.Action, Scores: scores,
		ReasonCodes: reasons, Evidence: evidence,
		PolicyVersion: e.policy.Version(), ModelVersion: "transparent-baseline-v1",
		ExpiresAt: now.Add(30 * time.Second),
	}, nil
}

func validateRequest(request core.DecisionRequest) error {
	if len(request.SessionID) < 8 || len(request.SessionID) > 128 || len(request.Action) < 1 || len(request.Action) > 80 {
		return ErrInvalidRequest
	}
	if len(request.EndpointClass) < 1 || len(request.EndpointClass) > 64 || request.Sequence == 0 {
		return ErrInvalidRequest
	}
	if strings.ContainsAny(request.SessionID+request.Action+request.EndpointClass, "\r\n\x00") {
		return ErrInvalidRequest
	}
	if request.Observations.BrowserEventCount < 0 || request.Observations.BrowserEventCount > 10_000 || request.Observations.HoneypotHits < 0 || request.Observations.HoneypotHits > 100 {
		return ErrInvalidRequest
	}
	if request.Observations.CannaiScore < 0 || request.Observations.CannaiScore > 1 {
		return ErrInvalidRequest
	}
	return nil
}

func newID() string {
	buffer := make([]byte, 16)
	if _, err := rand.Read(buffer); err != nil {
		panic("crypto/rand unavailable: " + err.Error())
	}
	return hex.EncodeToString(buffer)
}
