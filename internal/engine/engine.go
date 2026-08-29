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
	"github.com/palisade-bot-defense/palisade/internal/decoy"
	"github.com/palisade-bot-defense/palisade/internal/detector"
	"github.com/palisade-bot-defense/palisade/internal/fusion"
	"github.com/palisade-bot-defense/palisade/internal/policy"
	"github.com/palisade-bot-defense/palisade/internal/rollout"
	"github.com/palisade-bot-defense/palisade/internal/session"
	"github.com/palisade-bot-defense/palisade/internal/token"
	"github.com/palisade-bot-defense/palisade/pkg/palisadecontract"
)

var (
	ErrProofRequired         = errors.New("proof token is required")
	ErrInvalidRequest        = errors.New("invalid decision request")
	ErrExplicitTimeWithProof = errors.New("explicit decision time is unavailable with proof enforcement")
)

const ModelVersion = "transparent-baseline-v13"

type Engine struct {
	sessions      *session.MemoryStore
	detectors     *detector.Registry
	policy        *policy.Engine
	tokens        *token.Service
	requireProof  bool
	mode          core.RuntimeMode
	rollout       *rollout.Controller
	decoys        *decoy.Service
	now           func() time.Time
	newDecisionID func() string
}

type Option func(*Engine)

func WithClock(now func() time.Time) Option {
	return func(engine *Engine) {
		if now != nil {
			engine.now = now
		}
	}
}

func WithDecisionIDGenerator(generator func() string) Option {
	return func(engine *Engine) {
		if generator != nil {
			engine.newDecisionID = generator
		}
	}
}

func WithRollout(controller *rollout.Controller) Option {
	return func(engine *Engine) {
		engine.rollout = controller
	}
}

func New(sessions *session.MemoryStore, detectors *detector.Registry, policyEngine *policy.Engine, tokens *token.Service, requireProof bool, mode core.RuntimeMode, options ...Option) *Engine {
	if mode != core.RuntimeModeEnforce {
		mode = core.RuntimeModeShadow
	}
	engine := &Engine{
		sessions:      sessions,
		detectors:     detectors,
		policy:        policyEngine,
		tokens:        tokens,
		requireProof:  requireProof,
		mode:          mode,
		now:           time.Now,
		newDecisionID: newID,
	}
	engine.decoys = decoy.NewDefault()
	for _, option := range options {
		option(engine)
	}
	return engine
}

// Decoys exposes the process-local service so the authenticated HTTP contract
// and the decision engine share exactly one bounded capability store.
func (e *Engine) Decoys() *decoy.Service { return e.decoys }

func (e *Engine) Decide(ctx context.Context, request core.DecisionRequest) (core.Decision, error) {
	return e.decideAt(ctx, request, e.now().UTC())
}

// DecideAt evaluates a request using an explicit observation time. It is used
// by offline replay so session TTLs and expiries follow captured event time.
func (e *Engine) DecideAt(ctx context.Context, request core.DecisionRequest, observedAt time.Time) (core.Decision, error) {
	if e.requireProof {
		return core.Decision{}, ErrExplicitTimeWithProof
	}
	return e.decideAt(ctx, request, observedAt.UTC())
}

func (e *Engine) decideAt(ctx context.Context, request core.DecisionRequest, now time.Time) (core.Decision, error) {
	if err := validateRequest(request); err != nil {
		return core.Decision{}, err
	}
	if e.requireProof {
		if request.ProofToken == "" {
			return core.Decision{}, ErrProofRequired
		}
		if _, err := e.tokens.VerifyAndConsume(request.ProofToken, request.SessionID, request.Action, now); err != nil {
			return core.Decision{}, fmt.Errorf("verify proof: %w", err)
		}
	}
	snapshot := e.sessions.Observe(request.SessionID, request.Sequence, request.EndpointClass, now)
	if e.decoys != nil {
		request.Observations.VerifiedDecoyHits = e.decoys.TakeHits(request.SessionID, request.EndpointClass, now)
	}
	evidence, err := e.detectors.Evaluate(ctx, core.DetectorInput{Request: request, Session: snapshot})
	if err != nil {
		return core.Decision{}, fmt.Errorf("evaluate detectors: %w", err)
	}
	scores := fusion.Calculate(evidence)
	result, err := e.policy.Evaluate(policy.Input{
		Scores: scores, EndpointClass: request.EndpointClass,
		HoneypotHits: boundedDecoyHits(request.Observations.HoneypotHits, request.Observations.VerifiedDecoyHits),
		PolicyAlert:  request.Observations.PolicyAlert,
		VerifiedBot:  core.VerifiedPublicCrawler(request.Observations, request.EndpointClass),
	})
	if err != nil {
		return core.Decision{}, err
	}
	computedAction := result.Action
	action := computedAction
	mode := e.mode
	rolloutID := ""
	directive := rollout.DefaultDirective(action, now)
	reasons := []string{result.Reason}
	if e.rollout != nil {
		applied := e.rollout.ApplyWithContext(request.SessionID, request.EndpointClass, computedAction, rollout.AdaptiveContextFrom(snapshot, evidence), now)
		action, mode, rolloutID, directive = applied.Action, applied.Mode, applied.RolloutID, applied.Directive
		reasons = append(reasons, applied.Reasons...)
		if mode == core.RuntimeModeShadow && computedAction != core.ActionAllow && computedAction != core.ActionObserve {
			reasons = append(reasons, core.ReasonShadowActionOverridden)
		}
	} else if e.mode == core.RuntimeModeShadow && computedAction != core.ActionAllow && computedAction != core.ActionObserve {
		action = core.ActionObserve
		directive = rollout.DefaultDirective(action, now)
		reasons = append(reasons, core.ReasonShadowActionOverridden)
	}
	for _, item := range evidence {
		reasons = append(reasons, item.Code)
	}
	e.sessions.RecordEnforcement(request.SessionID, directive, now)
	return core.Decision{
		DecisionID:     e.newDecisionID(),
		Action:         action,
		ComputedAction: computedAction,
		Mode:           mode,
		RolloutID:      rolloutID,
		Directive:      directive,
		Scores:         scores,
		ReasonCodes:    reasons,
		Evidence:       evidence,
		PolicyVersion:  e.policy.Version(),
		ModelVersion:   ModelVersion,
		ExpiresAt:      now.Add(30 * time.Second),
	}, nil
}

func boundedDecoyHits(claimed, verified int) int {
	if claimed >= 100 || verified >= 100 || claimed+verified >= 100 {
		return 100
	}
	return claimed + verified
}

func validateRequest(request core.DecisionRequest) error {
	if len(request.SessionID) < 8 || len(request.SessionID) > 128 || !core.ValidRequestAction(request.Action) {
		return ErrInvalidRequest
	}
	if !core.ValidEndpointClass(request.EndpointClass) || request.Sequence == 0 {
		return ErrInvalidRequest
	}
	if strings.ContainsAny(request.SessionID+request.Action+request.EndpointClass, "\r\n\x00") {
		return ErrInvalidRequest
	}
	if request.Observations.BrowserEventCount < 0 || request.Observations.BrowserEventCount > 10_000 || request.Observations.HoneypotHits < 0 || request.Observations.HoneypotHits > 100 {
		return ErrInvalidRequest
	}
	if request.Observations.ExternalRiskScore < 0 || request.Observations.ExternalRiskScore > 1 {
		return ErrInvalidRequest
	}
	if _, valid := core.NormalizeEvaluationCohort(request.EvaluationCohort); !valid {
		return ErrInvalidRequest
	}
	if _, valid := core.NormalizeCrawlerClass(request.Observations.CrawlerClass); !valid {
		return ErrInvalidRequest
	}
	if _, valid := core.NormalizeCrawlerVerification(request.Observations.CrawlerVerification); !valid {
		return ErrInvalidRequest
	}
	if !palisadecontract.ValidCrawlerIdentity(request.Observations.VerifiedBot, string(request.Observations.CrawlerClass), string(request.Observations.CrawlerVerification)) {
		return ErrInvalidRequest
	}
	if !validTransportProtocol(request.Observations.TransportProtocol) || !validTransportSecurity(request.Observations.TransportSecurity) ||
		!validClientAddressSource(request.Observations.ClientAddressSource) {
		return ErrInvalidRequest
	}
	if !core.ValidEdgeIntelligence(request.Observations.EdgeFingerprintClass, request.Observations.EdgeFingerprintMethod,
		request.Observations.NetworkReputation, request.Observations.NetworkType) {
		return ErrInvalidRequest
	}
	if !palisadecontract.ValidOptionalUnknownClass(request.Observations.ChallengeVerdict, palisadecontract.ValidChallengeVerdict) {
		return ErrInvalidRequest
	}
	return nil
}

func validTransportProtocol(value string) bool {
	return palisadecontract.ValidOptionalUnknownClass(value, palisadecontract.ValidTransportProtocol)
}

func validTransportSecurity(value string) bool {
	return palisadecontract.ValidOptionalUnknownClass(value, palisadecontract.ValidTransportSecurity)
}

func validClientAddressSource(value string) bool {
	return palisadecontract.ValidOptionalUnknownClass(value, palisadecontract.ValidClientAddressSource)
}

func newID() string {
	buffer := make([]byte, 16)
	if _, err := rand.Read(buffer); err != nil {
		panic("crypto/rand unavailable: " + err.Error())
	}
	return hex.EncodeToString(buffer)
}
