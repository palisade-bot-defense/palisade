package httpapi

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/palisade-bot-defense/palisade/internal/core"
	"github.com/palisade-bot-defense/palisade/internal/events"
	"github.com/palisade-bot-defense/palisade/internal/rollout"
)

var ErrInvalidEventShadowProfile = errors.New("invalid event shadow evaluation profile")

// EventShadowProfile is a server-trusted action and endpoint classification
// used only to turn an accepted browser event flush into a shadow decision.
type EventShadowProfile struct {
	action        string
	endpointClass string
}

func NewEventShadowProfile(action, endpointClass string) (EventShadowProfile, error) {
	if !validEventShadowAction(action) || !validEventShadowEndpoint(endpointClass) {
		return EventShadowProfile{}, ErrInvalidEventShadowProfile
	}
	return EventShadowProfile{action: action, endpointClass: endpointClass}, nil
}

func (s *Server) recordEventShadowDecision(ctx context.Context, batch events.Batch, verifiedSession, userAgentPresent bool, now time.Time) error {
	if s.eventShadow == nil {
		return nil
	}
	if s.shadowRecorder == nil || s.tokens == nil || len(batch.Events) == 0 {
		return errors.New("event shadow evaluation dependencies unavailable")
	}
	proof, err := s.tokens.Issue(batch.SessionID, s.eventShadow.action, time.Minute, now)
	if err != nil {
		return fmt.Errorf("issue internal event shadow proof: %w", err)
	}
	request := core.DecisionRequest{
		SessionID:     batch.SessionID,
		Action:        s.eventShadow.action,
		EndpointClass: s.eventShadow.endpointClass,
		Sequence:      batch.Events[len(batch.Events)-1].Sequence,
		ProofToken:    proof,
		Observations: core.Observations{
			UserAgentPresent:      userAgentPresent,
			BrowserEventCount:     s.events.Count(batch.SessionID, now),
			BrowserEventsVerified: true,
			ServerSessionVerified: verifiedSession,
		},
	}
	decision, err := s.engine.Decide(ctx, request)
	if err != nil {
		return fmt.Errorf("evaluate accepted event batch: %w", err)
	}
	// Proofs are hot-path credentials and must never reach recorder
	// implementations, even though the built-in encrypted sink ignores them.
	request.ProofToken = ""
	decision = forceShadowDecision(decision, now)
	s.recordRuntimeDecision(decision)
	if err := s.shadowRecorder.RecordDecision(request, decision, now); err != nil {
		return fmt.Errorf("record accepted event batch decision: %w", err)
	}
	s.counters.recordedDecisions.Add(1)
	return nil
}

func forceShadowDecision(decision core.Decision, now time.Time) core.Decision {
	decision.Mode = core.RuntimeModeShadow
	decision.RolloutID = ""
	if decision.ComputedAction == core.ActionAllow {
		decision.Action = core.ActionAllow
	} else {
		decision.Action = core.ActionObserve
	}
	if decision.ComputedAction == core.ActionDelay || decision.ComputedAction == core.ActionThrottle || decision.ComputedAction == core.ActionChallenge || decision.ComputedAction == core.ActionBlock {
		decision.ReasonCodes = appendReasonOnce(decision.ReasonCodes, core.ReasonShadowActionOverridden)
	}
	decision.Directive = rollout.DefaultDirective(decision.Action, now)
	decision.ExpiresAt = now.Add(30 * time.Second)
	return decision
}

func (s *Server) recordEventShadowDrop(err error) {
	dropped := s.eventShadowDrops.Add(1)
	if dropped == 1 || dropped%1024 == 0 {
		s.logger.Warn("event shadow evaluation dropped", "dropped_total", dropped, "error", err)
	}
}

func appendReasonOnce(reasons []string, reason string) []string {
	for _, existing := range reasons {
		if existing == reason {
			return reasons
		}
	}
	return append(reasons, reason)
}

func validEventShadowAction(value string) bool {
	switch value {
	case "read", "write", "create", "update", "delete", "search", "compare", "login", "logout", "register", "checkout", "purchase", "other":
		return true
	default:
		return false
	}
}

func validEventShadowEndpoint(value string) bool {
	switch value {
	case "public_content", "compare_index", "compare_noindex", "challenge_worker", "other_public", "account", "login", "checkout", "other":
		return true
	default:
		return false
	}
}
