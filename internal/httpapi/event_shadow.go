package httpapi

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/palisade-bot-defense/palisade/internal/core"
	"github.com/palisade-bot-defense/palisade/internal/events"
	"github.com/palisade-bot-defense/palisade/internal/rollout"
	"github.com/palisade-bot-defense/palisade/internal/token"
)

var ErrInvalidEventShadowProfile = errors.New("invalid event shadow evaluation profile")

// EventShadowProfile is a server-trusted action and endpoint classification
// used only to turn an accepted browser event flush into a shadow decision.
type EventShadowProfile struct {
	action        string
	endpointClass string
	fromProof     bool
}

func NewEventShadowProfile(action, endpointClass string) (EventShadowProfile, error) {
	if !validEventShadowAction(action) || !validEventShadowEndpoint(endpointClass) {
		return EventShadowProfile{}, ErrInvalidEventShadowProfile
	}
	return EventShadowProfile{action: action, endpointClass: endpointClass}, nil
}

// NewEventShadowProofProfile requires each accepted event proof to carry the
// backend-authorized action and endpoint class. It is mutually exclusive with
// the static profile at the CLI boundary.
func NewEventShadowProofProfile() EventShadowProfile {
	return EventShadowProfile{fromProof: true}
}

func (s *Server) recordEventShadowDecision(ctx context.Context, batch events.Batch, receipt events.IngestReceipt, proofClaims token.Claims, verifiedSession, userAgentPresent bool, now time.Time) error {
	if s.eventShadow == nil {
		return nil
	}
	if s.shadowRecorder == nil || s.tokens == nil || len(batch.Events) == 0 || receipt.BatchSequence == 0 {
		return errors.New("event shadow evaluation dependencies unavailable")
	}
	action, endpointClass, err := s.eventShadow.classification(proofClaims)
	if err != nil {
		return err
	}
	proof, err := s.tokens.Issue(batch.SessionID, action, time.Minute, now)
	if err != nil {
		return fmt.Errorf("issue internal event shadow proof: %w", err)
	}
	request := core.DecisionRequest{
		SessionID:     batch.SessionID,
		Action:        action,
		EndpointClass: endpointClass,
		// A decision sequence counts accepted HTTP batches. The browser event
		// sequence counts events within those batches and can legitimately jump
		// by dozens between flushes; treating that jump as missing requests
		// produced false SEQUENCE_GAP_HIGH evidence in the first shadow pilot.
		Sequence:   receipt.BatchSequence,
		ProofToken: proof,
		Observations: core.Observations{
			UserAgentPresent:      userAgentPresent,
			BrowserEventCount:     receipt.TotalAcceptedEvents,
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
	s.counters.eventShadowRecorded.Add(1)
	return nil
}

func (p EventShadowProfile) classification(claims token.Claims) (string, string, error) {
	if p.fromProof {
		if !validEventShadowAction(claims.RequestAction) || !validEventShadowEndpoint(claims.EndpointClass) {
			return "", "", errors.New("event shadow proof context required")
		}
		return claims.RequestAction, claims.EndpointClass, nil
	}
	if claims.RequestAction != "" || claims.EndpointClass != "" {
		return "", "", errors.New("event shadow proof context is disabled")
	}
	return p.action, p.endpointClass, nil
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
	return core.ValidRequestAction(value)
}

func validEventShadowEndpoint(value string) bool {
	return core.ValidEndpointClass(value)
}
