package replay

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/palisade-bot-defense/palisade/internal/core"
)

type DecisionEngine interface {
	DecideAt(context.Context, core.DecisionRequest, time.Time) (core.Decision, error)
}

type Record struct {
	Request                core.DecisionRequest `json:"request"`
	ObservedAt             time.Time            `json:"observed_at"`
	ExpectedAction         core.Action          `json:"expected_action,omitempty"`
	ExpectedComputedAction core.Action          `json:"expected_computed_action,omitempty"`
}

var (
	ErrObservedAtRequired   = errors.New("observed_at is required")
	ErrObservedAtOutOfOrder = errors.New("observed_at is earlier than the previous record")
)

func Run(ctx context.Context, input io.Reader, output io.Writer, engine DecisionEngine) error {
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 64*1024), 1<<20)
	encoder := json.NewEncoder(output)
	line := 0
	var previousObservedAt time.Time
	for scanner.Scan() {
		line++
		var record Record
		if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
			return fmt.Errorf("decode replay line %d: %w", line, err)
		}
		if record.ObservedAt.IsZero() {
			return fmt.Errorf("replay line %d: %w", line, ErrObservedAtRequired)
		}
		observedAt := record.ObservedAt.UTC()
		if !previousObservedAt.IsZero() && observedAt.Before(previousObservedAt) {
			return fmt.Errorf("replay line %d: %w", line, ErrObservedAtOutOfOrder)
		}
		previousObservedAt = observedAt
		decision, err := engine.DecideAt(ctx, record.Request, observedAt)
		if err != nil {
			return fmt.Errorf("decide replay line %d: %w", line, err)
		}
		actionMatched := record.ExpectedAction == "" || decision.Action == record.ExpectedAction
		computedActionMatched := record.ExpectedComputedAction == "" || decision.ComputedAction == record.ExpectedComputedAction
		matched := actionMatched && computedActionMatched
		if err := encoder.Encode(map[string]any{
			"line": line, "matched": matched,
			"observed_at":     observedAt,
			"expected_action": record.ExpectedAction, "expected_computed_action": record.ExpectedComputedAction,
			"decision": decision,
		}); err != nil {
			return fmt.Errorf("encode replay result: %w", err)
		}
		if !matched {
			return fmt.Errorf(
				"replay line %d: expected action=%s computed_action=%s, got action=%s computed_action=%s",
				line, record.ExpectedAction, record.ExpectedComputedAction, decision.Action, decision.ComputedAction,
			)
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read replay: %w", err)
	}
	return nil
}
