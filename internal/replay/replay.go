package replay

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/palisade-bot-defense/palisade/internal/core"
)

type DecisionEngine interface {
	Decide(context.Context, core.DecisionRequest) (core.Decision, error)
}

type Record struct {
	Request        core.DecisionRequest `json:"request"`
	ExpectedAction core.Action          `json:"expected_action,omitempty"`
}

func Run(ctx context.Context, input io.Reader, output io.Writer, engine DecisionEngine) error {
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 64*1024), 1<<20)
	encoder := json.NewEncoder(output)
	line := 0
	for scanner.Scan() {
		line++
		var record Record
		if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
			return fmt.Errorf("decode replay line %d: %w", line, err)
		}
		decision, err := engine.Decide(ctx, record.Request)
		if err != nil {
			return fmt.Errorf("decide replay line %d: %w", line, err)
		}
		matched := record.ExpectedAction == "" || decision.Action == record.ExpectedAction
		if err := encoder.Encode(map[string]any{"line": line, "matched": matched, "expected_action": record.ExpectedAction, "decision": decision}); err != nil {
			return fmt.Errorf("encode replay result: %w", err)
		}
		if !matched {
			return fmt.Errorf("replay line %d: expected %s, got %s", line, record.ExpectedAction, decision.Action)
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read replay: %w", err)
	}
	return nil
}
