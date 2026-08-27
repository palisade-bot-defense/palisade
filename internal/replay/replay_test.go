package replay

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/palisade-bot-defense/palisade/internal/core"
)

type replayTestEngine struct{}

func (replayTestEngine) DecideAt(_ context.Context, _ core.DecisionRequest, observedAt time.Time) (core.Decision, error) {
	return core.Decision{Action: core.ActionAllow, ComputedAction: core.ActionAllow, ExpiresAt: observedAt.Add(30 * time.Second)}, nil
}

func TestRunRequiresObservedAt(t *testing.T) {
	err := Run(context.Background(), strings.NewReader(`{"request":{}}`+"\n"), &bytes.Buffer{}, replayTestEngine{})
	if !errors.Is(err, ErrObservedAtRequired) || !strings.Contains(err.Error(), "replay line 1") {
		t.Fatalf("error = %v, want line-specific %v", err, ErrObservedAtRequired)
	}
}

func TestRunRejectsDecreasingObservedAt(t *testing.T) {
	input := `{"observed_at":"2026-01-15T12:00:01Z","request":{}}` + "\n" +
		`{"observed_at":"2026-01-15T12:00:00Z","request":{}}` + "\n"
	err := Run(context.Background(), strings.NewReader(input), &bytes.Buffer{}, replayTestEngine{})
	if !errors.Is(err, ErrObservedAtOutOfOrder) || !strings.Contains(err.Error(), "replay line 2") {
		t.Fatalf("error = %v, want line-specific %v", err, ErrObservedAtOutOfOrder)
	}
}

func TestRunAcceptsEqualObservedAt(t *testing.T) {
	input := `{"observed_at":"2026-01-15T12:00:00Z","request":{}}` + "\n" +
		`{"observed_at":"2026-01-15T12:00:00Z","request":{}}` + "\n"
	if err := Run(context.Background(), strings.NewReader(input), &bytes.Buffer{}, replayTestEngine{}); err != nil {
		t.Fatal(err)
	}
}
