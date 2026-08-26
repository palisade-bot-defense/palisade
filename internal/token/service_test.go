package token

import (
	"errors"
	"testing"
	"time"
)

func TestIssueVerifyAndRejectReplay(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	service, err := NewService([]byte("0123456789abcdef0123456789abcdef"), NewMemoryNonceStore())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := service.Issue("session-a", "search", time.Minute, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.VerifyAndConsume(raw, "session-a", "search", now.Add(time.Second)); err != nil {
		t.Fatalf("first verification failed: %v", err)
	}
	if _, err := service.VerifyAndConsume(raw, "session-a", "search", now.Add(2*time.Second)); !errors.Is(err, ErrReplayToken) {
		t.Fatalf("expected replay error, got %v", err)
	}
}

func TestTokenIsBoundToAction(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	service, _ := NewService([]byte("0123456789abcdef0123456789abcdef"), NewMemoryNonceStore())
	raw, _ := service.Issue("session-a", "search", time.Minute, now)
	if _, err := service.VerifyAndConsume(raw, "session-a", "checkout", now); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expected invalid token, got %v", err)
	}
}

func FuzzVerifyToken(f *testing.F) {
	service, _ := NewService([]byte("0123456789abcdef0123456789abcdef"), NewMemoryNonceStore())
	f.Add("not-a-token", "s", "a")
	f.Fuzz(func(t *testing.T, raw, sessionID, action string) {
		_, _ = service.VerifyAndConsume(raw, sessionID, action, time.Now())
	})
}
