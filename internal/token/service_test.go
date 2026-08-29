package token

import (
	"encoding/base64"
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

func TestEventContextIsSignedBoundedAndOneTime(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	service, err := NewService([]byte("0123456789abcdef0123456789abcdef"), NewMemoryNonceStore())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := service.IssueEventContext("session-a", "compare", "compare_noindex", time.Minute, now)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := service.VerifyAndConsume(raw, "session-a", "events", now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if claims.RequestAction != "compare" || claims.EndpointClass != "compare_noindex" {
		t.Fatalf("event context = %+v", claims)
	}
	if _, err := service.VerifyAndConsume(raw, "session-a", "events", now.Add(2*time.Second)); !errors.Is(err, ErrReplayToken) {
		t.Fatalf("event context replay = %v", err)
	}
	for _, invalid := range []struct{ action, endpoint string }{
		{"", "public_content"}, {"read", ""}, {"/raw/path", "public_content"}, {"read", "/private"},
	} {
		if _, err := service.IssueEventContext("session-a", invalid.action, invalid.endpoint, time.Minute, now); err == nil {
			t.Fatalf("accepted invalid event context %#v", invalid)
		}
	}
}

func TestVerifyRejectsTrailingClaimsData(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	service, _ := NewService([]byte("0123456789abcdef0123456789abcdef"), NewMemoryNonceStore())
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"v":1,"sid":"session-a","act":"events","iat":1800000000,"exp":1800000060,"n":"AAAAAAAAAAAAAAAAAAAAAA"} {}`))
	raw := payload + "." + service.sign(payload)
	if _, err := service.VerifyAndConsume(raw, "session-a", "events", now); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("trailing claims data = %v", err)
	}
}

func TestVerifyRejectsUnboundedSignedLifetime(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	service, _ := NewService([]byte("0123456789abcdef0123456789abcdef"), NewMemoryNonceStore())
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"v":1,"sid":"session-a","act":"events","iat":1800000000,"exp":1800000301,"n":"AAAAAAAAAAAAAAAAAAAAAA"}`))
	raw := payload + "." + service.sign(payload)
	if _, err := service.VerifyAndConsume(raw, "session-a", "events", now); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("unbounded lifetime = %v", err)
	}
}

func TestIssueRejectsUnboundedBindings(t *testing.T) {
	service, _ := NewService([]byte("0123456789abcdef0123456789abcdef"), NewMemoryNonceStore())
	now := time.Unix(1_800_000_000, 0)
	for _, input := range []struct{ session, action string }{
		{"short", "read"},
		{string(make([]byte, 129)), "read"},
		{"session-a", ""},
		{"session-a", "read\nraw"},
		{"session-a", "vendor-action"},
	} {
		if _, err := service.Issue(input.session, input.action, time.Minute, now); err == nil {
			t.Fatalf("accepted binding session_len=%d action=%q", len(input.session), input.action)
		}
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
