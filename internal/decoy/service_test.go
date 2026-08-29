package decoy

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

func TestCapabilityIsBoundOneTimeAndExpires(t *testing.T) {
	now := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	service, err := New(Config{Random: bytes.NewReader(bytes.Repeat([]byte{0x42}, 96))})
	if err != nil {
		t.Fatal(err)
	}
	issued, err := service.Issue(IssueRequest{
		SessionID: "session-12345678", EndpointClass: "login", Surface: SurfaceForm, TTL: time.Minute,
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(issued.Capability) != 43 || !issued.ExpiresAt.Equal(now.Add(time.Minute)) {
		t.Fatalf("unexpected capability metadata: %+v", issued)
	}
	if err := service.Hit(issued.Capability, InteractionSubmitted, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := service.Hit(issued.Capability, InteractionSubmitted, now.Add(2*time.Second)); !errors.Is(err, ErrInvalidCapability) {
		t.Fatalf("replay error = %v", err)
	}
	if hits := service.TakeHits("session-12345678", "account", now.Add(2*time.Second)); hits != 0 {
		t.Fatalf("cross-endpoint hits = %d", hits)
	}
	if hits := service.TakeHits("other-session-123", "login", now.Add(2*time.Second)); hits != 0 {
		t.Fatalf("cross-session hits = %d", hits)
	}
	if hits := service.TakeHits("session-12345678", "login", now.Add(2*time.Second)); hits != 1 {
		t.Fatalf("hits = %d, want 1", hits)
	}
	if hits := service.TakeHits("session-12345678", "login", now.Add(2*time.Second)); hits != 0 {
		t.Fatalf("second take = %d", hits)
	}
}

func TestExpiredCapabilityAndPendingHitFailClosed(t *testing.T) {
	now := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	service, _ := New(Config{})
	issued, err := service.Issue(IssueRequest{
		SessionID: "session-12345678", EndpointClass: "public_content", Surface: SurfaceLink, TTL: MinimumTTL,
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Hit(issued.Capability, InteractionTouched, issued.ExpiresAt); !errors.Is(err, ErrExpired) {
		t.Fatalf("expiry error = %v", err)
	}
	second, _ := service.Issue(IssueRequest{
		SessionID: "session-12345678", EndpointClass: "public_content", Surface: SurfaceAPI, TTL: time.Minute,
	}, now)
	if err := service.Hit(second.Capability, InteractionSubmitted, now); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("cross-surface interaction error = %v", err)
	}
	if err := service.Hit(second.Capability, InteractionTouched, now); err != nil {
		t.Fatal(err)
	}
	if hits := service.TakeHits("session-12345678", "public_content", now.Add(PendingTTL)); hits != 0 {
		t.Fatalf("expired pending hits = %d", hits)
	}
}

func TestValidationAndCapacityAreBounded(t *testing.T) {
	now := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	service, _ := New(Config{MaxEntries: 1})
	valid := IssueRequest{SessionID: "session-12345678", EndpointClass: "other", Surface: SurfaceAPI, TTL: time.Minute}
	if _, err := service.Issue(valid, now); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Issue(valid, now); !errors.Is(err, ErrCapacity) {
		t.Fatalf("capacity error = %v", err)
	}
	invalid := []IssueRequest{
		{SessionID: "short", EndpointClass: "other", Surface: SurfaceAPI, TTL: time.Minute},
		{SessionID: "session-12345678", EndpointClass: "/raw/path", Surface: SurfaceAPI, TTL: time.Minute},
		{SessionID: "session-12345678", EndpointClass: "other", Surface: "html", TTL: time.Minute},
		{SessionID: "session-12345678", EndpointClass: "other", Surface: SurfaceAPI, TTL: time.Second},
	}
	for _, request := range invalid {
		if _, err := service.Issue(request, now); !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("request %+v error = %v", request, err)
		}
	}
	if err := service.Hit("raw-url-or-short-token", InteractionTouched, now); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("invalid hit error = %v", err)
	}
}
