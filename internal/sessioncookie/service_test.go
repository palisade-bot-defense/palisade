package sessioncookie

import (
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestIssueAndVerifySecureCookie(t *testing.T) {
	service, err := New([]byte("0123456789abcdef0123456789abcdef"), DefaultTTL)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0).UTC()
	cookie, issued, err := service.Issue(now)
	if err != nil {
		t.Fatal(err)
	}
	if cookie.Name != CookieName || cookie.Path != "/" || !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf("unsafe cookie attributes: %+v", cookie)
	}
	verified, err := service.Verify(cookie.Value, now.Add(time.Minute))
	if err != nil || verified.SessionID != issued.SessionID {
		t.Fatalf("verify: claims=%+v err=%v", verified, err)
	}
	parts := strings.Split(cookie.Value, ".")
	parts[0] = "x" + parts[0][1:]
	if _, err := service.Verify(strings.Join(parts, "."), now); !errors.Is(err, ErrInvalidCookie) {
		t.Fatalf("tampered cookie error = %v", err)
	}
	if _, err := service.Verify(cookie.Value, now.Add(DefaultTTL)); !errors.Is(err, ErrExpiredCookie) {
		t.Fatalf("expired cookie error = %v", err)
	}
}

func TestCookieKeyIsDomainSeparatedFromProofSignature(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	service, err := New(secret, DefaultTTL)
	if err != nil {
		t.Fatal(err)
	}
	if string(service.key) == string(secret) {
		t.Fatal("session cookie reused the base HMAC key directly")
	}
}
