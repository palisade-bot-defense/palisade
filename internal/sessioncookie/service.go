package sessioncookie

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	CookieName = "__Host-palisade_session"
	DefaultTTL = 24 * time.Hour
	MaximumTTL = 7 * 24 * time.Hour
)

var (
	ErrInvalidCookie = errors.New("invalid session cookie")
	ErrExpiredCookie = errors.New("expired session cookie")
)

type Claims struct {
	Version   int    `json:"v"`
	SessionID string `json:"sid"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
}

type Service struct {
	key []byte
	ttl time.Duration
}

func New(secret []byte, ttl time.Duration) (*Service, error) {
	if len(secret) < 32 {
		return nil, errors.New("session cookie secret must contain at least 32 bytes")
	}
	if ttl <= 0 || ttl > MaximumTTL {
		return nil, errors.New("session cookie TTL must be positive and at most seven days")
	}
	derive := hmac.New(sha256.New, secret)
	_, _ = derive.Write([]byte("palisade:session-cookie:v1:key"))
	return &Service{key: derive.Sum(nil), ttl: ttl}, nil
}

func (s *Service) Issue(now time.Time) (http.Cookie, Claims, error) {
	random := make([]byte, 24)
	if _, err := rand.Read(random); err != nil {
		return http.Cookie{}, Claims{}, err
	}
	now = now.UTC()
	claims := Claims{
		Version:   1,
		SessionID: base64.RawURLEncoding.EncodeToString(random),
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(s.ttl).Unix(),
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return http.Cookie{}, Claims{}, err
	}
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	value := encoded + "." + s.sign(encoded)
	return http.Cookie{
		Name:     CookieName,
		Value:    value,
		Path:     "/",
		Expires:  time.Unix(claims.ExpiresAt, 0).UTC(),
		MaxAge:   int(s.ttl.Seconds()),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}, claims, nil
}

func (s *Service) Verify(value string, now time.Time) (Claims, error) {
	var claims Claims
	parts := strings.Split(value, ".")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" || len(value) > 4096 {
		return claims, ErrInvalidCookie
	}
	if !hmac.Equal([]byte(parts[1]), []byte(s.sign(parts[0]))) {
		return claims, ErrInvalidCookie
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || len(payload) > 1024 {
		return claims, ErrInvalidCookie
	}
	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&claims); err != nil {
		return Claims{}, ErrInvalidCookie
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Claims{}, ErrInvalidCookie
	}
	sessionBytes, err := base64.RawURLEncoding.DecodeString(claims.SessionID)
	if err != nil || len(sessionBytes) != 24 || claims.Version != 1 || claims.IssuedAt > now.Add(30*time.Second).Unix() || claims.ExpiresAt <= claims.IssuedAt {
		return Claims{}, ErrInvalidCookie
	}
	if claims.ExpiresAt <= now.Unix() {
		return Claims{}, ErrExpiredCookie
	}
	if claims.ExpiresAt-claims.IssuedAt > int64(MaximumTTL/time.Second) {
		return Claims{}, ErrInvalidCookie
	}
	return claims, nil
}

func (s *Service) sign(payload string) string {
	mac := hmac.New(sha256.New, s.key)
	_, _ = mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
