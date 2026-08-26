package token

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

var (
	ErrInvalidToken = errors.New("invalid proof token")
	ErrExpiredToken = errors.New("expired proof token")
	ErrReplayToken  = errors.New("proof token already consumed")
)

type Claims struct {
	Version   int    `json:"v"`
	SessionID string `json:"sid"`
	Action    string `json:"act"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
	Nonce     string `json:"n"`
}

type NonceStore interface {
	Consume(nonce string, expiresAt, now time.Time) bool
}

type Service struct {
	secret []byte
	nonces NonceStore
}

func NewService(secret []byte, nonces NonceStore) (*Service, error) {
	if len(secret) < 32 {
		return nil, errors.New("HMAC secret must contain at least 32 bytes")
	}
	if nonces == nil {
		return nil, errors.New("nonce store is required")
	}
	return &Service{secret: append([]byte(nil), secret...), nonces: nonces}, nil
}

func (s *Service) Issue(sessionID, action string, ttl time.Duration, now time.Time) (string, error) {
	if sessionID == "" || action == "" {
		return "", errors.New("session and action are required")
	}
	if ttl <= 0 || ttl > 5*time.Minute {
		return "", errors.New("token TTL must be between zero and five minutes")
	}
	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		return "", fmt.Errorf("create nonce: %w", err)
	}
	claims := Claims{
		Version:   1,
		SessionID: sessionID,
		Action:    action,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(ttl).Unix(),
		Nonce:     base64.RawURLEncoding.EncodeToString(nonceBytes),
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("encode claims: %w", err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	return encoded + "." + s.sign(encoded), nil
}

func (s *Service) VerifyAndConsume(raw, expectedSession, expectedAction string, now time.Time) (Claims, error) {
	var claims Claims
	parts := strings.Split(raw, ".")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return claims, ErrInvalidToken
	}
	expectedSignature := s.sign(parts[0])
	if !hmac.Equal([]byte(parts[1]), []byte(expectedSignature)) {
		return claims, ErrInvalidToken
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || len(payload) > 2048 {
		return claims, ErrInvalidToken
	}
	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&claims); err != nil {
		return Claims{}, ErrInvalidToken
	}
	if claims.Version != 1 || claims.SessionID != expectedSession || claims.Action != expectedAction || claims.Nonce == "" {
		return Claims{}, ErrInvalidToken
	}
	if claims.IssuedAt > now.Add(30*time.Second).Unix() || claims.ExpiresAt <= now.Unix() {
		return Claims{}, ErrExpiredToken
	}
	expiry := time.Unix(claims.ExpiresAt, 0)
	if !s.nonces.Consume(claims.Nonce, expiry, now) {
		return Claims{}, ErrReplayToken
	}
	return claims, nil
}

func (s *Service) sign(payload string) string {
	mac := hmac.New(sha256.New, s.secret)
	_, _ = mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

type MemoryNonceStore struct {
	mu      sync.Mutex
	entries map[string]time.Time
	ops     uint64
}

func NewMemoryNonceStore() *MemoryNonceStore {
	return &MemoryNonceStore{entries: make(map[string]time.Time)}
}

func (m *MemoryNonceStore) Consume(nonce string, expiresAt, now time.Time) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ops++
	if m.ops%256 == 0 {
		for key, expiry := range m.entries {
			if !expiry.After(now) {
				delete(m.entries, key)
			}
		}
	}
	if expiry, exists := m.entries[nonce]; exists && expiry.After(now) {
		return false
	}
	m.entries[nonce] = expiresAt
	return true
}
