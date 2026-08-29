package palisadehttp

import (
	"context"
	"net/http"
	"time"
)

const (
	DefaultDecoyTTL = 5 * time.Minute
	MinimumDecoyTTL = 30 * time.Second
	MaximumDecoyTTL = 15 * time.Minute
)

type DecoySurface string

const (
	DecoySurfaceLink DecoySurface = "link"
	DecoySurfaceForm DecoySurface = "form"
	DecoySurfaceAPI  DecoySurface = "api"
)

type DecoyInteraction string

const (
	DecoyTouched   DecoyInteraction = "touched"
	DecoySubmitted DecoyInteraction = "submitted"
)

type DecoyCapability struct {
	Capability string    `json:"capability"`
	ExpiresAt  time.Time `json:"expires_at"`
}

// IssueDecoy asks PALISADE for a one-time capability using the browser's
// signed continuity cookie. The caller decides where to render the trap.
func (m *Middleware) IssueDecoy(ctx context.Context, cookie http.Cookie, endpointClass string, surface DecoySurface, ttl time.Duration) (DecoyCapability, error) {
	if ttl == 0 {
		ttl = DefaultDecoyTTL
	}
	if cookie.Name != SessionCookieName || cookie.Value == "" || len(cookie.Value) > 4096 || !validEndpointClass(endpointClass) ||
		!validDecoySurface(surface) || ttl < MinimumDecoyTTL || ttl > MaximumDecoyTTL || ttl%time.Second != 0 {
		return DecoyCapability{}, ErrInvalidDecoy
	}
	payload := struct {
		EndpointClass string       `json:"endpoint_class"`
		Surface       DecoySurface `json:"surface"`
		TTLSeconds    int          `json:"ttl_seconds"`
	}{EndpointClass: endpointClass, Surface: surface, TTLSeconds: int(ttl / time.Second)}
	var result DecoyCapability
	status, err := m.postJSON(ctx, "/v1/decoy/issue", payload, &cookie, true, &result)
	if err != nil {
		return DecoyCapability{}, err
	}
	if status != http.StatusCreated {
		return DecoyCapability{}, apiStatusError{status: status, op: "decoy issuance"}
	}
	now := m.now().UTC()
	if !validDecoyCapability(result.Capability) || !result.ExpiresAt.After(now) || result.ExpiresAt.After(now.Add(MaximumDecoyTTL+time.Second)) {
		return DecoyCapability{}, ErrInvalidResponse
	}
	return result, nil
}

// RecordDecoyHit consumes the opaque capability from a deployment-owned trap.
// It is backend-only and never forwards the application request itself.
func (m *Middleware) RecordDecoyHit(ctx context.Context, capability string, interaction DecoyInteraction) error {
	if !validDecoyCapability(capability) || !validDecoyInteraction(interaction) {
		return ErrInvalidDecoy
	}
	payload := struct {
		Capability  string           `json:"capability"`
		Interaction DecoyInteraction `json:"interaction"`
	}{Capability: capability, Interaction: interaction}
	status, err := m.postJSON(ctx, "/v1/decoy/hit", payload, nil, true, nil)
	if err != nil {
		return err
	}
	if status != http.StatusAccepted {
		return apiStatusError{status: status, op: "decoy hit"}
	}
	return nil
}

func validDecoySurface(value DecoySurface) bool {
	return value == DecoySurfaceLink || value == DecoySurfaceForm || value == DecoySurfaceAPI
}

func validDecoyInteraction(value DecoyInteraction) bool {
	return value == DecoyTouched || value == DecoySubmitted
}

func validDecoyCapability(value string) bool {
	if len(value) != 43 {
		return false
	}
	for _, character := range value {
		if !((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '_' || character == '-') {
			return false
		}
	}
	return true
}
