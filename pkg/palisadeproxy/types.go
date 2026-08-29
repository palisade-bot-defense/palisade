// Package palisadeproxy provides an independent, handler-based PALISADE
// reverse-proxy reference adapter. It sends only closed normalized fields to
// PALISADE and never forwards an application URL, query, body, cookie or raw
// user-agent.
package palisadeproxy

import (
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/palisade-bot-defense/palisade/pkg/palisadeedge"
)

const (
	SessionCookieName  = "__Host-palisade_session"
	DefaultPrefix      = "/__palisade"
	DefaultMaxSessions = 100_000
	DefaultStateTTL    = 10 * time.Minute
)

var (
	ErrInvalidConfig         = errors.New("invalid PALISADE reverse-proxy configuration")
	ErrInvalidClassification = errors.New("invalid PALISADE request classification")
	ErrInvalidSignals        = errors.New("invalid PALISADE normalized signals")
	ErrInvalidResponse       = errors.New("invalid PALISADE service response")
	ErrStateCapacity         = errors.New("PALISADE reverse-proxy state capacity exceeded")
)

type FailureMode string

const (
	FailOpen   FailureMode = "fail_open"
	FailClosed FailureMode = "fail_closed"
)

type Classification struct {
	Action           string
	EndpointClass    string
	EvaluationCohort string
}

// Signals is deliberately closed. Raw request fields cannot be represented by
// this type and therefore cannot accidentally enter the PALISADE wire payload.
type Signals struct {
	UserAgentPresent      bool    `json:"user_agent_present"`
	BrowserEventCount     int     `json:"browser_event_count"`
	HoneypotHits          int     `json:"honeypot_hits"`
	ChallengeVerdict      string  `json:"challenge_verdict,omitempty"`
	ExternalRiskScore     float64 `json:"external_risk_score,omitempty"`
	PolicyAlert           bool    `json:"policy_alert"`
	VerifiedBot           bool    `json:"verified_bot"`
	CrawlerClass          string  `json:"crawler_class,omitempty"`
	CrawlerVerification   string  `json:"crawler_verification,omitempty"`
	TransportProtocol     string  `json:"transport_protocol"`
	TransportSecurity     string  `json:"transport_security"`
	ClientAddressSource   string  `json:"client_address_source"`
	EdgeFingerprintClass  string  `json:"edge_fingerprint_class,omitempty"`
	EdgeFingerprintMethod string  `json:"edge_fingerprint_method,omitempty"`
	NetworkReputation     string  `json:"network_reputation,omitempty"`
	NetworkType           string  `json:"network_type,omitempty"`
}

type Classifier func(*http.Request) (Classification, error)
type SignalProvider func(*http.Request) (Signals, error)

type Config struct {
	BaseURL     string
	APIKey      string
	HTTPClient  *http.Client
	Upstream    http.Handler
	Classifier  Classifier
	Signals     SignalProvider
	FailureMode FailureMode
	Prefix      string
	MaxSessions int
	StateTTL    time.Duration
	Logger      *slog.Logger
	// EdgeSignals verifies a short-lived HMAC envelope from an explicitly
	// allowlisted direct peer and supplies only closed normalized classes.
	EdgeSignals *palisadeedge.Verifier
}

func StaticClassification(action, endpointClass string) Classifier {
	return func(*http.Request) (Classification, error) {
		return Classification{Action: action, EndpointClass: endpointClass}, nil
	}
}
