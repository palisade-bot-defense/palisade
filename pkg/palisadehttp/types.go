// Package palisadehttp provides reference net/http middleware for PALISADE.
// It sends only closed, normalized fields to the PALISADE service and never
// forwards an application request body, URL or query string.
package palisadehttp

import (
	"errors"
	"log/slog"
	"net/http"
	"time"
)

const (
	SessionCookieName               = "__Host-palisade_session"
	RedemptionCookieName            = "__Host-palisade_redemption"
	PendingCookieName               = "__Host-palisade_pending"
	DefaultPrefix                   = "/__palisade"
	DefaultMaxSessions              = 100_000
	DefaultMaxGrants                = 100_000
	DefaultStateTTL                 = 10 * time.Minute
	DefaultGrantTTL                 = 30 * time.Second
	DefaultPendingTTL               = 15 * time.Minute
	DefaultCoverageEvery            = uint64(100)
	DefaultCoverageInterval         = 30 * time.Second
	DefaultCrawlerRegistryReportTTL = 5 * time.Minute
)

var (
	ErrInvalidConfig         = errors.New("invalid PALISADE HTTP adapter configuration")
	ErrInvalidClassification = errors.New("invalid PALISADE request classification")
	ErrInvalidSignals        = errors.New("invalid PALISADE normalized signals")
	ErrInvalidOutcome        = errors.New("invalid PALISADE normalized outcome")
	ErrCoverageBusy          = errors.New("PALISADE coverage report is already in flight")
	ErrSessionRequired       = errors.New("PALISADE session cookie is required")
	ErrStateCapacity         = errors.New("PALISADE adapter state capacity exceeded")
	ErrInvalidPending        = errors.New("invalid PALISADE pending challenge")
	ErrInvalidResponse       = errors.New("invalid PALISADE service response")
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

type Signals struct {
	UserAgentPresent    bool    `json:"user_agent_present"`
	BrowserEventCount   int     `json:"browser_event_count"`
	HoneypotHits        int     `json:"honeypot_hits"`
	ChallengeVerdict    string  `json:"challenge_verdict,omitempty"`
	ExternalRiskScore   float64 `json:"external_risk_score,omitempty"`
	PolicyAlert         bool    `json:"policy_alert"`
	VerifiedBot         bool    `json:"verified_bot"`
	CrawlerClass        string  `json:"crawler_class,omitempty"`
	CrawlerVerification string  `json:"crawler_verification,omitempty"`
	TransportProtocol   string  `json:"transport_protocol"`
	TransportSecurity   string  `json:"transport_security"`
	ClientAddressSource string  `json:"client_address_source"`
}

type Classifier func(*http.Request) (Classification, error)
type SignalProvider func(*http.Request) (Signals, error)

type Config struct {
	BaseURL      string
	APIKey       string
	HTTPClient   *http.Client
	Classifier   Classifier
	Signals      SignalProvider
	FailureMode  FailureMode
	Prefix       string
	FallbackPath string
	MaxSessions  int
	MaxGrants    int
	StateTTL     time.Duration
	GrantTTL     time.Duration
	PendingTTL   time.Duration
	Logger       *slog.Logger
	// CoverageReporting sends only cumulative counts for completed requests
	// handled by this middleware. It never reports URLs, methods, identifiers or
	// request fields and is disabled unless explicitly enabled.
	CoverageReporting      bool
	CoverageReportEvery    uint64
	CoverageReportInterval time.Duration
	// TrustedProxyCIDRs authorizes only the direct TCP peers that may supply the
	// two configured normalization headers. Raw addresses never leave the adapter.
	TrustedProxyCIDRs     []string
	TrustedClientIPHeader string
	TrustedProtoHeader    string
	// CrawlerRegistry verifies a claimed crawler product against a local,
	// deployment-maintained static or signed expiring IP registry. The adapter
	// never sends the address or user-agent to PALISADE, and never performs a
	// network lookup in the hot path.
	CrawlerRegistry *CrawlerRegistry
	// CrawlerRegistryReporting enables explicit authenticated publication of
	// closed registry health through ReportCrawlerRegistryStatus. It does not
	// start a background task and never transmits registry entries.
	CrawlerRegistryReporting bool
	CrawlerRegistryReportTTL time.Duration
}

func StaticClassification(action, endpointClass string) Classifier {
	return func(*http.Request) (Classification, error) {
		return Classification{Action: action, EndpointClass: endpointClass}, nil
	}
}
