package core

import (
	"time"

	"github.com/palisade-human-trust/palisade/pkg/palisadecontract"
)

type Dimension string

const (
	DimensionAutomation Dimension = "automation"
	DimensionIntent     Dimension = "intent"
	DimensionContinuity Dimension = "continuity"
)

type Direction int

const (
	DirectionBenign     Direction = -1
	DirectionSuspicious Direction = 1
)

type Evidence struct {
	Code       string        `json:"code"`
	Detector   string        `json:"detector"`
	Dimension  Dimension     `json:"dimension"`
	Direction  Direction     `json:"direction"`
	Strength   float64       `json:"strength"`
	Confidence float64       `json:"confidence"`
	TTL        time.Duration `json:"-"`
}

type Observations struct {
	UserAgentPresent      bool                `json:"user_agent_present"`
	BrowserEventCount     int                 `json:"browser_event_count"`
	HoneypotHits          int                 `json:"honeypot_hits"`
	ChallengeVerdict      string              `json:"challenge_verdict,omitempty"`
	ExternalRiskScore     float64             `json:"external_risk_score,omitempty"`
	PolicyAlert           bool                `json:"policy_alert"`
	VerifiedBot           bool                `json:"verified_bot"`
	CrawlerClass          CrawlerClass        `json:"crawler_class,omitempty"`
	CrawlerVerification   CrawlerVerification `json:"crawler_verification,omitempty"`
	TransportProtocol     string              `json:"transport_protocol,omitempty"`
	TransportSecurity     string              `json:"transport_security,omitempty"`
	ClientAddressSource   string              `json:"client_address_source,omitempty"`
	EdgeFingerprintClass  string              `json:"edge_fingerprint_class,omitempty"`
	EdgeFingerprintMethod string              `json:"edge_fingerprint_method,omitempty"`
	NetworkReputation     string              `json:"network_reputation,omitempty"`
	NetworkType           string              `json:"network_type,omitempty"`
	ServerSessionVerified bool                `json:"-"`
	// VerifiedDecoyHits is populated only by PALISADE's in-process decoy store.
	// A JSON caller cannot claim this stronger provenance.
	VerifiedDecoyHits int `json:"-"`
	// BrowserEventsVerified is set only by a trusted in-process boundary after
	// reading the server-side event store. A caller-supplied count must never
	// create benign continuity evidence by itself.
	BrowserEventsVerified bool `json:"-"`
}

// ValidEdgeIntelligence accepts only deployment-normalized classes. Raw JA4,
// HTTP/2 fingerprint, ASN, IP, vendor label or free-form reputation values are
// deliberately outside the PALISADE decision contract.
func ValidEdgeIntelligence(class, method, reputation, networkType string) bool {
	return palisadecontract.ValidEdgeIntelligence(class, method, reputation, networkType)
}

// CrawlerClass is an operator-controlled purpose class, not an identity claim.
// Training crawlers are deliberately distinct from search and answer-engine
// retrieval so deployments can apply their robots and licensing policy.
type CrawlerClass string

const (
	CrawlerClassUnknown            CrawlerClass = "unknown"
	CrawlerClassSearchIndexer      CrawlerClass = "search_indexer"
	CrawlerClassAnswerEngine       CrawlerClass = "answer_engine"
	CrawlerClassTrainingCrawler    CrawlerClass = "training_crawler"
	CrawlerClassUserTriggeredAgent CrawlerClass = "user_triggered_agent"
	CrawlerClassPreview            CrawlerClass = "preview"
	CrawlerClassMonitoring         CrawlerClass = "monitoring"
	CrawlerClassOther              CrawlerClass = "other"
)

type CrawlerVerification string

const (
	CrawlerVerificationUnknown       CrawlerVerification = "unknown"
	CrawlerVerificationIPUARegistry  CrawlerVerification = "ip_ua_registry"
	CrawlerVerificationFCrDNSUA      CrawlerVerification = "fcrdns_ua"
	CrawlerVerificationHTTPSignature CrawlerVerification = "http_signature"
)

func NormalizeCrawlerClass(value CrawlerClass) (CrawlerClass, bool) {
	if value == "" {
		return CrawlerClassUnknown, true
	}
	if !palisadecontract.ValidCrawlerClass(string(value)) {
		return "", false
	}
	return value, true
}

func NormalizeCrawlerVerification(value CrawlerVerification) (CrawlerVerification, bool) {
	if value == "" {
		return CrawlerVerificationUnknown, true
	}
	if !palisadecontract.ValidCrawlerVerification(string(value)) {
		return "", false
	}
	return value, true
}

// VerifiedPublicCrawler is the sole gate that lets beneficial automation
// neutralize automation risk. Identity, verification and public scope must all
// agree; private/sensitive endpoints and training crawlers never qualify.
func VerifiedPublicCrawler(observations Observations, endpointClass string) bool {
	if !observations.VerifiedBot || !publicCrawlerEndpoint(endpointClass) {
		return false
	}
	verification, valid := NormalizeCrawlerVerification(observations.CrawlerVerification)
	if !valid || verification == CrawlerVerificationUnknown {
		return false
	}
	class, valid := NormalizeCrawlerClass(observations.CrawlerClass)
	if !valid {
		return false
	}
	switch class {
	case CrawlerClassSearchIndexer, CrawlerClassAnswerEngine,
		CrawlerClassUserTriggeredAgent, CrawlerClassPreview:
		return true
	default:
		return false
	}
}

func publicCrawlerEndpoint(value string) bool {
	switch value {
	case "public_content", "compare_index", "other_public":
		return true
	default:
		return false
	}
}

// EvaluationCohort is a coarse, deployment-supplied measurement slice. It is
// never detector evidence and must not encode a browser fingerprint, medical
// condition, account identity or other free-form client attribute.
type EvaluationCohort string

const (
	EvaluationCohortStandard      EvaluationCohort = "standard"
	EvaluationCohortReducedMotion EvaluationCohort = "reduced_motion"
	EvaluationCohortKeyboardOnly  EvaluationCohort = "keyboard_only"
	EvaluationCohortFallbackPath  EvaluationCohort = "fallback_path"
	EvaluationCohortSensorMissing EvaluationCohort = "sensor_missing"
	EvaluationCohortUnknown       EvaluationCohort = "unknown"
)

func NormalizeEvaluationCohort(value EvaluationCohort) (EvaluationCohort, bool) {
	if value == "" {
		return EvaluationCohortUnknown, true
	}
	if !palisadecontract.ValidEvaluationCohort(string(value)) {
		return "", false
	}
	return value, true
}

type DecisionRequest struct {
	SessionID        string           `json:"session_id"`
	Action           string           `json:"action"`
	EndpointClass    string           `json:"endpoint_class"`
	EvaluationCohort EvaluationCohort `json:"evaluation_cohort,omitempty"`
	Sequence         uint64           `json:"sequence"`
	ProofToken       string           `json:"proof_token,omitempty"`
	Observations     Observations     `json:"observations"`
}

type SessionSnapshot struct {
	SessionID               string    `json:"session_id"`
	FirstSeen               time.Time `json:"first_seen"`
	LastSeen                time.Time `json:"last_seen"`
	RequestCount            uint64    `json:"request_count"`
	LastSequence            uint64    `json:"last_sequence"`
	MaxSequenceGap          uint64    `json:"max_sequence_gap"`
	DistinctEndpointClasses uint8     `json:"distinct_endpoint_classes"`
	EndpointTransitions     uint64    `json:"endpoint_transitions"`
	RecentEnforcements      uint8     `json:"recent_enforcements"`
	PrematureRetries        uint8     `json:"premature_retries"`
}

func ValidEndpointClass(value string) bool {
	return palisadecontract.ValidEndpointClass(value)
}

// ValidRequestAction accepts only deployment-independent action classes. It
// deliberately excludes paths, methods and application-specific free text so
// trusted adapters cannot accidentally turn request metadata into a signal.
func ValidRequestAction(value string) bool {
	return palisadecontract.ValidRequestAction(value)
}

type DetectorInput struct {
	Request DecisionRequest
	Session SessionSnapshot
}

type Scores struct {
	AutomationRisk    float64 `json:"automation_risk"`
	AbuseIntentRisk   float64 `json:"abuse_intent_risk"`
	AccountContinuity float64 `json:"account_continuity"`
}

type Action string

const (
	ActionAllow     Action = "allow"
	ActionObserve   Action = "observe"
	ActionDelay     Action = "delay"
	ActionThrottle  Action = "throttle"
	ActionChallenge Action = "challenge"
	ActionBlock     Action = "block"
)

type RuntimeMode string

const (
	RuntimeModeShadow  RuntimeMode = "shadow"
	RuntimeModeCanary  RuntimeMode = "canary"
	RuntimeModeEnforce RuntimeMode = "enforce"
)

const ReasonShadowActionOverridden = "SHADOW_ACTION_OVERRIDDEN"

type EnforcementDirective struct {
	Handling          string    `json:"handling"`
	HTTPStatus        int       `json:"http_status"`
	RetryAfterSeconds int       `json:"retry_after_seconds,omitempty"`
	ExpiresAt         time.Time `json:"expires_at"`
}

type Decision struct {
	DecisionID     string               `json:"decision_id"`
	Action         Action               `json:"action"`
	ComputedAction Action               `json:"computed_action"`
	Mode           RuntimeMode          `json:"mode"`
	RolloutID      string               `json:"rollout_id,omitempty"`
	Directive      EnforcementDirective `json:"directive"`
	Scores         Scores               `json:"scores"`
	ReasonCodes    []string             `json:"reason_codes"`
	Evidence       []Evidence           `json:"evidence"`
	PolicyVersion  string               `json:"policy_version"`
	ModelVersion   string               `json:"model_version"`
	ExpiresAt      time.Time            `json:"expires_at"`
}
