package shadowlog

import (
	"errors"
	"regexp"
	"time"

	"github.com/palisade-bot-defense/palisade/internal/core"
)

const (
	SchemaVersion                = "palisade.shadow-record.v3"
	PreviousSchemaVersion        = "palisade.shadow-record.v2"
	LegacySchemaVersion          = "palisade.shadow-record.v1"
	DefaultMaxFileBytes          = int64(64 << 20)
	DefaultMaxFileAge            = time.Hour
	DefaultRetention             = 7 * 24 * time.Hour
	DefaultQueueSize             = 4096
	DefaultScanMaxFiles          = uint64(4096)
	DefaultScanMaxRecords        = uint64(10_000_000)
	DefaultScanMaxEncryptedBytes = int64(16 << 30)
	MaximumScanMaxFiles          = uint64(1_000_000)
	MaximumScanMaxRecords        = uint64(100_000_000)
	MaximumScanMaxEncryptedBytes = int64(1 << 40)
)

var (
	ErrQueueFull       = errors.New("shadow log queue is full")
	ErrClosed          = errors.New("shadow log is closed")
	ErrWriterFailed    = errors.New("shadow log writer failed")
	ErrInvalidOutcome  = errors.New("invalid shadow outcome")
	ErrScanFileLimit   = errors.New("shadow log scan file budget exceeded")
	ErrScanRecordLimit = errors.New("shadow log scan record budget exceeded")
	ErrScanByteLimit   = errors.New("shadow log scan encrypted-byte budget exceeded")
	stableValue        = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,128}$`)
)

type ScanLimits struct {
	MaxFiles          uint64
	MaxRecords        uint64
	MaxEncryptedBytes int64
}

type Config struct {
	Directory    string
	KeyFile      string
	MaxFileBytes int64
	MaxFileAge   time.Duration
	Retention    time.Duration
	QueueSize    int
	Now          func() time.Time
}

type Record struct {
	SchemaVersion string         `json:"schema_version"`
	Kind          string         `json:"kind"`
	RecordedAt    string         `json:"recorded_at"`
	SessionKey    string         `json:"session_key"`
	Decision      *DecisionEntry `json:"decision,omitempty"`
	Outcome       *OutcomeEntry  `json:"outcome,omitempty"`
}

type DecisionEntry struct {
	DecisionID       string                `json:"decision_id"`
	RequestAction    string                `json:"request_action"`
	EndpointClass    string                `json:"endpoint_class"`
	EvaluationCohort core.EvaluationCohort `json:"evaluation_cohort,omitempty"`
	Action           core.Action           `json:"action"`
	ComputedAction   core.Action           `json:"computed_action"`
	Mode             core.RuntimeMode      `json:"mode"`
	RolloutID        string                `json:"rollout_id,omitempty"`
	Scores           core.Scores           `json:"scores"`
	ReasonCodes      []string              `json:"reason_codes"`
	PolicyVersion    string                `json:"policy_version"`
	ModelVersion     string                `json:"model_version"`
}

type OutcomeRequest struct {
	SessionID     string `json:"session_id"`
	DecisionID    string `json:"decision_id"`
	EndpointClass string `json:"endpoint_class"`
	Outcome       string `json:"outcome"`
	Provenance    string `json:"provenance"`
	Confidence    string `json:"confidence"`
}

type OutcomeEntry struct {
	DecisionID    string `json:"decision_id,omitempty"`
	EndpointClass string `json:"endpoint_class"`
	Outcome       string `json:"outcome"`
	Provenance    string `json:"provenance"`
	Confidence    string `json:"confidence"`
}

type Verification struct {
	Files          uint64 `json:"files"`
	Records        uint64 `json:"records"`
	Decisions      uint64 `json:"decisions"`
	Outcomes       uint64 `json:"outcomes"`
	EncryptedBytes int64  `json:"encrypted_bytes"`
	FirstAt        string `json:"first_at,omitempty"`
	LastAt         string `json:"last_at,omitempty"`
}

func (request OutcomeRequest) Validate() error {
	return validateOutcomeRequest(request, true)
}

func validateOutcomeRequest(request OutcomeRequest, requireDecisionID bool) error {
	if !validSessionID(request.SessionID) {
		return ErrInvalidOutcome
	}
	if (requireDecisionID && request.DecisionID == "") || (request.DecisionID != "" && !stableValue.MatchString(request.DecisionID)) {
		return ErrInvalidOutcome
	}
	if normalizeEndpoint(request.EndpointClass) == "other" && request.EndpointClass != "other" {
		return ErrInvalidOutcome
	}
	switch request.Outcome {
	case "human_confirmed":
		if (request.Provenance == "authenticated_account" || request.Provenance == "operator_review") && request.Confidence == "confirmed" {
			return nil
		}
	case "operator_confirmed_abuse":
		if request.Provenance == "operator_review" && request.Confidence == "confirmed" {
			return nil
		}
	case "successful_action", "challenge_passed", "challenge_failed", "challenge_abandoned":
		if request.Provenance == "server_observed" && request.Confidence == "confirmed" {
			return nil
		}
	case "appeal_requested", "fallback_used":
		if (request.Provenance == "server_observed" || request.Provenance == "user_feedback") && request.Confidence == "confirmed" {
			return nil
		}
	case "unknown":
		if request.Provenance == "unknown" && request.Confidence == "unknown" {
			return nil
		}
	}
	return ErrInvalidOutcome
}

func validSessionID(value string) bool {
	return len(value) >= 8 && len(value) <= 128 && stableValue.MatchString(value)
}

func normalizeRequestAction(value string) string {
	switch value {
	case "read", "write", "create", "update", "delete", "search", "compare", "login", "logout", "register", "checkout", "purchase", "events", "other":
		return value
	default:
		return "other"
	}
}

func normalizeEndpoint(value string) string {
	switch value {
	case "public_content", "compare_index", "compare_noindex", "challenge_worker", "other_public", "account", "login", "checkout", "other":
		return value
	default:
		return "other"
	}
}
