package shadowanalysis

import (
	"errors"
	"time"

	"github.com/palisade-bot-defense/palisade/internal/shadowlog"
)

const (
	SchemaVersion              = "palisade.shadow-analysis.v1"
	DefaultMinDecisions        = uint64(1000)
	DefaultMinOutcomeCoverage  = 0.10
	DefaultMinConfirmedHumans  = uint64(100)
	DefaultMinConfirmedAbuse   = uint64(100)
	DefaultMaxChallengeRate    = 0.05
	DefaultMaxChallengeFailure = 0.10
	DefaultMinChallengeResults = uint64(100)
	DefaultMaxDistinctMetadata = 256
	DefaultTopReasonCodes      = 32
	MinimumRolloutWindow       = 24 * time.Hour
)

var ErrDistinctBudget = errors.New("shadow analysis distinct-value budget exceeded")

type Config struct {
	ScanLimits          shadowlog.ScanLimits
	MinDecisions        uint64
	MinOutcomeCoverage  float64
	MinConfirmedHumans  uint64
	MinConfirmedAbuse   uint64
	MaxChallengeRate    float64
	MaxChallengeFailure float64
	MinChallengeResults uint64
	MaxDistinctMetadata int
	TopReasonCodes      int
}

type Report struct {
	SchemaVersion   string                 `json:"schema_version"`
	Source          shadowlog.Verification `json:"source"`
	Readiness       Readiness              `json:"readiness"`
	Decisions       DecisionSummary        `json:"decisions"`
	Outcomes        OutcomeSummary         `json:"outcomes"`
	Scores          ScoreSummaries         `json:"scores"`
	Endpoints       []EndpointSummary      `json:"endpoints"`
	TopReasonCodes  []CountedValue         `json:"top_reason_codes"`
	PolicyVersions  []CountedValue         `json:"policy_versions"`
	ModelVersions   []CountedValue         `json:"model_versions"`
	CanaryRollouts  []CountedValue         `json:"canary_rollouts"`
	Recommendations []Recommendation       `json:"recommendations"`
}

type Readiness struct {
	State                string   `json:"state"`
	OperatorAction       string   `json:"operator_action"`
	AutomaticEnforcement bool     `json:"automatic_enforcement"`
	ReasonCodes          []string `json:"reason_codes"`
}

type DecisionSummary struct {
	Total                   uint64       `json:"total"`
	Enforced                ActionCounts `json:"enforced"`
	Computed                ActionCounts `json:"computed"`
	Modes                   ModeCounts   `json:"modes"`
	ShadowRiskyEnforcements uint64       `json:"shadow_risky_enforcements"`
	ComputedChallengeRate   float64      `json:"computed_challenge_rate"`
}

type ActionCounts struct {
	Allow     uint64 `json:"allow"`
	Observe   uint64 `json:"observe"`
	Throttle  uint64 `json:"throttle"`
	Challenge uint64 `json:"challenge"`
	Block     uint64 `json:"block"`
}

type ModeCounts struct {
	Shadow  uint64 `json:"shadow"`
	Canary  uint64 `json:"canary"`
	Enforce uint64 `json:"enforce"`
}

type OutcomeSummary struct {
	Total                  uint64  `json:"total"`
	Coverage               float64 `json:"coverage"`
	SuccessfulAction       uint64  `json:"successful_action"`
	ChallengePassed        uint64  `json:"challenge_passed"`
	ChallengeFailed        uint64  `json:"challenge_failed"`
	ChallengeAbandoned     uint64  `json:"challenge_abandoned"`
	HumanConfirmed         uint64  `json:"human_confirmed"`
	OperatorConfirmedAbuse uint64  `json:"operator_confirmed_abuse"`
	AppealRequested        uint64  `json:"appeal_requested"`
	FallbackUsed           uint64  `json:"fallback_used"`
	Unknown                uint64  `json:"unknown"`
	ChallengeResults       uint64  `json:"challenge_results"`
	ChallengeFailureRate   float64 `json:"challenge_failure_rate"`
}

type ScoreSummaries struct {
	AutomationRisk    ScoreSummary `json:"automation_risk"`
	AbuseIntentRisk   ScoreSummary `json:"abuse_intent_risk"`
	AccountContinuity ScoreSummary `json:"account_continuity"`
}

type ScoreSummary struct {
	Minimum float64 `json:"minimum"`
	Maximum float64 `json:"maximum"`
	Mean    float64 `json:"mean"`
}

type EndpointSummary struct {
	EndpointClass          string `json:"endpoint_class"`
	Decisions              uint64 `json:"decisions"`
	Outcomes               uint64 `json:"outcomes"`
	ComputedRiskyActions   uint64 `json:"computed_risky_actions"`
	HumanConfirmed         uint64 `json:"human_confirmed"`
	OperatorConfirmedAbuse uint64 `json:"operator_confirmed_abuse"`
}

type CountedValue struct {
	Value string `json:"value"`
	Count uint64 `json:"count"`
}

type Recommendation struct {
	Code        string  `json:"code"`
	Priority    string  `json:"priority"`
	Disposition string  `json:"disposition"`
	Metric      string  `json:"metric"`
	Observed    float64 `json:"observed"`
	Threshold   float64 `json:"threshold"`
	Unit        string  `json:"unit"`
	Message     string  `json:"message"`
}
