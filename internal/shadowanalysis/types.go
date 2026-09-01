package shadowanalysis

import (
	"errors"
	"time"

	"github.com/palisade-human-trust/palisade/internal/core"
	"github.com/palisade-human-trust/palisade/internal/shadowlog"
)

const (
	SchemaVersion              = "palisade.shadow-analysis.v4"
	DefaultMinDecisions        = uint64(1000)
	DefaultMinOutcomeCoverage  = 0.10
	DefaultMinConfirmedHumans  = uint64(100)
	DefaultMinConfirmedAbuse   = uint64(100)
	DefaultMaxChallengeRate    = 0.05
	DefaultMaxChallengeFailure = 0.10
	DefaultMinChallengeResults = uint64(100)
	DefaultMaxDistinctMetadata = 256
	DefaultTopReasonCodes      = 32
	DefaultMaxDecisionLinks    = 1_000_000
	MaximumDecisionLinks       = 5_000_000
	MinimumRolloutWindow       = 24 * time.Hour
	ChallengeOutcomeMaturity   = 15 * time.Minute
)

var (
	ErrDistinctBudget = errors.New("shadow analysis distinct-value budget exceeded")
	ErrLinkBudget     = errors.New("shadow analysis decision-link budget exceeded")
)

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
	MaxDecisionLinks    int
}

type Report struct {
	SchemaVersion          string                  `json:"schema_version"`
	Source                 shadowlog.Verification  `json:"source"`
	Readiness              Readiness               `json:"readiness"`
	Decisions              DecisionSummary         `json:"decisions"`
	Outcomes               OutcomeSummary          `json:"outcomes"`
	Scores                 ScoreSummaries          `json:"scores"`
	Endpoints              []EndpointSummary       `json:"endpoints"`
	TopReasonCodes         []CountedValue          `json:"top_reason_codes"`
	PolicyVersions         []CountedValue          `json:"policy_versions"`
	ModelVersions          []CountedValue          `json:"model_versions"`
	CanaryRollouts         []CountedValue          `json:"canary_rollouts"`
	CanaryComparisons      []CanaryComparison      `json:"canary_comparisons"`
	CanaryChallengeBudgets []CanaryChallengeBudget `json:"canary_challenge_budgets"`
	Linkage                LinkageSummary          `json:"linkage"`
	EvaluationSlices       []EvaluationSlice       `json:"evaluation_slices"`
	Recommendations        []Recommendation        `json:"recommendations"`
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
	Delay     uint64 `json:"delay,omitempty"`
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
	EndpointClass          string             `json:"endpoint_class"`
	Decisions              uint64             `json:"decisions"`
	Outcomes               uint64             `json:"outcomes"`
	ComputedRiskyActions   uint64             `json:"computed_risky_actions"`
	HumanConfirmed         uint64             `json:"human_confirmed"`
	OperatorConfirmedAbuse uint64             `json:"operator_confirmed_abuse"`
	OutcomeKinds           OutcomeKindCounts  `json:"outcome_kinds"`
	Evaluation             EndpointEvaluation `json:"evaluation"`
	LinkedEvaluation       LinkedEvaluation   `json:"linked_evaluation"`
}

type LinkageSummary struct {
	UniqueDecisionIDs             uint64             `json:"unique_decision_ids"`
	DuplicateDecisionIDs          uint64             `json:"duplicate_decision_ids"`
	DuplicateDecisionRecords      uint64             `json:"duplicate_decision_records"`
	OutcomeEventsWithDecisionID   uint64             `json:"outcome_events_with_decision_id"`
	LegacyOutcomeEventsWithoutID  uint64             `json:"legacy_outcome_events_without_id"`
	MatchedOutcomeEvents          uint64             `json:"matched_outcome_events"`
	UnknownDecisionOutcomeEvents  uint64             `json:"unknown_decision_outcome_events"`
	EndpointMismatchOutcomeEvents uint64             `json:"endpoint_mismatch_outcome_events"`
	DuplicateOutcomeEvents        uint64             `json:"duplicate_outcome_events"`
	ConfirmedDecisionLabels       uint64             `json:"confirmed_decision_labels"`
	ConfirmedLabelCoverage        ProportionEstimate `json:"confirmed_label_coverage"`
	AmbiguousGroundTruthDecisions uint64             `json:"ambiguous_ground_truth_decisions"`
	AmbiguousChallengeDecisions   uint64             `json:"ambiguous_challenge_decisions"`
}

type ConfusionMatrix struct {
	TruePositive  uint64 `json:"true_positive"`
	FalsePositive uint64 `json:"false_positive"`
	TrueNegative  uint64 `json:"true_negative"`
	FalseNegative uint64 `json:"false_negative"`
}

type LinkedEvaluation struct {
	Decisions                  uint64             `json:"decisions"`
	ConfirmedLabels            uint64             `json:"confirmed_labels"`
	AmbiguousGroundTruth       uint64             `json:"ambiguous_ground_truth"`
	Confusion                  ConfusionMatrix    `json:"confusion"`
	FalsePositiveRate          ProportionEstimate `json:"false_positive_rate"`
	AbuseRecall                ProportionEstimate `json:"abuse_recall"`
	AbusePrecision             ProportionEstimate `json:"abuse_precision"`
	MatureChallenges           uint64             `json:"mature_challenges"`
	ChallengePassed            uint64             `json:"challenge_passed"`
	ChallengeFailed            uint64             `json:"challenge_failed"`
	ChallengeAbandoned         uint64             `json:"challenge_abandoned"`
	FallbackUsed               uint64             `json:"fallback_used"`
	UnresolvedMatureChallenges uint64             `json:"unresolved_mature_challenges"`
	AmbiguousChallengeOutcomes uint64             `json:"ambiguous_challenge_outcomes"`
	ChallengePassRate          ProportionEstimate `json:"challenge_pass_rate"`
	ChallengeFailureRate       ProportionEstimate `json:"challenge_failure_rate"`
	ChallengeAbandonmentRate   ProportionEstimate `json:"challenge_abandonment_rate"`
	FallbackRate               ProportionEstimate `json:"fallback_rate"`
}

type EvaluationSlice struct {
	EndpointClass    string                `json:"endpoint_class"`
	EvaluationCohort core.EvaluationCohort `json:"evaluation_cohort"`
	Evaluation       LinkedEvaluation      `json:"evaluation"`
}

type OutcomeKindCounts struct {
	SuccessfulAction       uint64 `json:"successful_action"`
	ChallengePassed        uint64 `json:"challenge_passed"`
	ChallengeFailed        uint64 `json:"challenge_failed"`
	ChallengeAbandoned     uint64 `json:"challenge_abandoned"`
	HumanConfirmed         uint64 `json:"human_confirmed"`
	OperatorConfirmedAbuse uint64 `json:"operator_confirmed_abuse"`
	AppealRequested        uint64 `json:"appeal_requested"`
	FallbackUsed           uint64 `json:"fallback_used"`
	Unknown                uint64 `json:"unknown"`
}

type EndpointEvaluation struct {
	ComputedRiskyRate        ProportionEstimate `json:"computed_risky_rate"`
	ChallengeFailureRate     ProportionEstimate `json:"challenge_failure_rate"`
	ChallengeAbandonmentRate ProportionEstimate `json:"challenge_abandonment_rate"`
	FallbackOutcomeShare     ProportionEstimate `json:"fallback_outcome_share"`
	AppealOutcomeShare       ProportionEstimate `json:"appeal_outcome_share"`
	UnknownOutcomeShare      ProportionEstimate `json:"unknown_outcome_share"`
	ConfirmedLabels          uint64             `json:"confirmed_labels"`
	AbuseLabelShare          ProportionEstimate `json:"abuse_label_share"`
}

type ProportionEstimate struct {
	Count   uint64  `json:"count"`
	Total   uint64  `json:"total"`
	Rate    float64 `json:"rate"`
	Lower95 float64 `json:"lower_95"`
	Upper95 float64 `json:"upper_95"`
}

type DifferenceEstimate struct {
	Estimate float64 `json:"estimate"`
	Lower95  float64 `json:"lower_95"`
	Upper95  float64 `json:"upper_95"`
}

type CanaryComparison struct {
	RolloutID              string             `json:"rollout_id"`
	EndpointClass          string             `json:"endpoint_class"`
	Comparable             bool               `json:"comparable"`
	ShadowDecisions        uint64             `json:"shadow_decisions"`
	CanaryDecisions        uint64             `json:"canary_decisions"`
	ShadowComputedRisky    ProportionEstimate `json:"shadow_computed_risky"`
	CanaryComputedRisky    ProportionEstimate `json:"canary_computed_risky"`
	CanaryEnforcedRisky    ProportionEstimate `json:"canary_enforced_risky"`
	ComputedRiskDifference DifferenceEstimate `json:"computed_risk_difference"`
}

// CanaryChallengeBudget contains only mature, uniquely linked challenge
// outcomes for one exact signed rollout and endpoint. It deliberately excludes
// raw decision IDs and unrelated historical challenge outcomes.
type CanaryChallengeBudget struct {
	RolloutID                  string             `json:"rollout_id"`
	EndpointClass              string             `json:"endpoint_class"`
	MatureChallenges           uint64             `json:"mature_challenges"`
	ChallengePassed            uint64             `json:"challenge_passed"`
	ChallengeFailed            uint64             `json:"challenge_failed"`
	ChallengeAbandoned         uint64             `json:"challenge_abandoned"`
	FallbackUsed               uint64             `json:"fallback_used"`
	UnresolvedMatureChallenges uint64             `json:"unresolved_mature_challenges"`
	AmbiguousChallengeOutcomes uint64             `json:"ambiguous_challenge_outcomes"`
	TerminalOutcomeCoverage    ProportionEstimate `json:"terminal_outcome_coverage"`
	ChallengeAbandonmentRate   ProportionEstimate `json:"challenge_abandonment_rate"`
	FallbackRate               ProportionEstimate `json:"fallback_rate"`
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
