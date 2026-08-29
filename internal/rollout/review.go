package rollout

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"math/bits"
	"reflect"
	"regexp"
	"sort"
	"time"

	"github.com/palisade-bot-defense/palisade/internal/core"
	"github.com/palisade-bot-defense/palisade/internal/shadowanalysis"
)

const (
	ReviewSchemaVersion        = "palisade.rollout-review.v4"
	ReviewStateHold            = "hold"
	ReviewStateCandidate       = "review_candidate"
	ReviewGatePass             = "pass"
	ReviewGateHold             = "hold"
	DefaultCanaryBasisPoints   = uint32(100)
	DefaultCanaryDuration      = 24 * time.Hour
	DefaultEnforcementDuration = 12 * time.Hour
)

var (
	ErrInvalidReview = errors.New("invalid rollout review proposal")
	reviewGateCode   = regexp.MustCompile(`^[A-Z][A-Z0-9_]{2,63}$`)
)

type ReviewProposal struct {
	SchemaVersion        string           `json:"schema_version"`
	SourceReportSHA256   string           `json:"source_report_sha256"`
	SourceSchemaVersion  string           `json:"source_schema_version"`
	SourceFirstAt        string           `json:"source_first_at"`
	SourceLastAt         string           `json:"source_last_at"`
	PolicyVersion        string           `json:"policy_version"`
	ModelVersion         string           `json:"model_version"`
	State                string           `json:"state"`
	AutomaticActivation  bool             `json:"automatic_activation"`
	RequestedStage       core.RuntimeMode `json:"requested_stage"`
	PredecessorRolloutID string           `json:"predecessor_rollout_id"`
	RecommendedScope     *ReviewScope     `json:"recommended_scope"`
	Gates                []ReviewGate     `json:"gates"`
	OperatorChecklist    []string         `json:"operator_checklist"`
}

type ReviewScope struct {
	EndpointClasses             []string    `json:"endpoint_classes"`
	MaxAction                   core.Action `json:"max_action"`
	CanaryBasisPoints           uint32      `json:"canary_basis_points"`
	DurationSeconds             int64       `json:"duration_seconds"`
	ThrottleSeconds             int         `json:"throttle_seconds"`
	ChallengeTTLSeconds         int         `json:"challenge_ttl_seconds"`
	BlockSeconds                int         `json:"block_seconds"`
	MinMatureChallenges         uint64      `json:"min_mature_challenges"`
	MinChallengeOutcomeCoverage float64     `json:"min_challenge_outcome_coverage"`
	MaxChallengeAbandonmentRate float64     `json:"max_challenge_abandonment_rate"`
	MaxChallengeFallbackRate    float64     `json:"max_challenge_fallback_rate"`
}

type ReviewGate struct {
	Code     string `json:"code"`
	Status   string `json:"status"`
	Observed string `json:"observed"`
	Required string `json:"required"`
	Message  string `json:"message"`
}

type ReviewOptions struct {
	Stage                core.RuntimeMode
	PredecessorRolloutID string
}

func BuildReviewProposal(report shadowanalysis.Report, reportBytes []byte, options ReviewOptions) (ReviewProposal, error) {
	if err := validateReportBytes(report, reportBytes, false); err != nil {
		return ReviewProposal{}, err
	}
	if options.Stage != core.RuntimeModeCanary && options.Stage != core.RuntimeModeEnforce {
		return ReviewProposal{}, fmt.Errorf("%w: requested stage must be canary or enforce", ErrInvalidReview)
	}
	if (options.Stage == core.RuntimeModeCanary && options.PredecessorRolloutID != "") ||
		(options.Stage == core.RuntimeModeEnforce && !stableID.MatchString(options.PredecessorRolloutID)) {
		return ReviewProposal{}, fmt.Errorf("%w: predecessor must be empty for canary and a stable ID for enforce", ErrInvalidReview)
	}

	proposal := ReviewProposal{
		SchemaVersion:        ReviewSchemaVersion,
		SourceReportSHA256:   hex.EncodeToString(sha256Sum(reportBytes)),
		SourceSchemaVersion:  report.SchemaVersion,
		SourceFirstAt:        report.Source.FirstAt,
		SourceLastAt:         report.Source.LastAt,
		State:                ReviewStateCandidate,
		AutomaticActivation:  false,
		RequestedStage:       options.Stage,
		PredecessorRolloutID: options.PredecessorRolloutID,
		OperatorChecklist: []string{
			"confirm_endpoint_confidence_intervals",
			"confirm_accessible_fallback_and_support",
			"confirm_origin_adapter_fail_safe_behavior",
			"confirm_rollback_owner_and_command",
		},
	}

	windowSeconds := sourceWindowSeconds(report.Source.FirstAt, report.Source.LastAt)
	proposal.addGate("REPORT_READINESS", report.Readiness.State == "operator_review_candidate" && report.Readiness.OperatorAction == "review_reversible_canary" && !report.Readiness.AutomaticEnforcement,
		report.Readiness.State, "operator_review_candidate", "The validated aggregate report must nominate only operator review of a reversible canary.")
	proposal.addGate("OBSERVATION_WINDOW", windowSeconds >= int64(shadowanalysis.MinimumRolloutWindow/time.Second),
		fmt.Sprintf("%d", windowSeconds), fmt.Sprintf("%d", int64(shadowanalysis.MinimumRolloutWindow/time.Second)), "The report must cover at least one complete 24-hour traffic cycle.")

	policyVersion, policyCount, policyOK := reviewDominantVersion(report.PolicyVersions, report.Decisions.Total)
	proposal.addGate("POLICY_VERSION_DOMINANCE", policyOK, fmt.Sprintf("%s:%d/%d", policyVersion, policyCount, report.Decisions.Total), "single_valid_version>=90%", "A rollout must bind to one dominant policy version.")
	modelVersion, modelCount, modelOK := reviewDominantVersion(report.ModelVersions, report.Decisions.Total)
	proposal.addGate("MODEL_VERSION_DOMINANCE", modelOK, fmt.Sprintf("%s:%d/%d", modelVersion, modelCount, report.Decisions.Total), "single_valid_version>=90%", "A rollout must bind to one dominant model version.")
	if policyOK {
		proposal.PolicyVersion = policyVersion
	}
	if modelOK {
		proposal.ModelVersion = modelVersion
	}

	endpoint, endpointOK := recommendedEndpoint(report.Endpoints)
	observedEndpoint := "none"
	if endpointOK {
		observedEndpoint = fmt.Sprintf("%s:risky=%d/%d,linked_human=%d,linked_abuse=%d", endpoint.EndpointClass, endpoint.ComputedRiskyActions, endpoint.Decisions, linkedHumanLabels(endpoint), linkedAbuseLabels(endpoint))
	}
	proposal.addGate("ELIGIBLE_ENDPOINT_SCOPE", endpointOK, observedEndpoint, fmt.Sprintf("one_public_endpoint_with_risky_shadow_actions,human>=%d,abuse>=%d", shadowanalysis.DefaultMinConfirmedHumans, shadowanalysis.DefaultMinConfirmedAbuse), "Choose one narrow public endpoint with measured risky shadow actions and sufficient confirmed human and confirmed-abuse outcomes; account and authentication endpoints are excluded.")

	if options.Stage == core.RuntimeModeEnforce {
		comparison, found := canaryComparison(report.CanaryComparisons, options.PredecessorRolloutID, endpoint.EndpointClass)
		decisions := uint64(0)
		if found {
			decisions = comparison.CanaryDecisions
		}
		proposal.addGate("PREDECESSOR_ENDPOINT_CANARY", found && decisions >= MinimumCanaryDecisions, fmt.Sprintf("%s:%d", endpoint.EndpointClass, decisions), fmt.Sprintf("same_endpoint_decisions>=%d", MinimumCanaryDecisions), "Enforcement review requires measured decisions from the exact predecessor canary on the exact recommended endpoint.")
		budget, budgetFound := canaryChallengeBudget(report.CanaryChallengeBudgets, options.PredecessorRolloutID, endpoint.EndpointClass)
		sampleReady := budgetFound && budget.MatureChallenges >= DefaultMinMatureChallenges
		proposal.addGate("PREDECESSOR_CHALLENGE_SAMPLE", sampleReady,
			fmt.Sprintf("%s:%d", endpoint.EndpointClass, budget.MatureChallenges), fmt.Sprintf("same_rollout_endpoint_mature_challenges>=%d", DefaultMinMatureChallenges),
			"Challenge enforcement requires a mature, uniquely linked sample from the exact predecessor canary and endpoint.")
		proposal.addGate("CHALLENGE_OUTCOME_COVERAGE_BUDGET", sampleReady && budget.TerminalOutcomeCoverage.Lower95 >= DefaultMinChallengeOutcomeCoverage,
			fmt.Sprintf("lower95=%.6f,count=%d/%d", budget.TerminalOutcomeCoverage.Lower95, budget.TerminalOutcomeCoverage.Count, budget.TerminalOutcomeCoverage.Total), fmt.Sprintf("lower95>=%.2f", DefaultMinChallengeOutcomeCoverage),
			"The conservative terminal-outcome coverage bound must meet the signed challenge budget.")
		proposal.addGate("CHALLENGE_ABANDONMENT_BUDGET", sampleReady && budget.ChallengeAbandonmentRate.Upper95 <= DefaultMaxChallengeAbandonmentRate,
			fmt.Sprintf("upper95=%.6f,count=%d/%d", budget.ChallengeAbandonmentRate.Upper95, budget.ChallengeAbandonmentRate.Count, budget.ChallengeAbandonmentRate.Total), fmt.Sprintf("upper95<=%.2f", DefaultMaxChallengeAbandonmentRate),
			"The conservative challenge-abandonment bound must remain within the signed friction budget.")
		proposal.addGate("CHALLENGE_FALLBACK_BUDGET", sampleReady && budget.FallbackRate.Upper95 <= DefaultMaxChallengeFallbackRate,
			fmt.Sprintf("upper95=%.6f,count=%d/%d", budget.FallbackRate.Upper95, budget.FallbackRate.Count, budget.FallbackRate.Total), fmt.Sprintf("upper95<=%.2f", DefaultMaxChallengeFallbackRate),
			"The conservative accessible-fallback bound must remain within the signed friction budget.")
	}

	if proposal.hasHoldGate() {
		proposal.State = ReviewStateHold
		proposal.RecommendedScope = nil
	} else {
		scope := ReviewScope{
			EndpointClasses:             []string{endpoint.EndpointClass},
			MaxAction:                   core.ActionChallenge,
			CanaryBasisPoints:           DefaultCanaryBasisPoints,
			DurationSeconds:             int64(DefaultCanaryDuration / time.Second),
			ThrottleSeconds:             DefaultThrottleSeconds,
			ChallengeTTLSeconds:         DefaultChallengeTTLSeconds,
			BlockSeconds:                DefaultBlockSeconds,
			MinMatureChallenges:         DefaultMinMatureChallenges,
			MinChallengeOutcomeCoverage: DefaultMinChallengeOutcomeCoverage,
			MaxChallengeAbandonmentRate: DefaultMaxChallengeAbandonmentRate,
			MaxChallengeFallbackRate:    DefaultMaxChallengeFallbackRate,
		}
		if options.Stage == core.RuntimeModeEnforce {
			scope.CanaryBasisPoints = FullRolloutBasisPoints
			scope.DurationSeconds = int64(DefaultEnforcementDuration / time.Second)
		}
		proposal.RecommendedScope = &scope
	}
	if err := proposal.Validate(); err != nil {
		return ReviewProposal{}, err
	}
	return proposal, nil
}

func PrepareFromReview(report shadowanalysis.Report, reportBytes []byte, proposal ReviewProposal, rolloutID, approvalID string, createdAt time.Time, privateKey ed25519.PrivateKey) (SignedPlan, error) {
	if err := proposal.Validate(); err != nil || proposal.State != ReviewStateCandidate || proposal.RecommendedScope == nil {
		return SignedPlan{}, ErrInvalidReview
	}
	expected, err := BuildReviewProposal(report, reportBytes, ReviewOptions{Stage: proposal.RequestedStage, PredecessorRolloutID: proposal.PredecessorRolloutID})
	if err != nil || !reflect.DeepEqual(expected, proposal) {
		return SignedPlan{}, fmt.Errorf("%w: proposal does not match the exact aggregate report and deterministic scope", ErrInvalidReview)
	}
	scope := proposal.RecommendedScope
	return prepareSignedPlan(report, reportBytes, PrepareOptions{
		RolloutID:                   rolloutID,
		ApprovalID:                  approvalID,
		PredecessorRolloutID:        proposal.PredecessorRolloutID,
		Stage:                       proposal.RequestedStage,
		EndpointClasses:             append([]string(nil), scope.EndpointClasses...),
		MaxAction:                   scope.MaxAction,
		CanaryBasisPoints:           scope.CanaryBasisPoints,
		ThrottleSeconds:             scope.ThrottleSeconds,
		ChallengeTTLSeconds:         scope.ChallengeTTLSeconds,
		BlockSeconds:                scope.BlockSeconds,
		MinMatureChallenges:         scope.MinMatureChallenges,
		MinChallengeOutcomeCoverage: scope.MinChallengeOutcomeCoverage,
		MaxChallengeAbandonmentRate: scope.MaxChallengeAbandonmentRate,
		MaxChallengeFallbackRate:    scope.MaxChallengeFallbackRate,
		CreatedAt:                   createdAt,
		ExpiresAt:                   createdAt.Add(time.Duration(scope.DurationSeconds) * time.Second),
	}, privateKey)
}

func (p ReviewProposal) Validate() error {
	if p.SchemaVersion != ReviewSchemaVersion || !sha256Pattern.MatchString(p.SourceReportSHA256) || p.SourceSchemaVersion != shadowanalysis.SchemaVersion ||
		p.AutomaticActivation || (p.State != ReviewStateHold && p.State != ReviewStateCandidate) ||
		(p.RequestedStage != core.RuntimeModeCanary && p.RequestedStage != core.RuntimeModeEnforce) || len(p.Gates) < 5 || len(p.Gates) > 10 ||
		len(p.OperatorChecklist) != 4 {
		return ErrInvalidReview
	}
	if p.SourceFirstAt == "" || p.SourceLastAt == "" {
		if p.SourceFirstAt != p.SourceLastAt || p.State != ReviewStateHold {
			return ErrInvalidReview
		}
	} else {
		firstAt, err := canonicalReviewTime(p.SourceFirstAt)
		if err != nil {
			return ErrInvalidReview
		}
		lastAt, err := canonicalReviewTime(p.SourceLastAt)
		if err != nil || lastAt.Before(firstAt) {
			return ErrInvalidReview
		}
	}
	if (p.PolicyVersion != "" && !stableID.MatchString(p.PolicyVersion)) || (p.ModelVersion != "" && !stableID.MatchString(p.ModelVersion)) {
		return ErrInvalidReview
	}
	if (p.RequestedStage == core.RuntimeModeCanary && p.PredecessorRolloutID != "") ||
		(p.RequestedStage == core.RuntimeModeEnforce && !stableID.MatchString(p.PredecessorRolloutID)) {
		return ErrInvalidReview
	}
	seen := make(map[string]struct{}, len(p.Gates))
	hasHold := false
	expectedGateCodes := []string{"REPORT_READINESS", "OBSERVATION_WINDOW", "POLICY_VERSION_DOMINANCE", "MODEL_VERSION_DOMINANCE", "ELIGIBLE_ENDPOINT_SCOPE"}
	if p.RequestedStage == core.RuntimeModeEnforce {
		expectedGateCodes = append(expectedGateCodes, "PREDECESSOR_ENDPOINT_CANARY", "PREDECESSOR_CHALLENGE_SAMPLE", "CHALLENGE_OUTCOME_COVERAGE_BUDGET", "CHALLENGE_ABANDONMENT_BUDGET", "CHALLENGE_FALLBACK_BUDGET")
	}
	if len(p.Gates) != len(expectedGateCodes) {
		return ErrInvalidReview
	}
	for index, gate := range p.Gates {
		if !reviewGateCode.MatchString(gate.Code) || (gate.Status != ReviewGatePass && gate.Status != ReviewGateHold) || gate.Observed == "" || gate.Required == "" || gate.Message == "" {
			return ErrInvalidReview
		}
		if gate.Code != expectedGateCodes[index] {
			return ErrInvalidReview
		}
		if _, exists := seen[gate.Code]; exists {
			return ErrInvalidReview
		}
		seen[gate.Code] = struct{}{}
		hasHold = hasHold || gate.Status == ReviewGateHold
	}
	expectedChecklist := []string{
		"confirm_endpoint_confidence_intervals",
		"confirm_accessible_fallback_and_support",
		"confirm_origin_adapter_fail_safe_behavior",
		"confirm_rollback_owner_and_command",
	}
	if !reflect.DeepEqual(p.OperatorChecklist, expectedChecklist) || (hasHold != (p.State == ReviewStateHold)) {
		return ErrInvalidReview
	}
	if p.State == ReviewStateHold {
		if p.RecommendedScope != nil {
			return ErrInvalidReview
		}
		return nil
	}
	if !stableID.MatchString(p.PolicyVersion) || !stableID.MatchString(p.ModelVersion) || p.RecommendedScope == nil {
		return ErrInvalidReview
	}
	return p.RecommendedScope.validate(p.RequestedStage)
}

func (s ReviewScope) validate(stage core.RuntimeMode) error {
	if len(s.EndpointClasses) != 1 || !allowedEndpoint(s.EndpointClasses[0]) || s.ThrottleSeconds != DefaultThrottleSeconds ||
		s.ChallengeTTLSeconds != DefaultChallengeTTLSeconds || s.BlockSeconds != DefaultBlockSeconds ||
		s.MinMatureChallenges != DefaultMinMatureChallenges || s.MinChallengeOutcomeCoverage != DefaultMinChallengeOutcomeCoverage ||
		s.MaxChallengeAbandonmentRate != DefaultMaxChallengeAbandonmentRate || s.MaxChallengeFallbackRate != DefaultMaxChallengeFallbackRate {
		return ErrInvalidReview
	}
	if stage == core.RuntimeModeCanary {
		if s.MaxAction != core.ActionChallenge || s.CanaryBasisPoints != DefaultCanaryBasisPoints || s.DurationSeconds != int64(DefaultCanaryDuration/time.Second) {
			return ErrInvalidReview
		}
		return nil
	}
	if s.MaxAction != core.ActionChallenge || s.CanaryBasisPoints != FullRolloutBasisPoints || s.DurationSeconds != int64(DefaultEnforcementDuration/time.Second) {
		return ErrInvalidReview
	}
	return nil
}

func (p *ReviewProposal) addGate(code string, passed bool, observed, required, message string) {
	status := ReviewGateHold
	if passed {
		status = ReviewGatePass
	}
	p.Gates = append(p.Gates, ReviewGate{Code: code, Status: status, Observed: observed, Required: required, Message: message})
}

func (p ReviewProposal) hasHoldGate() bool {
	for _, gate := range p.Gates {
		if gate.Status == ReviewGateHold {
			return true
		}
	}
	return false
}

func reviewDominantVersion(values []shadowanalysis.CountedValue, decisions uint64) (string, uint64, bool) {
	minimum := decisions - decisions/10
	if decisions == 0 || len(values) == 0 || !stableID.MatchString(values[0].Value) || values[0].Count < minimum {
		return "none", 0, false
	}
	return values[0].Value, values[0].Count, true
}

func recommendedEndpoint(values []shadowanalysis.EndpointSummary) (shadowanalysis.EndpointSummary, bool) {
	candidates := make([]shadowanalysis.EndpointSummary, 0, len(values))
	for _, endpoint := range values {
		if allowedEndpoint(endpoint.EndpointClass) && endpoint.Decisions > 0 && endpoint.ComputedRiskyActions > 0 &&
			linkedHumanLabels(endpoint) >= shadowanalysis.DefaultMinConfirmedHumans && linkedAbuseLabels(endpoint) >= shadowanalysis.DefaultMinConfirmedAbuse {
			candidates = append(candidates, endpoint)
		}
	}
	if len(candidates) == 0 {
		return shadowanalysis.EndpointSummary{}, false
	}
	sort.Slice(candidates, func(left, right int) bool {
		leftHigh, leftLow := bits.Mul64(candidates[left].ComputedRiskyActions, candidates[right].Decisions)
		rightHigh, rightLow := bits.Mul64(candidates[right].ComputedRiskyActions, candidates[left].Decisions)
		if leftHigh != rightHigh {
			return leftHigh < rightHigh
		}
		if leftLow != rightLow {
			return leftLow < rightLow
		}
		if candidates[left].Decisions != candidates[right].Decisions {
			return candidates[left].Decisions > candidates[right].Decisions
		}
		return candidates[left].EndpointClass < candidates[right].EndpointClass
	})
	return candidates[0], true
}

func linkedHumanLabels(endpoint shadowanalysis.EndpointSummary) uint64 {
	return endpoint.LinkedEvaluation.Confusion.FalsePositive + endpoint.LinkedEvaluation.Confusion.TrueNegative
}

func linkedAbuseLabels(endpoint shadowanalysis.EndpointSummary) uint64 {
	return endpoint.LinkedEvaluation.Confusion.TruePositive + endpoint.LinkedEvaluation.Confusion.FalseNegative
}

func canaryComparison(values []shadowanalysis.CanaryComparison, rolloutID, endpoint string) (shadowanalysis.CanaryComparison, bool) {
	for _, comparison := range values {
		if comparison.RolloutID == rolloutID && comparison.EndpointClass == endpoint {
			return comparison, true
		}
	}
	return shadowanalysis.CanaryComparison{}, false
}

func canaryChallengeBudget(values []shadowanalysis.CanaryChallengeBudget, rolloutID, endpoint string) (shadowanalysis.CanaryChallengeBudget, bool) {
	for _, budget := range values {
		if budget.RolloutID == rolloutID && budget.EndpointClass == endpoint {
			return budget, true
		}
	}
	return shadowanalysis.CanaryChallengeBudget{}, false
}

func sourceWindowSeconds(first, last string) int64 {
	firstAt, firstErr := time.Parse(time.RFC3339, first)
	lastAt, lastErr := time.Parse(time.RFC3339, last)
	if firstErr != nil || lastErr != nil || lastAt.Before(firstAt) {
		return 0
	}
	return lastAt.Unix() - firstAt.Unix()
}

func canonicalReviewTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil || parsed.UTC().Format(time.RFC3339) != value {
		return time.Time{}, ErrInvalidReview
	}
	return parsed, nil
}
