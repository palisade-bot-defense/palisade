package shadowanalysis

import (
	"errors"
	"math"
	"slices"
	"sort"
	"time"
)

var ErrInvalidReport = errors.New("invalid shadow analysis report")

// ValidateForRollout checks the aggregate arithmetic and recomputes the
// default readiness gate. A signed rollout must never trust a caller-supplied
// readiness string without validating the measurements that produced it.
func ValidateForRollout(report Report) error {
	if report.SchemaVersion != SchemaVersion || report.Source.EncryptedBytes < 0 ||
		report.Source.Decisions != report.Decisions.Total || report.Source.Outcomes != report.Outcomes.Total ||
		!equalSum(report.Source.Records, report.Source.Decisions, report.Source.Outcomes) ||
		(report.Source.Records > 0 && report.Source.Files == 0) {
		return ErrInvalidReport
	}
	if !validSourceTimes(report.Source.FirstAt, report.Source.LastAt) || !sourceWindowAtLeast(report.Source.FirstAt, report.Source.LastAt, MinimumRolloutWindow) ||
		!equalSum(report.Decisions.Total, report.Decisions.Enforced.Allow, report.Decisions.Enforced.Observe, report.Decisions.Enforced.Throttle, report.Decisions.Enforced.Challenge, report.Decisions.Enforced.Block) ||
		!equalSum(report.Decisions.Total, report.Decisions.Computed.Allow, report.Decisions.Computed.Observe, report.Decisions.Computed.Throttle, report.Decisions.Computed.Challenge, report.Decisions.Computed.Block) ||
		!equalSum(report.Decisions.Total, report.Decisions.Modes.Shadow, report.Decisions.Modes.Canary, report.Decisions.Modes.Enforce) ||
		report.Decisions.ShadowRiskyEnforcements > report.Decisions.Modes.Shadow {
		return ErrInvalidReport
	}
	if !closeRatio(report.Decisions.ComputedChallengeRate, ratio(report.Decisions.Computed.Challenge, report.Decisions.Total)) ||
		!equalSum(report.Outcomes.Total, report.Outcomes.SuccessfulAction, report.Outcomes.ChallengePassed, report.Outcomes.ChallengeFailed, report.Outcomes.ChallengeAbandoned,
			report.Outcomes.HumanConfirmed, report.Outcomes.OperatorConfirmedAbuse, report.Outcomes.AppealRequested, report.Outcomes.FallbackUsed, report.Outcomes.Unknown) ||
		!equalSum(report.Outcomes.ChallengeResults, report.Outcomes.ChallengePassed, report.Outcomes.ChallengeFailed, report.Outcomes.ChallengeAbandoned) ||
		!closeRatio(report.Outcomes.Coverage, minimum(1, ratio(report.Outcomes.Total, report.Decisions.Total))) ||
		!closeRatio(report.Outcomes.ChallengeFailureRate, ratio(report.Outcomes.ChallengeFailed+report.Outcomes.ChallengeAbandoned, report.Outcomes.ChallengeResults)) {
		return ErrInvalidReport
	}
	if !validScore(report.Scores.AutomationRisk, report.Decisions.Total) || !validScore(report.Scores.AbuseIntentRisk, report.Decisions.Total) ||
		!validScore(report.Scores.AccountContinuity, report.Decisions.Total) || !validEndpoints(report) ||
		!validCountedValues(report.PolicyVersions, report.Decisions.Total) || !validCountedValues(report.ModelVersions, report.Decisions.Total) ||
		!validCountedValues(report.CanaryRollouts, report.Decisions.Modes.Canary) {
		return ErrInvalidReport
	}
	config, err := normalizeConfig(Config{})
	if err != nil {
		return err
	}
	expectedRecommendations, expected := recommend(report, config)
	if report.Readiness.State != expected.State || report.Readiness.OperatorAction != expected.OperatorAction ||
		report.Readiness.AutomaticEnforcement != expected.AutomaticEnforcement || !slices.Equal(report.Readiness.ReasonCodes, expected.ReasonCodes) ||
		!slices.Equal(report.Recommendations, expectedRecommendations) {
		return ErrInvalidReport
	}
	return nil
}

func validSourceTimes(first, last string) bool {
	if first == "" || last == "" {
		return first == last
	}
	firstAt, firstErr := time.Parse(time.RFC3339, first)
	lastAt, lastErr := time.Parse(time.RFC3339, last)
	return firstErr == nil && lastErr == nil && !lastAt.Before(firstAt) && firstAt.UTC().Format(time.RFC3339) == first && lastAt.UTC().Format(time.RFC3339) == last
}

func sourceWindowAtLeast(first, last string, minimum time.Duration) bool {
	firstAt, firstErr := time.Parse(time.RFC3339, first)
	lastAt, lastErr := time.Parse(time.RFC3339, last)
	return firstErr == nil && lastErr == nil && lastAt.Sub(firstAt) >= minimum
}

func validScore(score ScoreSummary, decisions uint64) bool {
	values := []float64{score.Minimum, score.Maximum, score.Mean}
	for _, value := range values {
		if math.IsNaN(value) || math.IsInf(value, 0) || value < 0 || value > 1 {
			return false
		}
	}
	if decisions == 0 {
		return score == (ScoreSummary{})
	}
	return score.Minimum <= score.Mean && score.Mean <= score.Maximum
}

func validEndpoints(report Report) bool {
	var decisions, outcomes, humans, abuse uint64
	previous := ""
	for _, endpoint := range report.Endpoints {
		if !allowedReportEndpoint(endpoint.EndpointClass) || (previous != "" && endpoint.EndpointClass <= previous) || endpoint.ComputedRiskyActions > endpoint.Decisions ||
			!add(&decisions, endpoint.Decisions) || !add(&outcomes, endpoint.Outcomes) || !add(&humans, endpoint.HumanConfirmed) || !add(&abuse, endpoint.OperatorConfirmedAbuse) {
			return false
		}
		previous = endpoint.EndpointClass
	}
	return decisions == report.Decisions.Total && outcomes == report.Outcomes.Total && humans == report.Outcomes.HumanConfirmed && abuse == report.Outcomes.OperatorConfirmedAbuse
}

func validCountedValues(values []CountedValue, expected uint64) bool {
	if expected == 0 {
		return len(values) == 0
	}
	if len(values) == 0 || !sort.SliceIsSorted(values, func(left, right int) bool {
		if values[left].Count == values[right].Count {
			return values[left].Value < values[right].Value
		}
		return values[left].Count > values[right].Count
	}) {
		return false
	}
	seen := make(map[string]struct{}, len(values))
	var total uint64
	for _, value := range values {
		if value.Value == "" || value.Count == 0 {
			return false
		}
		if _, exists := seen[value.Value]; exists || !add(&total, value.Count) {
			return false
		}
		seen[value.Value] = struct{}{}
	}
	return total == expected
}

func allowedReportEndpoint(value string) bool {
	switch value {
	case "public_content", "compare_index", "compare_noindex", "challenge_worker", "other_public", "account", "login", "checkout", "other":
		return true
	default:
		return false
	}
}

func equalSum(expected uint64, values ...uint64) bool {
	var total uint64
	for _, value := range values {
		if !add(&total, value) {
			return false
		}
	}
	return total == expected
}

func add(total *uint64, value uint64) bool {
	if ^uint64(0)-*total < value {
		return false
	}
	*total += value
	return true
}

func ratio(numerator, denominator uint64) float64 {
	if denominator == 0 {
		return 0
	}
	return float64(numerator) / float64(denominator)
}

func closeRatio(actual, expected float64) bool {
	return !math.IsNaN(actual) && !math.IsInf(actual, 0) && math.Abs(actual-expected) <= 1e-12
}
