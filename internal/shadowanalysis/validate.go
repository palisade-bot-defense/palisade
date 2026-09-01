package shadowanalysis

import (
	"errors"
	"math"
	"regexp"
	"slices"
	"sort"
	"time"

	"github.com/palisade-human-trust/palisade/internal/core"
)

var ErrInvalidReport = errors.New("invalid shadow analysis report")

var stableReportValue = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,128}$`)

// ValidateReport checks the aggregate arithmetic and recomputes the default
// readiness gate. It is suitable for read-only presentation of reports that
// are still collecting their first complete traffic cycle.
func ValidateReport(report Report) error {
	if report.SchemaVersion != SchemaVersion || report.Source.EncryptedBytes < 0 ||
		report.Source.Decisions != report.Decisions.Total || report.Source.Outcomes != report.Outcomes.Total ||
		!equalSum(report.Source.Records, report.Source.Decisions, report.Source.Outcomes) ||
		(report.Source.Records > 0 && (report.Source.Files == 0 || report.Source.FirstAt == "" || report.Source.LastAt == "")) {
		return ErrInvalidReport
	}
	if !validSourceTimes(report.Source.FirstAt, report.Source.LastAt) ||
		!equalSum(report.Decisions.Total, report.Decisions.Enforced.Allow, report.Decisions.Enforced.Observe, report.Decisions.Enforced.Delay, report.Decisions.Enforced.Throttle, report.Decisions.Enforced.Challenge, report.Decisions.Enforced.Block) ||
		!equalSum(report.Decisions.Total, report.Decisions.Computed.Allow, report.Decisions.Computed.Observe, report.Decisions.Computed.Delay, report.Decisions.Computed.Throttle, report.Decisions.Computed.Challenge, report.Decisions.Computed.Block) ||
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
		!validRankedValues(report.TopReasonCodes, DefaultTopReasonCodes) ||
		!validCountedValues(report.PolicyVersions, report.Decisions.Total) || !validCountedValues(report.ModelVersions, report.Decisions.Total) ||
		!validCountedValues(report.CanaryRollouts, report.Decisions.Modes.Canary) || !validCanaryComparisons(report) ||
		!validCanaryChallengeBudgets(report) || !validLinkage(report) {
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

// ValidateForRollout additionally requires a complete minimum observation
// window. A signed rollout must never trust a caller-supplied readiness string
// without validating the measurements that produced it.
func ValidateForRollout(report Report) error {
	if ValidateReport(report) != nil || !sourceWindowAtLeast(report.Source.FirstAt, report.Source.LastAt, MinimumRolloutWindow) {
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
	return firstErr == nil && lastErr == nil && !lastAt.Before(firstAt) && lastAt.Unix()-firstAt.Unix() >= int64(minimum/time.Second)
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
	var decisions, outcomes, risky, humans, abuse uint64
	var outcomeKinds OutcomeKindCounts
	previous := ""
	for _, endpoint := range report.Endpoints {
		if !allowedReportEndpoint(endpoint.EndpointClass) || (previous != "" && endpoint.EndpointClass <= previous) || endpoint.ComputedRiskyActions > endpoint.Decisions ||
			!equalSum(endpoint.Outcomes, endpoint.OutcomeKinds.SuccessfulAction, endpoint.OutcomeKinds.ChallengePassed, endpoint.OutcomeKinds.ChallengeFailed,
				endpoint.OutcomeKinds.ChallengeAbandoned, endpoint.OutcomeKinds.HumanConfirmed, endpoint.OutcomeKinds.OperatorConfirmedAbuse,
				endpoint.OutcomeKinds.AppealRequested, endpoint.OutcomeKinds.FallbackUsed, endpoint.OutcomeKinds.Unknown) ||
			endpoint.HumanConfirmed != endpoint.OutcomeKinds.HumanConfirmed || endpoint.OperatorConfirmedAbuse != endpoint.OutcomeKinds.OperatorConfirmedAbuse ||
			!validEndpointEvaluation(endpoint) || !validLinkedEvaluation(endpoint.LinkedEvaluation) || endpoint.LinkedEvaluation.Decisions > endpoint.Decisions ||
			endpoint.LinkedEvaluation.Confusion.FalsePositive+endpoint.LinkedEvaluation.Confusion.TrueNegative > endpoint.HumanConfirmed ||
			endpoint.LinkedEvaluation.Confusion.TruePositive+endpoint.LinkedEvaluation.Confusion.FalseNegative > endpoint.OperatorConfirmedAbuse ||
			!add(&decisions, endpoint.Decisions) || !add(&outcomes, endpoint.Outcomes) || !add(&risky, endpoint.ComputedRiskyActions) ||
			!add(&humans, endpoint.HumanConfirmed) || !add(&abuse, endpoint.OperatorConfirmedAbuse) || !addOutcomeKinds(&outcomeKinds, endpoint.OutcomeKinds) {
			return false
		}
		previous = endpoint.EndpointClass
	}
	globalKinds := OutcomeKindCounts{
		SuccessfulAction: report.Outcomes.SuccessfulAction, ChallengePassed: report.Outcomes.ChallengePassed,
		ChallengeFailed: report.Outcomes.ChallengeFailed, ChallengeAbandoned: report.Outcomes.ChallengeAbandoned,
		HumanConfirmed: report.Outcomes.HumanConfirmed, OperatorConfirmedAbuse: report.Outcomes.OperatorConfirmedAbuse,
		AppealRequested: report.Outcomes.AppealRequested, FallbackUsed: report.Outcomes.FallbackUsed, Unknown: report.Outcomes.Unknown,
	}
	var globalRisky uint64
	return add(&globalRisky, report.Decisions.Computed.Delay) && add(&globalRisky, report.Decisions.Computed.Throttle) && add(&globalRisky, report.Decisions.Computed.Challenge) && add(&globalRisky, report.Decisions.Computed.Block) &&
		decisions == report.Decisions.Total && outcomes == report.Outcomes.Total && risky == globalRisky && humans == report.Outcomes.HumanConfirmed &&
		abuse == report.Outcomes.OperatorConfirmedAbuse && outcomeKinds == globalKinds
}

func validLinkage(report Report) bool {
	linkage := report.Linkage
	var decisionRecords, outcomeEvents, linkedOutcomeEvents uint64
	if !add(&decisionRecords, linkage.UniqueDecisionIDs) || !add(&decisionRecords, linkage.DuplicateDecisionRecords) || decisionRecords != report.Source.Decisions ||
		linkage.DuplicateDecisionIDs > linkage.UniqueDecisionIDs ||
		!add(&outcomeEvents, linkage.OutcomeEventsWithDecisionID) || !add(&outcomeEvents, linkage.LegacyOutcomeEventsWithoutID) || outcomeEvents != report.Source.Outcomes ||
		!add(&linkedOutcomeEvents, linkage.MatchedOutcomeEvents) || !add(&linkedOutcomeEvents, linkage.UnknownDecisionOutcomeEvents) ||
		!add(&linkedOutcomeEvents, linkage.EndpointMismatchOutcomeEvents) || linkedOutcomeEvents != linkage.OutcomeEventsWithDecisionID ||
		linkage.DuplicateOutcomeEvents > linkage.OutcomeEventsWithDecisionID {
		return false
	}

	endpointEvaluations := make(map[string]LinkedEvaluation, len(report.Endpoints))
	var endpointTotal LinkedEvaluation
	for _, endpoint := range report.Endpoints {
		if endpoint.LinkedEvaluation.Decisions > 0 {
			endpointEvaluations[endpoint.EndpointClass] = endpoint.LinkedEvaluation
		}
		if !addLinkedEvaluation(&endpointTotal, endpoint.LinkedEvaluation) {
			return false
		}
	}
	if endpointTotal.Decisions != linkage.UniqueDecisionIDs-linkage.DuplicateDecisionIDs ||
		endpointTotal.ConfirmedLabels != linkage.ConfirmedDecisionLabels ||
		endpointTotal.AmbiguousGroundTruth != linkage.AmbiguousGroundTruthDecisions ||
		endpointTotal.AmbiguousChallengeOutcomes != linkage.AmbiguousChallengeDecisions {
		return false
	}
	if !validProportion(linkage.ConfirmedLabelCoverage) || linkage.ConfirmedLabelCoverage.Count != linkage.ConfirmedDecisionLabels ||
		linkage.ConfirmedLabelCoverage.Total != report.Decisions.Total {
		return false
	}

	sliceTotals := make(map[string]LinkedEvaluation, len(report.Endpoints))
	previousEndpoint := ""
	var previousCohort core.EvaluationCohort
	for _, slice := range report.EvaluationSlices {
		cohort, valid := core.NormalizeEvaluationCohort(slice.EvaluationCohort)
		if !valid || cohort != slice.EvaluationCohort || !allowedReportEndpoint(slice.EndpointClass) || !validLinkedEvaluation(slice.Evaluation) ||
			(previousEndpoint != "" && (slice.EndpointClass < previousEndpoint || (slice.EndpointClass == previousEndpoint && slice.EvaluationCohort <= previousCohort))) {
			return false
		}
		total := sliceTotals[slice.EndpointClass]
		if !addLinkedEvaluation(&total, slice.Evaluation) {
			return false
		}
		sliceTotals[slice.EndpointClass] = total
		previousEndpoint, previousCohort = slice.EndpointClass, slice.EvaluationCohort
	}
	if len(report.EvaluationSlices) > 54 || len(sliceTotals) != len(endpointEvaluations) {
		return false
	}
	for endpoint, expected := range endpointEvaluations {
		actual, exists := sliceTotals[endpoint]
		if !exists || finalizeLinkedEvaluation(actual) != expected {
			return false
		}
	}
	return true
}

func validLinkedEvaluation(value LinkedEvaluation) bool {
	var labels, humanLabels, abuseLabels, matureOutcomes, classifiedDecisions uint64
	if !add(&labels, value.Confusion.TruePositive) || !add(&labels, value.Confusion.FalsePositive) ||
		!add(&labels, value.Confusion.TrueNegative) || !add(&labels, value.Confusion.FalseNegative) || labels != value.ConfirmedLabels ||
		!add(&humanLabels, value.Confusion.FalsePositive) || !add(&humanLabels, value.Confusion.TrueNegative) ||
		!add(&abuseLabels, value.Confusion.TruePositive) || !add(&abuseLabels, value.Confusion.FalseNegative) ||
		!add(&matureOutcomes, value.ChallengePassed) || !add(&matureOutcomes, value.ChallengeFailed) ||
		!add(&matureOutcomes, value.ChallengeAbandoned) || !add(&matureOutcomes, value.FallbackUsed) ||
		!add(&matureOutcomes, value.UnresolvedMatureChallenges) || !add(&matureOutcomes, value.AmbiguousChallengeOutcomes) ||
		!add(&classifiedDecisions, value.ConfirmedLabels) || !add(&classifiedDecisions, value.AmbiguousGroundTruth) ||
		matureOutcomes != value.MatureChallenges || classifiedDecisions > value.Decisions || value.MatureChallenges > value.Decisions {
		return false
	}
	return validProportion(value.FalsePositiveRate) && value.FalsePositiveRate.Count == value.Confusion.FalsePositive && value.FalsePositiveRate.Total == humanLabels &&
		validProportion(value.AbuseRecall) && value.AbuseRecall.Count == value.Confusion.TruePositive && value.AbuseRecall.Total == abuseLabels &&
		validProportion(value.AbusePrecision) && value.AbusePrecision.Count == value.Confusion.TruePositive && value.AbusePrecision.Total == value.Confusion.TruePositive+value.Confusion.FalsePositive &&
		validProportion(value.ChallengePassRate) && value.ChallengePassRate.Count == value.ChallengePassed && value.ChallengePassRate.Total == value.MatureChallenges &&
		validProportion(value.ChallengeFailureRate) && value.ChallengeFailureRate.Count == value.ChallengeFailed && value.ChallengeFailureRate.Total == value.MatureChallenges &&
		validProportion(value.ChallengeAbandonmentRate) && value.ChallengeAbandonmentRate.Count == value.ChallengeAbandoned && value.ChallengeAbandonmentRate.Total == value.MatureChallenges &&
		validProportion(value.FallbackRate) && value.FallbackRate.Count == value.FallbackUsed && value.FallbackRate.Total == value.MatureChallenges
}

func addLinkedEvaluation(total *LinkedEvaluation, value LinkedEvaluation) bool {
	return add(&total.Decisions, value.Decisions) && add(&total.ConfirmedLabels, value.ConfirmedLabels) &&
		add(&total.AmbiguousGroundTruth, value.AmbiguousGroundTruth) &&
		add(&total.Confusion.TruePositive, value.Confusion.TruePositive) && add(&total.Confusion.FalsePositive, value.Confusion.FalsePositive) &&
		add(&total.Confusion.TrueNegative, value.Confusion.TrueNegative) && add(&total.Confusion.FalseNegative, value.Confusion.FalseNegative) &&
		add(&total.MatureChallenges, value.MatureChallenges) && add(&total.ChallengePassed, value.ChallengePassed) &&
		add(&total.ChallengeFailed, value.ChallengeFailed) && add(&total.ChallengeAbandoned, value.ChallengeAbandoned) &&
		add(&total.FallbackUsed, value.FallbackUsed) && add(&total.UnresolvedMatureChallenges, value.UnresolvedMatureChallenges) &&
		add(&total.AmbiguousChallengeOutcomes, value.AmbiguousChallengeOutcomes)
}

func addOutcomeKinds(total *OutcomeKindCounts, value OutcomeKindCounts) bool {
	return add(&total.SuccessfulAction, value.SuccessfulAction) && add(&total.ChallengePassed, value.ChallengePassed) &&
		add(&total.ChallengeFailed, value.ChallengeFailed) && add(&total.ChallengeAbandoned, value.ChallengeAbandoned) &&
		add(&total.HumanConfirmed, value.HumanConfirmed) && add(&total.OperatorConfirmedAbuse, value.OperatorConfirmedAbuse) &&
		add(&total.AppealRequested, value.AppealRequested) && add(&total.FallbackUsed, value.FallbackUsed) && add(&total.Unknown, value.Unknown)
}

func validEndpointEvaluation(endpoint EndpointSummary) bool {
	var challengeResults, labels uint64
	if !add(&challengeResults, endpoint.OutcomeKinds.ChallengePassed) || !add(&challengeResults, endpoint.OutcomeKinds.ChallengeFailed) ||
		!add(&challengeResults, endpoint.OutcomeKinds.ChallengeAbandoned) || !add(&labels, endpoint.HumanConfirmed) ||
		!add(&labels, endpoint.OperatorConfirmedAbuse) {
		return false
	}
	evaluation := endpoint.Evaluation
	return evaluation.ConfirmedLabels == labels &&
		validProportion(evaluation.ComputedRiskyRate) && evaluation.ComputedRiskyRate.Count == endpoint.ComputedRiskyActions && evaluation.ComputedRiskyRate.Total == endpoint.Decisions &&
		validProportion(evaluation.ChallengeFailureRate) && evaluation.ChallengeFailureRate.Count == endpoint.OutcomeKinds.ChallengeFailed+endpoint.OutcomeKinds.ChallengeAbandoned && evaluation.ChallengeFailureRate.Total == challengeResults &&
		validProportion(evaluation.ChallengeAbandonmentRate) && evaluation.ChallengeAbandonmentRate.Count == endpoint.OutcomeKinds.ChallengeAbandoned && evaluation.ChallengeAbandonmentRate.Total == challengeResults &&
		validProportion(evaluation.FallbackOutcomeShare) && evaluation.FallbackOutcomeShare.Count == endpoint.OutcomeKinds.FallbackUsed && evaluation.FallbackOutcomeShare.Total == endpoint.Outcomes &&
		validProportion(evaluation.AppealOutcomeShare) && evaluation.AppealOutcomeShare.Count == endpoint.OutcomeKinds.AppealRequested && evaluation.AppealOutcomeShare.Total == endpoint.Outcomes &&
		validProportion(evaluation.UnknownOutcomeShare) && evaluation.UnknownOutcomeShare.Count == endpoint.OutcomeKinds.Unknown && evaluation.UnknownOutcomeShare.Total == endpoint.Outcomes &&
		validProportion(evaluation.AbuseLabelShare) && evaluation.AbuseLabelShare.Count == endpoint.OperatorConfirmedAbuse && evaluation.AbuseLabelShare.Total == labels
}

func validCanaryComparisons(report Report) bool {
	if len(report.CanaryComparisons) > DefaultMaxDistinctMetadata {
		return false
	}
	rollouts := make(map[string]uint64, len(report.CanaryRollouts))
	endpoints := make(map[string]struct{}, len(report.Endpoints))
	for _, endpoint := range report.Endpoints {
		endpoints[endpoint.EndpointClass] = struct{}{}
	}
	previousRollout, previousEndpoint := "", ""
	var total uint64
	for _, comparison := range report.CanaryComparisons {
		_, endpointExists := endpoints[comparison.EndpointClass]
		if !stableReportValue.MatchString(comparison.RolloutID) || !endpointExists || comparison.Comparable != (comparison.ShadowDecisions > 0 && comparison.CanaryDecisions > 0) ||
			(previousRollout != "" && (comparison.RolloutID < previousRollout || (comparison.RolloutID == previousRollout && comparison.EndpointClass <= previousEndpoint))) ||
			comparison.ShadowComputedRisky.Total != comparison.ShadowDecisions || comparison.CanaryComputedRisky.Total != comparison.CanaryDecisions ||
			comparison.CanaryEnforcedRisky.Total != comparison.CanaryDecisions || !validProportion(comparison.ShadowComputedRisky) ||
			!validProportion(comparison.CanaryComputedRisky) || !validProportion(comparison.CanaryEnforcedRisky) ||
			!validComparisonDifference(comparison) ||
			!add(&total, comparison.CanaryDecisions) {
			return false
		}
		count := rollouts[comparison.RolloutID]
		if !add(&count, comparison.CanaryDecisions) {
			return false
		}
		rollouts[comparison.RolloutID] = count
		previousRollout, previousEndpoint = comparison.RolloutID, comparison.EndpointClass
	}
	if total != report.Decisions.Modes.Canary || len(rollouts) != len(report.CanaryRollouts) {
		return false
	}
	for _, rollout := range report.CanaryRollouts {
		if rollouts[rollout.Value] != rollout.Count {
			return false
		}
	}
	return true
}

func validCanaryChallengeBudgets(report Report) bool {
	if report.CanaryComparisons == nil || report.CanaryChallengeBudgets == nil ||
		len(report.CanaryChallengeBudgets) != len(report.CanaryComparisons) || len(report.CanaryChallengeBudgets) > DefaultMaxDistinctMetadata {
		return false
	}
	comparisons := make(map[string]CanaryComparison, len(report.CanaryComparisons))
	type challengeTotals struct {
		mature, passed, failed, abandoned, fallback, unresolved, ambiguous uint64
	}
	endpointTotals := make(map[string]*challengeTotals)
	for _, comparison := range report.CanaryComparisons {
		comparisons[comparison.RolloutID+"\x00"+comparison.EndpointClass] = comparison
	}
	previousRollout, previousEndpoint := "", ""
	for _, budget := range report.CanaryChallengeBudgets {
		comparison, exists := comparisons[budget.RolloutID+"\x00"+budget.EndpointClass]
		var resolved, total uint64
		if !exists || (previousRollout != "" && (budget.RolloutID < previousRollout || (budget.RolloutID == previousRollout && budget.EndpointClass <= previousEndpoint))) ||
			budget.MatureChallenges > comparison.CanaryDecisions ||
			!add(&resolved, budget.ChallengePassed) || !add(&resolved, budget.ChallengeFailed) || !add(&resolved, budget.ChallengeAbandoned) ||
			!add(&resolved, budget.FallbackUsed) || !add(&total, resolved) || !add(&total, budget.UnresolvedMatureChallenges) || !add(&total, budget.AmbiguousChallengeOutcomes) ||
			total != budget.MatureChallenges ||
			!validProportion(budget.TerminalOutcomeCoverage) || budget.TerminalOutcomeCoverage.Count != resolved || budget.TerminalOutcomeCoverage.Total != budget.MatureChallenges ||
			!validProportion(budget.ChallengeAbandonmentRate) || budget.ChallengeAbandonmentRate.Count != budget.ChallengeAbandoned || budget.ChallengeAbandonmentRate.Total != budget.MatureChallenges ||
			!validProportion(budget.FallbackRate) || budget.FallbackRate.Count != budget.FallbackUsed || budget.FallbackRate.Total != budget.MatureChallenges {
			return false
		}
		totals := endpointTotals[budget.EndpointClass]
		if totals == nil {
			totals = &challengeTotals{}
			endpointTotals[budget.EndpointClass] = totals
		}
		if !add(&totals.mature, budget.MatureChallenges) || !add(&totals.passed, budget.ChallengePassed) || !add(&totals.failed, budget.ChallengeFailed) ||
			!add(&totals.abandoned, budget.ChallengeAbandoned) || !add(&totals.fallback, budget.FallbackUsed) ||
			!add(&totals.unresolved, budget.UnresolvedMatureChallenges) || !add(&totals.ambiguous, budget.AmbiguousChallengeOutcomes) {
			return false
		}
		delete(comparisons, budget.RolloutID+"\x00"+budget.EndpointClass)
		previousRollout, previousEndpoint = budget.RolloutID, budget.EndpointClass
	}
	if len(comparisons) != 0 {
		return false
	}
	for endpoint, totals := range endpointTotals {
		var linked *LinkedEvaluation
		for index := range report.Endpoints {
			if report.Endpoints[index].EndpointClass == endpoint {
				linked = &report.Endpoints[index].LinkedEvaluation
				break
			}
		}
		if linked == nil || totals.mature > linked.MatureChallenges || totals.passed > linked.ChallengePassed || totals.failed > linked.ChallengeFailed ||
			totals.abandoned > linked.ChallengeAbandoned || totals.fallback > linked.FallbackUsed || totals.unresolved > linked.UnresolvedMatureChallenges ||
			totals.ambiguous > linked.AmbiguousChallengeOutcomes {
			return false
		}
	}
	return true
}

func validComparisonDifference(comparison CanaryComparison) bool {
	if !comparison.Comparable {
		return comparison.ComputedRiskDifference == (DifferenceEstimate{})
	}
	return validDifference(comparison.ComputedRiskDifference, comparison.CanaryComputedRisky, comparison.ShadowComputedRisky)
}

func validCountedValues(values []CountedValue, expected uint64) bool {
	if expected == 0 {
		return len(values) == 0
	}
	if !validRankedValues(values, DefaultMaxDistinctMetadata) {
		return false
	}
	var total uint64
	for _, value := range values {
		if !add(&total, value.Count) {
			return false
		}
	}
	return total == expected
}

func validRankedValues(values []CountedValue, maximum int) bool {
	if len(values) > maximum || !sort.SliceIsSorted(values, func(left, right int) bool {
		if values[left].Count == values[right].Count {
			return values[left].Value < values[right].Value
		}
		return values[left].Count > values[right].Count
	}) {
		return false
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !stableReportValue.MatchString(value.Value) || value.Count == 0 {
			return false
		}
		if _, exists := seen[value.Value]; exists {
			return false
		}
		seen[value.Value] = struct{}{}
	}
	return true
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
