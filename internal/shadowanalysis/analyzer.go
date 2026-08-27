package shadowanalysis

import (
	"errors"
	"sort"

	"github.com/palisade-bot-defense/palisade/internal/core"
	"github.com/palisade-bot-defense/palisade/internal/shadowlog"
)

type analyzer struct {
	config          Config
	report          Report
	endpoints       map[string]*EndpointSummary
	reasons         map[string]uint64
	policies        map[string]uint64
	models          map[string]uint64
	canaries        map[string]uint64
	shadowEndpoints map[string]*modeAccumulator
	canaryEndpoints map[canaryEndpointKey]*modeAccumulator
	links           map[[32]byte]*linkedDecision
	scores          [3]scoreAccumulator
}

type modeAccumulator struct {
	decisions     uint64
	computedRisky uint64
	enforcedRisky uint64
}

type canaryEndpointKey struct {
	rolloutID string
	endpoint  string
}

type scoreAccumulator struct {
	count uint64
	min   float64
	max   float64
	sum   float64
}

func AnalyzeDirectory(directory, keyFile string, config Config) (Report, error) {
	config, err := normalizeConfig(config)
	if err != nil {
		return Report{}, err
	}
	analysis := newAnalyzer(config)
	verified, err := shadowlog.ScanDirectory(directory, keyFile, config.ScanLimits, analysis.observe)
	if err != nil {
		return Report{}, err
	}
	return analysis.finish(verified), nil
}

func newAnalyzer(config Config) *analyzer {
	return &analyzer{
		config:          config,
		report:          Report{SchemaVersion: SchemaVersion},
		endpoints:       make(map[string]*EndpointSummary),
		reasons:         make(map[string]uint64),
		policies:        make(map[string]uint64),
		models:          make(map[string]uint64),
		canaries:        make(map[string]uint64),
		shadowEndpoints: make(map[string]*modeAccumulator),
		canaryEndpoints: make(map[canaryEndpointKey]*modeAccumulator),
		links:           make(map[[32]byte]*linkedDecision),
	}
}

func (a *analyzer) observe(record shadowlog.Record) error {
	if record.Kind == "decision" {
		return a.observeDecision(record.Decision, record.RecordedAt)
	}
	return a.observeOutcome(record.Outcome)
}

func (a *analyzer) observeDecision(entry *shadowlog.DecisionEntry, recordedAt string) error {
	if err := a.observeLinkedDecision(entry, recordedAt); err != nil {
		return err
	}
	a.report.Decisions.Total++
	addAction(&a.report.Decisions.Enforced, entry.Action)
	addAction(&a.report.Decisions.Computed, entry.ComputedAction)
	if entry.Mode == core.RuntimeModeShadow {
		a.report.Decisions.Modes.Shadow++
		a.observeMode(a.shadowEndpoints, entry.EndpointClass, entry)
		if isRisky(entry.Action) {
			a.report.Decisions.ShadowRiskyEnforcements++
		}
	} else if entry.Mode == core.RuntimeModeCanary {
		a.report.Decisions.Modes.Canary++
		if err := incrementBounded(a.canaries, entry.RolloutID, a.config.MaxDistinctMetadata); err != nil {
			return err
		}
		key := canaryEndpointKey{rolloutID: entry.RolloutID, endpoint: entry.EndpointClass}
		if _, exists := a.canaryEndpoints[key]; !exists && len(a.canaryEndpoints) >= a.config.MaxDistinctMetadata {
			return ErrDistinctBudget
		}
		stats := a.canaryEndpoints[key]
		if stats == nil {
			stats = &modeAccumulator{}
			a.canaryEndpoints[key] = stats
		}
		stats.observe(entry)
	} else {
		a.report.Decisions.Modes.Enforce++
	}
	endpoint := a.endpoint(entry.EndpointClass)
	endpoint.Decisions++
	if isRisky(entry.ComputedAction) {
		endpoint.ComputedRiskyActions++
	}
	a.scores[0].add(entry.Scores.AutomationRisk)
	a.scores[1].add(entry.Scores.AbuseIntentRisk)
	a.scores[2].add(entry.Scores.AccountContinuity)
	for _, reason := range entry.ReasonCodes {
		if err := incrementBounded(a.reasons, reason, a.config.MaxDistinctMetadata); err != nil {
			return err
		}
	}
	if err := incrementBounded(a.policies, entry.PolicyVersion, a.config.MaxDistinctMetadata); err != nil {
		return err
	}
	return incrementBounded(a.models, entry.ModelVersion, a.config.MaxDistinctMetadata)
}

func (a *analyzer) observeOutcome(entry *shadowlog.OutcomeEntry) error {
	if err := a.observeLinkedOutcome(entry); err != nil {
		return err
	}
	a.report.Outcomes.Total++
	endpoint := a.endpoint(entry.EndpointClass)
	endpoint.Outcomes++
	switch entry.Outcome {
	case "successful_action":
		a.report.Outcomes.SuccessfulAction++
		endpoint.OutcomeKinds.SuccessfulAction++
	case "challenge_passed":
		a.report.Outcomes.ChallengePassed++
		endpoint.OutcomeKinds.ChallengePassed++
	case "challenge_failed":
		a.report.Outcomes.ChallengeFailed++
		endpoint.OutcomeKinds.ChallengeFailed++
	case "challenge_abandoned":
		a.report.Outcomes.ChallengeAbandoned++
		endpoint.OutcomeKinds.ChallengeAbandoned++
	case "human_confirmed":
		a.report.Outcomes.HumanConfirmed++
		endpoint.HumanConfirmed++
		endpoint.OutcomeKinds.HumanConfirmed++
	case "operator_confirmed_abuse":
		a.report.Outcomes.OperatorConfirmedAbuse++
		endpoint.OperatorConfirmedAbuse++
		endpoint.OutcomeKinds.OperatorConfirmedAbuse++
	case "appeal_requested":
		a.report.Outcomes.AppealRequested++
		endpoint.OutcomeKinds.AppealRequested++
	case "fallback_used":
		a.report.Outcomes.FallbackUsed++
		endpoint.OutcomeKinds.FallbackUsed++
	case "unknown":
		a.report.Outcomes.Unknown++
		endpoint.OutcomeKinds.Unknown++
	}
	return nil
}

func (a *analyzer) finish(source shadowlog.Verification) Report {
	a.report.Source = source
	decisions := a.report.Decisions.Total
	if decisions > 0 {
		a.report.Decisions.ComputedChallengeRate = float64(a.report.Decisions.Computed.Challenge) / float64(decisions)
		a.report.Outcomes.Coverage = minimum(1, float64(a.report.Outcomes.Total)/float64(decisions))
	}
	a.report.Outcomes.ChallengeResults = a.report.Outcomes.ChallengePassed + a.report.Outcomes.ChallengeFailed + a.report.Outcomes.ChallengeAbandoned
	if a.report.Outcomes.ChallengeResults > 0 {
		a.report.Outcomes.ChallengeFailureRate = float64(a.report.Outcomes.ChallengeFailed+a.report.Outcomes.ChallengeAbandoned) / float64(a.report.Outcomes.ChallengeResults)
	}
	a.report.Scores = ScoreSummaries{
		AutomationRisk: a.scores[0].summary(), AbuseIntentRisk: a.scores[1].summary(), AccountContinuity: a.scores[2].summary(),
	}
	a.finishLinkage(source)
	for _, endpoint := range a.endpoints {
		endpoint.Evaluation = evaluateEndpoint(*endpoint)
	}
	a.report.Endpoints = sortedEndpoints(a.endpoints)
	a.report.TopReasonCodes = sortedCounts(a.reasons, a.config.TopReasonCodes)
	a.report.PolicyVersions = sortedCounts(a.policies, a.config.MaxDistinctMetadata)
	a.report.ModelVersions = sortedCounts(a.models, a.config.MaxDistinctMetadata)
	a.report.CanaryRollouts = sortedCounts(a.canaries, a.config.MaxDistinctMetadata)
	a.report.CanaryComparisons = a.sortedCanaryComparisons()
	a.report.Recommendations, a.report.Readiness = recommend(a.report, a.config)
	return a.report
}

func recommend(report Report, config Config) ([]Recommendation, Readiness) {
	var recommendations []Recommendation
	var reasons []string
	linkedHumans, linkedAbuse := linkedLabelCounts(report.Endpoints)
	matureChallenges, challengeFriction := linkedChallengeFriction(report.Endpoints)
	add := func(code, priority, disposition, metric string, observed, threshold float64, unit, message string) {
		recommendations = append(recommendations, Recommendation{
			Code: code, Priority: priority, Disposition: disposition, Metric: metric,
			Observed: observed, Threshold: threshold, Unit: unit, Message: message,
		})
		reasons = append(reasons, code)
	}
	if report.Decisions.ShadowRiskyEnforcements > 0 {
		add("FIX_SHADOW_ENFORCEMENT", "critical", "required", "shadow_risky_enforcements", float64(report.Decisions.ShadowRiskyEnforcements), 0, "count", "Shadow records enforced a risky action; restore the shadow safety boundary before further rollout.")
	}
	if report.Decisions.Total < config.MinDecisions {
		add("COLLECT_MORE_DECISIONS", "high", "required", "decisions", float64(report.Decisions.Total), float64(config.MinDecisions), "count", "Collect a larger local shadow sample across a complete traffic cycle.")
	}
	if report.Linkage.ConfirmedLabelCoverage.Rate < config.MinOutcomeCoverage {
		add("IMPROVE_OUTCOME_COVERAGE", "high", "required", "linked_label_coverage", report.Linkage.ConfirmedLabelCoverage.Rate, config.MinOutcomeCoverage, "ratio", "Increase uniquely linked confirmed-label coverage before estimating false positives or abuse recall.")
	}
	if linkedHumans < config.MinConfirmedHumans {
		add("EXPAND_CONFIRMED_HUMANS", "high", "required", "linked_human_confirmed", float64(linkedHumans), float64(config.MinConfirmedHumans), "count", "Add authenticated or operator-reviewed human outcomes linked to their exact decision; challenge completion is not a human label.")
	}
	if linkedAbuse < config.MinConfirmedAbuse {
		add("EXPAND_CONFIRMED_ABUSE", "medium", "required", "linked_operator_confirmed_abuse", float64(linkedAbuse), float64(config.MinConfirmedAbuse), "count", "Add operator-confirmed abuse outcomes linked to their exact decision to measure precision without treating automation as abuse.")
	}
	if report.Decisions.ComputedChallengeRate > config.MaxChallengeRate {
		add("REVIEW_COMPUTED_CHALLENGE_RATE", "medium", "required", "computed_challenge_rate", report.Decisions.ComputedChallengeRate, config.MaxChallengeRate, "ratio", "Review endpoint-specific step-up thresholds and accessibility impact before any canary.")
	}
	if matureChallenges >= config.MinChallengeResults && challengeFriction > config.MaxChallengeFailure {
		add("REDUCE_CHALLENGE_FRICTION", "high", "required", "linked_challenge_friction_rate", challengeFriction, config.MaxChallengeFailure, "ratio", "Linked mature challenge failure, abandonment, unresolved or ambiguous outcomes are above the review budget; improve fallback, instrumentation and accessibility first.")
	}

	readiness := Readiness{AutomaticEnforcement: false, ReasonCodes: reasons}
	switch {
	case report.Decisions.ShadowRiskyEnforcements > 0:
		readiness.State = "invalid_shadow_behavior"
		readiness.OperatorAction = "remain_shadow"
	case report.Decisions.Total < config.MinDecisions:
		readiness.State = "collecting"
		readiness.OperatorAction = "remain_shadow"
	case report.Linkage.ConfirmedLabelCoverage.Rate < config.MinOutcomeCoverage || linkedHumans < config.MinConfirmedHumans || linkedAbuse < config.MinConfirmedAbuse:
		readiness.State = "needs_labels"
		readiness.OperatorAction = "remain_shadow"
	case report.Decisions.ComputedChallengeRate > config.MaxChallengeRate ||
		(matureChallenges >= config.MinChallengeResults && challengeFriction > config.MaxChallengeFailure):
		readiness.State = "needs_tuning"
		readiness.OperatorAction = "remain_shadow"
	default:
		readiness.State = "operator_review_candidate"
		readiness.OperatorAction = "review_reversible_canary"
		recommendations = append(recommendations, Recommendation{
			Code: "PREPARE_OPERATOR_REVIEW", Priority: "low", Disposition: "review_candidate", Metric: "automatic_enforcement", Observed: 0, Threshold: 0,
			Unit: "boolean", Message: "Evidence gates are populated; an operator may review endpoint-specific confidence intervals and a reversible canary. PALISADE does not enable enforcement automatically.",
		})
	}
	if readiness.OperatorAction == "remain_shadow" {
		recommendations = append(recommendations, Recommendation{
			Code: "KEEP_SHADOW_MODE", Priority: "high", Disposition: "hold", Metric: "automatic_enforcement", Observed: 0, Threshold: 0,
			Unit: "boolean", Message: "Keep enforcement disabled until the listed evidence and safety gaps are resolved and reviewed by an operator.",
		})
	}
	return recommendations, readiness
}

func linkedLabelCounts(endpoints []EndpointSummary) (humans, abuse uint64) {
	for _, endpoint := range endpoints {
		humans += endpoint.LinkedEvaluation.Confusion.FalsePositive + endpoint.LinkedEvaluation.Confusion.TrueNegative
		abuse += endpoint.LinkedEvaluation.Confusion.TruePositive + endpoint.LinkedEvaluation.Confusion.FalseNegative
	}
	return humans, abuse
}

func linkedChallengeFriction(endpoints []EndpointSummary) (mature uint64, rate float64) {
	var friction uint64
	for _, endpoint := range endpoints {
		evaluation := endpoint.LinkedEvaluation
		mature += evaluation.MatureChallenges
		friction += evaluation.ChallengeFailed + evaluation.ChallengeAbandoned + evaluation.UnresolvedMatureChallenges + evaluation.AmbiguousChallengeOutcomes
	}
	return mature, ratio(friction, mature)
}

func normalizeConfig(config Config) (Config, error) {
	if config.MinDecisions == 0 {
		config.MinDecisions = DefaultMinDecisions
	}
	if config.MinOutcomeCoverage == 0 {
		config.MinOutcomeCoverage = DefaultMinOutcomeCoverage
	}
	if config.MinConfirmedHumans == 0 {
		config.MinConfirmedHumans = DefaultMinConfirmedHumans
	}
	if config.MinConfirmedAbuse == 0 {
		config.MinConfirmedAbuse = DefaultMinConfirmedAbuse
	}
	if config.MaxChallengeRate == 0 {
		config.MaxChallengeRate = DefaultMaxChallengeRate
	}
	if config.MaxChallengeFailure == 0 {
		config.MaxChallengeFailure = DefaultMaxChallengeFailure
	}
	if config.MinChallengeResults == 0 {
		config.MinChallengeResults = DefaultMinChallengeResults
	}
	if config.MaxDistinctMetadata == 0 {
		config.MaxDistinctMetadata = DefaultMaxDistinctMetadata
	}
	if config.TopReasonCodes == 0 {
		config.TopReasonCodes = DefaultTopReasonCodes
	}
	if config.MaxDecisionLinks == 0 {
		config.MaxDecisionLinks = DefaultMaxDecisionLinks
	}
	if config.MinOutcomeCoverage <= 0 || config.MinOutcomeCoverage > 1 || config.MaxChallengeRate <= 0 || config.MaxChallengeRate > 1 ||
		config.MaxChallengeFailure <= 0 || config.MaxChallengeFailure > 1 || config.MaxDistinctMetadata < 16 || config.MaxDistinctMetadata > 4096 ||
		config.TopReasonCodes < 1 || config.TopReasonCodes > config.MaxDistinctMetadata || config.MaxDecisionLinks < 1 || config.MaxDecisionLinks > MaximumDecisionLinks {
		return Config{}, errors.New("shadow analysis thresholds are outside supported bounds")
	}
	return config, nil
}

func (a *analyzer) endpoint(name string) *EndpointSummary {
	if existing := a.endpoints[name]; existing != nil {
		return existing
	}
	created := &EndpointSummary{EndpointClass: name}
	a.endpoints[name] = created
	return created
}

func (a *analyzer) observeMode(values map[string]*modeAccumulator, endpoint string, entry *shadowlog.DecisionEntry) {
	stats := values[endpoint]
	if stats == nil {
		stats = &modeAccumulator{}
		values[endpoint] = stats
	}
	stats.observe(entry)
}

func (s *modeAccumulator) observe(entry *shadowlog.DecisionEntry) {
	s.decisions++
	if isRisky(entry.ComputedAction) {
		s.computedRisky++
	}
	if isRisky(entry.Action) {
		s.enforcedRisky++
	}
}

func evaluateEndpoint(endpoint EndpointSummary) EndpointEvaluation {
	challengeResults := endpoint.OutcomeKinds.ChallengePassed + endpoint.OutcomeKinds.ChallengeFailed + endpoint.OutcomeKinds.ChallengeAbandoned
	confirmedLabels := endpoint.HumanConfirmed + endpoint.OperatorConfirmedAbuse
	return EndpointEvaluation{
		ComputedRiskyRate:        Proportion(endpoint.ComputedRiskyActions, endpoint.Decisions),
		ChallengeFailureRate:     Proportion(endpoint.OutcomeKinds.ChallengeFailed+endpoint.OutcomeKinds.ChallengeAbandoned, challengeResults),
		ChallengeAbandonmentRate: Proportion(endpoint.OutcomeKinds.ChallengeAbandoned, challengeResults),
		FallbackOutcomeShare:     Proportion(endpoint.OutcomeKinds.FallbackUsed, endpoint.Outcomes),
		AppealOutcomeShare:       Proportion(endpoint.OutcomeKinds.AppealRequested, endpoint.Outcomes),
		UnknownOutcomeShare:      Proportion(endpoint.OutcomeKinds.Unknown, endpoint.Outcomes),
		ConfirmedLabels:          confirmedLabels,
		AbuseLabelShare:          Proportion(endpoint.OperatorConfirmedAbuse, confirmedLabels),
	}
}

func (a *analyzer) sortedCanaryComparisons() []CanaryComparison {
	keys := make([]canaryEndpointKey, 0, len(a.canaryEndpoints))
	for key := range a.canaryEndpoints {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(left, right int) bool {
		if keys[left].rolloutID == keys[right].rolloutID {
			return keys[left].endpoint < keys[right].endpoint
		}
		return keys[left].rolloutID < keys[right].rolloutID
	})
	result := make([]CanaryComparison, 0, len(keys))
	for _, key := range keys {
		canary := a.canaryEndpoints[key]
		shadow := a.shadowEndpoints[key.endpoint]
		if shadow == nil {
			shadow = &modeAccumulator{}
		}
		shadowRisky := Proportion(shadow.computedRisky, shadow.decisions)
		canaryRisky := Proportion(canary.computedRisky, canary.decisions)
		comparable := shadow.decisions > 0 && canary.decisions > 0
		difference := DifferenceEstimate{}
		if comparable {
			difference = ProportionDifference(canaryRisky, shadowRisky)
		}
		result = append(result, CanaryComparison{
			RolloutID: key.rolloutID, EndpointClass: key.endpoint,
			Comparable:      comparable,
			ShadowDecisions: shadow.decisions, CanaryDecisions: canary.decisions,
			ShadowComputedRisky: shadowRisky, CanaryComputedRisky: canaryRisky,
			CanaryEnforcedRisky:    Proportion(canary.enforcedRisky, canary.decisions),
			ComputedRiskDifference: difference,
		})
	}
	if result == nil {
		return []CanaryComparison{}
	}
	return result
}

func (s *scoreAccumulator) add(value float64) {
	if s.count == 0 || value < s.min {
		s.min = value
	}
	if s.count == 0 || value > s.max {
		s.max = value
	}
	s.count++
	s.sum += value
}

func (s scoreAccumulator) summary() ScoreSummary {
	if s.count == 0 {
		return ScoreSummary{}
	}
	mean := s.sum / float64(s.count)
	if mean < s.min {
		mean = s.min
	} else if mean > s.max {
		mean = s.max
	}
	return ScoreSummary{Minimum: s.min, Maximum: s.max, Mean: mean}
}

func incrementBounded(values map[string]uint64, value string, limit int) error {
	if _, exists := values[value]; !exists && len(values) >= limit {
		return ErrDistinctBudget
	}
	values[value]++
	return nil
}

func addAction(counts *ActionCounts, action core.Action) {
	switch action {
	case core.ActionAllow:
		counts.Allow++
	case core.ActionObserve:
		counts.Observe++
	case core.ActionThrottle:
		counts.Throttle++
	case core.ActionChallenge:
		counts.Challenge++
	case core.ActionBlock:
		counts.Block++
	}
}

func isRisky(action core.Action) bool {
	return action == core.ActionThrottle || action == core.ActionChallenge || action == core.ActionBlock
}

func sortedEndpoints(values map[string]*EndpointSummary) []EndpointSummary {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]EndpointSummary, 0, len(keys))
	for _, key := range keys {
		result = append(result, *values[key])
	}
	if result == nil {
		return []EndpointSummary{}
	}
	return result
}

func sortedCounts(values map[string]uint64, limit int) []CountedValue {
	result := make([]CountedValue, 0, len(values))
	for value, count := range values {
		result = append(result, CountedValue{Value: value, Count: count})
	}
	sort.Slice(result, func(left, right int) bool {
		if result[left].Count == result[right].Count {
			return result[left].Value < result[right].Value
		}
		return result[left].Count > result[right].Count
	})
	if len(result) > limit {
		result = result[:limit]
	}
	if result == nil {
		return []CountedValue{}
	}
	return result
}

func minimum(left, right float64) float64 {
	if left < right {
		return left
	}
	return right
}
