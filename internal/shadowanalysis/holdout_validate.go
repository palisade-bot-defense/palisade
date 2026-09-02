package shadowanalysis

import (
	"reflect"
	"slices"
	"time"

	"github.com/palisade-human-trust/palisade/internal/core"
)

func ValidateShadowHoldoutReport(report ShadowHoldoutReport) error {
	if report.SchemaVersion != ShadowHoldoutSchemaVersion || report.Split.Rule != "decision_recorded_before_cutoff_is_baseline_otherwise_holdout" {
		return ErrInvalidHoldout
	}
	cutoff, err := time.Parse(time.RFC3339, report.Split.HoldoutStart)
	if err != nil || cutoff.Location() != time.UTC || cutoff.Format(time.RFC3339) != report.Split.HoldoutStart {
		return ErrInvalidHoldout
	}
	if !validShadowHoldoutSource(report) || !validShadowHoldoutPartition(report.Baseline) || !validShadowHoldoutPartition(report.Holdout) ||
		!validShadowHoldoutLinkage(report) {
		return ErrInvalidHoldout
	}
	config := ShadowHoldoutConfig{
		HoldoutStart: report.Split.HoldoutStart, MinConfirmedHuman: report.Readiness.MinimumConfirmedHuman,
		MinConfirmedAbuse: report.Readiness.MinimumConfirmedAbuse, MaxDecisionLinks: DefaultMaxDecisionLinks,
	}
	if config.MinConfirmedHuman == 0 || config.MinConfirmedHuman > 1_000_000_000 ||
		config.MinConfirmedAbuse == 0 || config.MinConfirmedAbuse > 1_000_000_000 ||
		!reflect.DeepEqual(report.Readiness, shadowHoldoutReadiness(config, report.Baseline, report.Holdout)) {
		return ErrInvalidHoldout
	}
	wantLimitations := []string{
		"chronology is assigned by authenticated decision record time; delayed outcome time never changes the partition",
		"confirmed labels are operator or deployment assertions and do not establish causality",
		"this report does not evaluate unseen attack families and never authorizes enforcement",
	}
	if !slices.Equal(report.Limitations, wantLimitations) {
		return ErrInvalidHoldout
	}
	return nil
}

func validShadowHoldoutSource(report ShadowHoldoutReport) bool {
	source := report.Source
	var records uint64
	if !add(&records, source.Decisions) || !add(&records, source.Outcomes) || records != source.Records || source.EncryptedBytes < 0 {
		return false
	}
	if source.Records == 0 {
		return source.Files == 0 && source.FirstAt == "" && source.LastAt == ""
	}
	return source.Files > 0 && validSourceTimes(source.FirstAt, source.LastAt)
}

func validShadowHoldoutLinkage(report ShadowHoldoutReport) bool {
	linkage := report.Linkage
	var decisionRecords, outcomes, linkedOutcomes, eligibleDecisions, partitionDecisions, confirmed, ambiguous, ambiguousChallenges uint64
	if !add(&decisionRecords, linkage.UniqueDecisionIDs) || !add(&decisionRecords, linkage.DuplicateDecisionRecords) || decisionRecords != report.Source.Decisions ||
		linkage.DuplicateDecisionIDs > linkage.UniqueDecisionIDs ||
		!add(&outcomes, linkage.OutcomeEventsWithDecisionID) || !add(&outcomes, linkage.LegacyOutcomeEventsWithoutID) || outcomes != report.Source.Outcomes ||
		!add(&linkedOutcomes, linkage.MatchedOutcomeEvents) || !add(&linkedOutcomes, linkage.UnknownDecisionOutcomeEvents) ||
		!add(&linkedOutcomes, linkage.EndpointMismatchOutcomeEvents) || linkedOutcomes != linkage.OutcomeEventsWithDecisionID ||
		linkage.DuplicateOutcomeEvents > linkage.OutcomeEventsWithDecisionID {
		return false
	}
	eligibleDecisions = linkage.UniqueDecisionIDs - linkage.DuplicateDecisionIDs
	if !add(&partitionDecisions, report.Baseline.Decisions) || !add(&partitionDecisions, report.Holdout.Decisions) || partitionDecisions != eligibleDecisions ||
		!add(&confirmed, report.Baseline.Evaluation.ConfirmedLabels) || !add(&confirmed, report.Holdout.Evaluation.ConfirmedLabels) || confirmed != linkage.ConfirmedDecisionLabels ||
		!add(&ambiguous, report.Baseline.Evaluation.AmbiguousGroundTruth) || !add(&ambiguous, report.Holdout.Evaluation.AmbiguousGroundTruth) || ambiguous != linkage.AmbiguousGroundTruthDecisions ||
		!add(&ambiguousChallenges, report.Baseline.Evaluation.AmbiguousChallengeOutcomes) ||
		!add(&ambiguousChallenges, report.Holdout.Evaluation.AmbiguousChallengeOutcomes) || ambiguousChallenges != linkage.AmbiguousChallengeDecisions {
		return false
	}
	return validProportion(linkage.ConfirmedLabelCoverage) && linkage.ConfirmedLabelCoverage.Count == linkage.ConfirmedDecisionLabels &&
		linkage.ConfirmedLabelCoverage.Total == report.Source.Decisions
}

func validShadowHoldoutPartition(partition ShadowHoldoutPartition) bool {
	evaluation := partition.Evaluation
	var confirmedHuman, confirmedAbuse, labeled uint64
	if !add(&confirmedHuman, evaluation.Confusion.FalsePositive) || !add(&confirmedHuman, evaluation.Confusion.TrueNegative) ||
		!add(&confirmedAbuse, evaluation.Confusion.TruePositive) || !add(&confirmedAbuse, evaluation.Confusion.FalseNegative) ||
		!add(&labeled, evaluation.ConfirmedLabels) || !add(&labeled, evaluation.AmbiguousGroundTruth) {
		return false
	}
	if partition.Decisions != evaluation.Decisions || !validLinkedEvaluation(evaluation) ||
		partition.ConfirmedHuman != confirmedHuman || partition.ConfirmedAbuse != confirmedAbuse || labeled > evaluation.Decisions ||
		partition.UnlabeledDecisions != evaluation.Decisions-labeled ||
		len(partition.EvaluationSlices) > 54 || len(partition.AssuranceSlices) > 108 {
		return false
	}
	previousEndpoint := ""
	var previousCohort core.EvaluationCohort
	var total LinkedEvaluation
	// The assurance slices partition the same decisions a second way, so they
	// must be well formed, ordered, and sum to the same total. A slice set that
	// does not add up is a report this implementation did not produce.
	previousAssuranceEndpoint, previousAssuranceLevel := "", ""
	previousWithheld := false
	var assuranceTotal LinkedEvaluation
	for _, slice := range partition.AssuranceSlices {
		if !validAssuranceLevel(slice.AssuranceLevel) || !allowedReportEndpoint(slice.EndpointClass) ||
			!validLinkedEvaluation(slice.Evaluation) || !addLinkedEvaluation(&assuranceTotal, slice.Evaluation) {
			return false
		}
		if previousAssuranceEndpoint != "" {
			switch {
			case slice.EndpointClass < previousAssuranceEndpoint:
				return false
			case slice.EndpointClass == previousAssuranceEndpoint:
				if slice.AssuranceLevel < previousAssuranceLevel ||
					(slice.AssuranceLevel == previousAssuranceLevel && (previousWithheld || !slice.Withheld)) {
					return false
				}
			}
		}
		previousAssuranceEndpoint, previousAssuranceLevel, previousWithheld =
			slice.EndpointClass, slice.AssuranceLevel, slice.Withheld
	}
	if len(partition.AssuranceSlices) > 0 && assuranceTotal.Decisions != evaluation.Decisions {
		return false
	}
	for _, slice := range partition.EvaluationSlices {
		cohort, valid := core.NormalizeEvaluationCohort(slice.EvaluationCohort)
		if !valid || cohort != slice.EvaluationCohort || !allowedReportEndpoint(slice.EndpointClass) || !validLinkedEvaluation(slice.Evaluation) ||
			(previousEndpoint != "" && (slice.EndpointClass < previousEndpoint || (slice.EndpointClass == previousEndpoint && slice.EvaluationCohort <= previousCohort))) ||
			!addLinkedEvaluation(&total, slice.Evaluation) {
			return false
		}
		previousEndpoint, previousCohort = slice.EndpointClass, slice.EvaluationCohort
	}
	return finalizeLinkedEvaluation(total) == evaluation
}

// validAssuranceLevel accepts a decimal level or the explicit unknown bucket.
// Anything else means the report was not produced by this implementation.
func validAssuranceLevel(value string) bool {
	if value == AssuranceLevelUnknown {
		return true
	}
	return len(value) == 1 && value[0] >= '0' && value[0] <= '5'
}
