package localsequence

import (
	"encoding/hex"
	"errors"
	"reflect"
	"strings"

	"github.com/palisade-bot-defense/palisade/internal/offlineimport"
	"github.com/palisade-bot-defense/palisade/internal/shadowanalysis"
)

func ValidateHoldoutReport(report HoldoutReport) error {
	if report.SchemaVersion != HoldoutSchemaVersion || report.SourceSchemaVersion != offlineimport.LocalEventSchemaVersion ||
		report.Config.MaxActiveSequences < 1 || report.Config.MaxActiveSequences > MaximumMaxActiveSequences ||
		report.Config.MaxScanShards < 1 || report.Config.MaxScanShards > offlineimport.MaximumShardCount ||
		report.Config.MaxScanEvents < 1 || report.Config.MaxScanEvents > offlineimport.MaximumLocalScanEvents ||
		report.Config.MaxScanBytes < 1 || report.Config.MaxScanBytes > offlineimport.MaximumLocalScanBytes ||
		report.Config.MinConfirmedPerLabel < 1 || report.Config.MinConfirmedPerLabel > MaximumMinEvaluationLabels ||
		report.Config.MinUnseenAbuse < 1 || report.Config.MinUnseenAbuse > MaximumMinEvaluationLabels ||
		report.Config.MaxFamilyRecords < 1 || report.Config.MaxFamilyRecords > MaximumMaxFamilyRecords ||
		report.Config.MaxFamilyBytes < 1 || report.Config.MaxFamilyBytes > MaximumMaxFamilyBytes ||
		report.Config.MaxFamilyLineBytes < 256 || report.Config.MaxFamilyLineBytes > MaximumMaxFamilyLineBytes {
		return errors.New("local holdout report metadata is invalid")
	}
	if report.Split.Method != "predeclared_window_start" || !validUTC(report.Split.HoldoutStart) ||
		!validFeatureDefinitions(report.FeatureDefinitions) || !reflect.DeepEqual(report.RuleDefinitions, holdoutRuleDefinitions) ||
		!equalStrings(report.Limitations, holdoutLimitations) {
		return errors.New("local holdout report definitions are invalid")
	}
	if report.Source.Shards > uint64(report.Config.MaxScanShards) || report.Source.Events > report.Config.MaxScanEvents ||
		report.Source.Bytes < 0 || report.Source.Bytes > report.Config.MaxScanBytes || report.Source.Sequences > report.Source.Events {
		return errors.New("local holdout report source totals are invalid")
	}
	if report.Source.Events == 0 {
		if report.Source.Sequences != 0 || report.Source.FirstAt != "" || report.Source.LastAt != "" {
			return errors.New("empty local holdout report has observations")
		}
	} else if report.Source.Shards == 0 || report.Source.Bytes == 0 || report.Source.Sequences == 0 || !validUTC(report.Source.FirstAt) || !validUTC(report.Source.LastAt) || report.Source.LastAt < report.Source.FirstAt {
		return errors.New("local holdout report source range is invalid")
	}
	if !validPartition(report.Partitions.Baseline) || !validPartition(report.Partitions.Holdout) || !validPartition(report.Partitions.UnseenFamilyHoldout) ||
		!labelSum(report.Split.BoundaryLabels, report.Split.BoundaryWindowsExcluded) ||
		!equalSum(report.Source.Sequences, report.Partitions.Baseline.Windows, report.Partitions.Holdout.Windows, report.Split.BoundaryWindowsExcluded) ||
		!equalSum(report.Source.Events, report.Partitions.Baseline.Events, report.Partitions.Holdout.Events, report.Split.BoundaryEventsExcluded) ||
		report.Partitions.UnseenFamilyHoldout.Windows > report.Partitions.Holdout.Windows || report.Partitions.UnseenFamilyHoldout.Events > report.Partitions.Holdout.Events ||
		!labelsAtMost(report.Partitions.UnseenFamilyHoldout.Labels, report.Partitions.Holdout.Labels) {
		return errors.New("local holdout report partition totals are inconsistent")
	}
	families := report.Families
	if !equalSum(report.Source.Sequences, families.AnnotatedWindows, families.UnannotatedWindows) ||
		families.AnnotationRecords > report.Config.MaxFamilyRecords || families.AnnotationBytes < 0 || families.AnnotationBytes > report.Config.MaxFamilyBytes ||
		families.BaselineDistinct > families.AnnotationRecords || families.HoldoutDistinct > families.AnnotationRecords || families.UnseenDistinct > families.HoldoutDistinct ||
		families.UnseenHoldoutWindows != report.Partitions.UnseenFamilyHoldout.Windows ||
		!equalSum(report.Partitions.Baseline.Labels.OperatorConfirmedAbuse+report.Partitions.Holdout.Labels.OperatorConfirmedAbuse,
			families.AnnotatedConfirmedAbuseWindows, families.UnannotatedConfirmedAbuseWindows) {
		return errors.New("local holdout report family totals are inconsistent")
	}
	if families.AnnotationsSupplied {
		if !validHexSHA256(families.AnnotationSHA256) {
			return errors.New("local holdout report family fingerprint is invalid")
		}
	} else if families.AnnotationRecords != 0 || families.AnnotationBytes != 0 || families.AnnotationSHA256 != "" || families.AnnotatedWindows != 0 ||
		families.BaselineDistinct != 0 || families.HoldoutDistinct != 0 || families.UnseenDistinct != 0 || families.UnseenHoldoutWindows != 0 ||
		families.AnnotatedConfirmedAbuseWindows != 0 {
		return errors.New("local holdout report contains family results without annotations")
	}
	if expected := expectedReadiness(report); !reflect.DeepEqual(report.Readiness, expected) {
		return errors.New("local holdout report readiness is inconsistent")
	}
	return nil
}

func validFeatureDefinitions(definitions FeatureDefinitions) bool {
	return definitions.InactivitySeconds == int64(InactivityWindow.Seconds()) &&
		definitions.MaximumWindowSeconds == int64(MaximumWindowDuration.Seconds()) &&
		definitions.ClusteredMinimumEvents == clusteredMinimumEvents &&
		definitions.ClusteredMaximumDurationSeconds == int64(clusteredMaximumDuration.Seconds()) &&
		definitions.HighRateMinimumPeakMinuteEvents == highRateMinimumPeakMinute &&
		definitions.SustainedMinimumEvents == sustainedMinimumEvents &&
		definitions.SustainedMinimumDurationSeconds == int64(sustainedMinimumDuration.Seconds())
}

func validPartition(partition PartitionEvaluation) bool {
	if !labelSum(partition.Labels, partition.Windows) || !equalSum(partition.Windows, partition.Collection.Clean, partition.Collection.WithArtifact) ||
		!validRuleEvaluations(partition.Rules, partition.Labels) || len(partition.Endpoints) != 7 {
		return false
	}
	endpointNames := []string{"public_content", "account", "authentication", "transaction", "api", "decoy", "other"}
	for index, endpoint := range partition.Endpoints {
		if endpoint.EndpointClass != endpointNames[index] || endpoint.Windows > partition.Windows || !labelSum(endpoint.Labels, endpoint.Windows) ||
			!labelsAtMost(endpoint.Labels, partition.Labels) || !validRuleEvaluations(endpoint.Rules, endpoint.Labels) {
			return false
		}
	}
	return true
}

func validRuleEvaluations(rules []RuleEvaluation, labels LabelSummary) bool {
	if len(rules) != len(holdoutRuleDefinitions) {
		return false
	}
	for index, rule := range rules {
		if rule.RuleID != holdoutRuleDefinitions[index].ID || !labelsCombine(rule.Flagged, rule.Unflagged, labels) ||
			rule.ConfirmedHumanFlagRate != shadowanalysis.Proportion(rule.Flagged.HumanConfirmed, labels.HumanConfirmed) ||
			rule.ConfirmedAbuseCaptureRate != shadowanalysis.Proportion(rule.Flagged.OperatorConfirmedAbuse, labels.OperatorConfirmedAbuse) ||
			rule.UnknownFlagRate != shadowanalysis.Proportion(rule.Flagged.Unknown, labels.Unknown) {
			return false
		}
	}
	return true
}

func labelSum(labels LabelSummary, total uint64) bool {
	return equalSum(total, labels.Unknown, labels.HumanConfirmed, labels.OperatorConfirmedAbuse, labels.Ambiguous)
}

func labelsCombine(left, right, total LabelSummary) bool {
	return equalSum(total.Unknown, left.Unknown, right.Unknown) &&
		equalSum(total.HumanConfirmed, left.HumanConfirmed, right.HumanConfirmed) &&
		equalSum(total.OperatorConfirmedAbuse, left.OperatorConfirmedAbuse, right.OperatorConfirmedAbuse) &&
		equalSum(total.Ambiguous, left.Ambiguous, right.Ambiguous)
}

func labelsAtMost(left, right LabelSummary) bool {
	return left.Unknown <= right.Unknown && left.HumanConfirmed <= right.HumanConfirmed &&
		left.OperatorConfirmedAbuse <= right.OperatorConfirmedAbuse && left.Ambiguous <= right.Ambiguous
}

func validHexSHA256(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32 && value == strings.ToLower(value)
}
