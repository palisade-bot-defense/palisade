package localsequence

import (
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/palisade-human-trust/palisade/internal/offlineimport"
	"github.com/palisade-human-trust/palisade/internal/shadowanalysis"
)

var holdoutRuleDefinitions = []RuleDefinition{
	{ID: "burst_behavior", Description: "clustered or high-rate burst shape"},
	{ID: "automation_high", Description: "maximum operator-declared automation evidence is high"},
	{ID: "abuse_intent_high", Description: "maximum operator-declared abuse-intent evidence is high"},
	{ID: "active_decoy", Description: "decoy interaction reached touched or submitted"},
	{ID: "combined_candidate", Description: "burst behavior, high automation, high abuse intent or active decoy"},
}

var holdoutLimitations = []string{
	"candidate rules are fixed diagnostics and are not production enforcement thresholds",
	"operator evidence and family mappings are declarations and are not independently verified",
	"unknown labels are not confirmed-human labels",
	"boundary-crossing windows are excluded from both chronological partitions",
	"endpoint membership slices are non-exclusive and must not be summed",
	"challenge completion does not establish humanity",
	"unseen family status is relative only to supplied annotation coverage",
	"the report emits no subject, session or family identifiers and no row-level events",
}

type holdoutEvaluator struct {
	cutoff           time.Time
	families         familyIndex
	baselineFamilies map[[32]byte]bool
	holdoutFamilies  map[[32]byte]bool
	unseenFamilies   map[[32]byte]bool
	report           HoldoutReport
}

func AnalyzeHoldoutDirectory(directory string, config HoldoutConfig) (HoldoutReport, error) {
	config, cutoff, err := normalizeHoldoutConfig(config)
	if err != nil {
		return HoldoutReport{}, err
	}
	families, err := loadFamilyAnnotations(config.FamilyAnnotations, config)
	if err != nil {
		return HoldoutReport{}, err
	}
	evaluator := newHoldoutEvaluator(config, cutoff, families)
	sequenceAnalyzer := newAnalyzer(config.Sequence)
	sequenceAnalyzer.onWindow = evaluator.observe
	_, verified, err := offlineimport.ScanLocalDirectory(directory, config.Sequence.ScanLimits, sequenceAnalyzer.observe)
	if err != nil {
		return HoldoutReport{}, err
	}
	if err := sequenceAnalyzer.finish(); err != nil {
		return HoldoutReport{}, err
	}
	evaluator.report.Source = SourceSummary{
		Shards: verified.Shards, Events: verified.Events, Bytes: verified.Bytes, Sequences: sequenceAnalyzer.report.Source.Sequences,
		FirstAt: verified.FirstAt, LastAt: verified.LastAt,
	}
	evaluator.finish()
	if err := ValidateHoldoutReport(evaluator.report); err != nil {
		return HoldoutReport{}, err
	}
	return evaluator.report, nil
}

func normalizeHoldoutConfig(config HoldoutConfig) (HoldoutConfig, time.Time, error) {
	sequence, err := normalizeConfig(config.Sequence)
	if err != nil {
		return HoldoutConfig{}, time.Time{}, err
	}
	config.Sequence = sequence
	cutoff, err := time.Parse(time.RFC3339Nano, config.HoldoutStart)
	if err != nil || cutoff.Location() != time.UTC || !strings.HasSuffix(config.HoldoutStart, "Z") {
		return HoldoutConfig{}, time.Time{}, errors.New("local holdout start must be UTC RFC3339 with a Z suffix")
	}
	config.HoldoutStart = cutoff.Format(time.RFC3339Nano)
	if config.MinConfirmedPerLabel == 0 {
		config.MinConfirmedPerLabel = DefaultMinConfirmedPerLabel
	}
	if config.MinUnseenAbuse == 0 {
		config.MinUnseenAbuse = DefaultMinUnseenAbuse
	}
	if config.MaxFamilyRecords == 0 {
		config.MaxFamilyRecords = DefaultMaxFamilyRecords
	}
	if config.MaxFamilyBytes == 0 {
		config.MaxFamilyBytes = DefaultMaxFamilyBytes
	}
	if config.MaxFamilyLineBytes == 0 {
		config.MaxFamilyLineBytes = DefaultMaxFamilyLineBytes
	}
	if config.MinConfirmedPerLabel > MaximumMinEvaluationLabels || config.MinUnseenAbuse > MaximumMinEvaluationLabels ||
		config.MaxFamilyRecords < 1 || config.MaxFamilyRecords > MaximumMaxFamilyRecords ||
		config.MaxFamilyBytes < 1 || config.MaxFamilyBytes > MaximumMaxFamilyBytes ||
		config.MaxFamilyLineBytes < 256 || config.MaxFamilyLineBytes > MaximumMaxFamilyLineBytes {
		return HoldoutConfig{}, time.Time{}, errors.New("local holdout limits are outside supported bounds")
	}
	return config, cutoff, nil
}

func newHoldoutEvaluator(config HoldoutConfig, cutoff time.Time, families familyIndex) *holdoutEvaluator {
	evaluator := &holdoutEvaluator{
		cutoff: cutoff, families: families,
		baselineFamilies: make(map[[32]byte]bool), holdoutFamilies: make(map[[32]byte]bool), unseenFamilies: make(map[[32]byte]bool),
		report: HoldoutReport{
			SchemaVersion: HoldoutSchemaVersion, SourceSchemaVersion: offlineimport.LocalEventSchemaVersion,
			Config: HoldoutReportConfig{
				MaxActiveSequences: config.Sequence.MaxActiveSequences, MaxScanShards: config.Sequence.ScanLimits.MaxShards,
				MaxScanEvents: config.Sequence.ScanLimits.MaxEvents, MaxScanBytes: config.Sequence.ScanLimits.MaxBytes,
				MinConfirmedPerLabel: config.MinConfirmedPerLabel, MinUnseenAbuse: config.MinUnseenAbuse,
				MaxFamilyRecords: config.MaxFamilyRecords, MaxFamilyBytes: config.MaxFamilyBytes, MaxFamilyLineBytes: config.MaxFamilyLineBytes,
			},
			FeatureDefinitions: FeatureDefinitions{
				InactivitySeconds: int64(InactivityWindow / time.Second), MaximumWindowSeconds: int64(MaximumWindowDuration / time.Second),
				ClusteredMinimumEvents: clusteredMinimumEvents, ClusteredMaximumDurationSeconds: int64(clusteredMaximumDuration / time.Second),
				HighRateMinimumPeakMinuteEvents: highRateMinimumPeakMinute, SustainedMinimumEvents: sustainedMinimumEvents,
				SustainedMinimumDurationSeconds: int64(sustainedMinimumDuration / time.Second),
			},
			RuleDefinitions: slices.Clone(holdoutRuleDefinitions),
			Split:           ChronologicalSplit{Method: "predeclared_window_start", HoldoutStart: config.HoldoutStart},
			Families: FamilySummary{
				AnnotationsSupplied: config.FamilyAnnotations != "", AnnotationRecords: families.records,
				AnnotationBytes: families.bytes, AnnotationSHA256: families.sha256,
			},
			Partitions: HoldoutPartitions{
				Baseline: newPartition(), Holdout: newPartition(), UnseenFamilyHoldout: newPartition(),
			},
			Limitations: slices.Clone(holdoutLimitations),
		},
	}
	return evaluator
}

func newPartition() PartitionEvaluation {
	partition := PartitionEvaluation{Rules: newRuleEvaluations()}
	for _, endpoint := range []string{"public_content", "account", "authentication", "transaction", "api", "decoy", "other"} {
		partition.Endpoints = append(partition.Endpoints, EndpointEvaluation{EndpointClass: endpoint, Rules: newRuleEvaluations()})
	}
	return partition
}

func newRuleEvaluations() []RuleEvaluation {
	result := make([]RuleEvaluation, len(holdoutRuleDefinitions))
	for index, definition := range holdoutRuleDefinitions {
		result[index].RuleID = definition.ID
	}
	return result
}

func (evaluator *holdoutEvaluator) observe(window windowFeature) error {
	family, annotated := evaluator.families.familyFor(window.key)
	if annotated {
		evaluator.report.Families.AnnotatedWindows++
	} else {
		evaluator.report.Families.UnannotatedWindows++
	}
	if window.first.Before(evaluator.cutoff) && !window.last.Before(evaluator.cutoff) {
		evaluator.report.Split.BoundaryWindowsExcluded++
		evaluator.report.Split.BoundaryEventsExcluded += window.events
		incrementLabel(&evaluator.report.Split.BoundaryLabels, windowLabel(window))
		return nil
	}
	if windowLabel(window) == "operator_confirmed_abuse" {
		if annotated {
			evaluator.report.Families.AnnotatedConfirmedAbuseWindows++
		} else {
			evaluator.report.Families.UnannotatedConfirmedAbuseWindows++
		}
	}
	if window.last.Before(evaluator.cutoff) {
		recordPartition(&evaluator.report.Partitions.Baseline, window)
		if annotated {
			evaluator.baselineFamilies[family] = true
		}
		return nil
	}
	recordPartition(&evaluator.report.Partitions.Holdout, window)
	if annotated {
		evaluator.holdoutFamilies[family] = true
		if !evaluator.baselineFamilies[family] {
			evaluator.unseenFamilies[family] = true
			recordPartition(&evaluator.report.Partitions.UnseenFamilyHoldout, window)
			evaluator.report.Families.UnseenHoldoutWindows++
		}
	}
	return nil
}

func recordPartition(partition *PartitionEvaluation, window windowFeature) {
	partition.Windows++
	partition.Events += window.events
	label := windowLabel(window)
	incrementLabel(&partition.Labels, label)
	if window.collectionIssue {
		partition.Collection.WithArtifact++
	} else {
		partition.Collection.Clean++
	}
	matches := ruleMatches(window)
	recordRules(partition.Rules, label, matches)
	for index, seen := range window.endpointSeen {
		if !seen {
			continue
		}
		endpoint := &partition.Endpoints[index]
		endpoint.Windows++
		incrementLabel(&endpoint.Labels, label)
		recordRules(endpoint.Rules, label, matches)
	}
}

func recordRules(rules []RuleEvaluation, label string, matches [5]bool) {
	for index := range rules {
		if matches[index] {
			incrementLabel(&rules[index].Flagged, label)
		} else {
			incrementLabel(&rules[index].Unflagged, label)
		}
	}
}

func ruleMatches(window windowFeature) [5]bool {
	burst := window.burstShape == "clustered" || window.burstShape == "high_rate"
	automation := window.automation == 3
	abuse := window.abuseIntent == 3
	decoy := window.decoy >= 2
	return [5]bool{burst, automation, abuse, decoy, burst || automation || abuse || decoy}
}

func windowLabel(window windowFeature) string {
	switch {
	case window.humanLabel && window.abuseLabel:
		return "ambiguous"
	case window.humanLabel:
		return "human_confirmed"
	case window.abuseLabel:
		return "operator_confirmed_abuse"
	default:
		return "unknown"
	}
}

func incrementLabel(labels *LabelSummary, label string) {
	switch label {
	case "human_confirmed":
		labels.HumanConfirmed++
	case "operator_confirmed_abuse":
		labels.OperatorConfirmedAbuse++
	case "ambiguous":
		labels.Ambiguous++
	default:
		labels.Unknown++
	}
}

func (evaluator *holdoutEvaluator) finish() {
	evaluator.report.Families.BaselineDistinct = uint64(len(evaluator.baselineFamilies))
	evaluator.report.Families.HoldoutDistinct = uint64(len(evaluator.holdoutFamilies))
	evaluator.report.Families.UnseenDistinct = uint64(len(evaluator.unseenFamilies))
	finishPartition(&evaluator.report.Partitions.Baseline)
	finishPartition(&evaluator.report.Partitions.Holdout)
	finishPartition(&evaluator.report.Partitions.UnseenFamilyHoldout)
	evaluator.report.Readiness = expectedReadiness(evaluator.report)
}

func finishPartition(partition *PartitionEvaluation) {
	finishRules(partition.Rules, partition.Labels)
	for index := range partition.Endpoints {
		finishRules(partition.Endpoints[index].Rules, partition.Endpoints[index].Labels)
	}
}

func finishRules(rules []RuleEvaluation, labels LabelSummary) {
	for index := range rules {
		rules[index].ConfirmedHumanFlagRate = shadowanalysis.Proportion(rules[index].Flagged.HumanConfirmed, labels.HumanConfirmed)
		rules[index].ConfirmedAbuseCaptureRate = shadowanalysis.Proportion(rules[index].Flagged.OperatorConfirmedAbuse, labels.OperatorConfirmedAbuse)
		rules[index].UnknownFlagRate = shadowanalysis.Proportion(rules[index].Flagged.Unknown, labels.Unknown)
	}
}

func expectedReadiness(report HoldoutReport) EvaluationReadiness {
	reasons := make([]string, 0, 7)
	baseline := report.Partitions.Baseline
	holdout := report.Partitions.Holdout
	if baseline.Windows == 0 {
		reasons = append(reasons, "baseline_empty")
	}
	if holdout.Windows == 0 {
		reasons = append(reasons, "holdout_empty")
	}
	minimum := report.Config.MinConfirmedPerLabel
	if baseline.Labels.HumanConfirmed < minimum {
		reasons = append(reasons, "baseline_confirmed_human_below_minimum")
	}
	if baseline.Labels.OperatorConfirmedAbuse < minimum {
		reasons = append(reasons, "baseline_confirmed_abuse_below_minimum")
	}
	if holdout.Labels.HumanConfirmed < minimum {
		reasons = append(reasons, "holdout_confirmed_human_below_minimum")
	}
	if holdout.Labels.OperatorConfirmedAbuse < minimum {
		reasons = append(reasons, "holdout_confirmed_abuse_below_minimum")
	}
	basicReady := len(reasons) == 0
	if !report.Families.AnnotationsSupplied {
		reasons = append(reasons, "family_annotations_not_supplied")
	} else if report.Families.UnannotatedConfirmedAbuseWindows != 0 {
		reasons = append(reasons, "family_confirmed_abuse_annotations_incomplete")
	} else if report.Partitions.UnseenFamilyHoldout.Labels.OperatorConfirmedAbuse < report.Config.MinUnseenAbuse {
		reasons = append(reasons, "unseen_family_confirmed_abuse_below_minimum")
	}
	state := "insufficient_confirmed_labels"
	if baseline.Windows == 0 || holdout.Windows == 0 {
		state = "insufficient_chronological_partitions"
	} else if basicReady {
		state = "chronological_holdout_ready"
		if report.Families.AnnotationsSupplied && report.Families.UnannotatedConfirmedAbuseWindows == 0 && report.Partitions.UnseenFamilyHoldout.Labels.OperatorConfirmedAbuse >= report.Config.MinUnseenAbuse {
			state = "chronological_and_unseen_family_ready"
		}
	}
	return EvaluationReadiness{State: state, Reasons: reasons, AutomaticEnforcement: false}
}
