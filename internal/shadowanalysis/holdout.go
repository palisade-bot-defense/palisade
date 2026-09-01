package shadowanalysis

import (
	"crypto/sha256"
	"errors"
	"time"

	"github.com/palisade-human-trust/palisade/internal/core"
	"github.com/palisade-human-trust/palisade/internal/shadowlog"
)

const (
	ShadowHoldoutSchemaVersion = "palisade.shadow-holdout.v1"
	DefaultHoldoutMinimum      = uint64(100)
)

var ErrInvalidHoldout = errors.New("invalid shadow holdout configuration or report")

type ShadowHoldoutConfig struct {
	ScanLimits        shadowlog.ScanLimits
	HoldoutStart      string
	MinConfirmedHuman uint64
	MinConfirmedAbuse uint64
	MaxDecisionLinks  int
}

type ShadowHoldoutReport struct {
	SchemaVersion string                 `json:"schema_version"`
	Source        shadowlog.Verification `json:"source"`
	Split         ShadowHoldoutSplit     `json:"split"`
	Readiness     ShadowHoldoutReadiness `json:"readiness"`
	Linkage       LinkageSummary         `json:"linkage"`
	Baseline      ShadowHoldoutPartition `json:"baseline"`
	Holdout       ShadowHoldoutPartition `json:"holdout"`
	Limitations   []string               `json:"limitations"`
}

type ShadowHoldoutSplit struct {
	HoldoutStart string `json:"holdout_start"`
	Rule         string `json:"rule"`
}

type ShadowHoldoutReadiness struct {
	State                 string   `json:"state"`
	AutomaticEnforcement  bool     `json:"automatic_enforcement"`
	MinimumConfirmedHuman uint64   `json:"minimum_confirmed_human"`
	MinimumConfirmedAbuse uint64   `json:"minimum_confirmed_abuse"`
	ReasonCodes           []string `json:"reason_codes"`
}

type ShadowHoldoutPartition struct {
	Decisions          uint64            `json:"decisions"`
	ConfirmedHuman     uint64            `json:"confirmed_human"`
	ConfirmedAbuse     uint64            `json:"confirmed_abuse"`
	UnlabeledDecisions uint64            `json:"unlabeled_decisions"`
	Evaluation         LinkedEvaluation  `json:"evaluation"`
	EvaluationSlices   []EvaluationSlice `json:"evaluation_slices"`
}

type shadowHoldoutAnalyzer struct {
	config  ShadowHoldoutConfig
	cutoff  time.Time
	links   map[[sha256.Size]byte]*linkedDecision
	linkage LinkageSummary
}

type shadowPartitionAccumulator struct {
	overall linkedAccumulator
	slices  map[evaluationSliceKey]*linkedAccumulator
}

func EvaluateShadowHoldoutDirectory(directory, keyFile string, config ShadowHoldoutConfig) (ShadowHoldoutReport, error) {
	normalized, cutoff, err := normalizeShadowHoldoutConfig(config)
	if err != nil {
		return ShadowHoldoutReport{}, err
	}
	analyzer := &shadowHoldoutAnalyzer{
		config: normalized, cutoff: cutoff,
		links: make(map[[sha256.Size]byte]*linkedDecision),
	}
	source, err := shadowlog.ScanDirectory(directory, keyFile, normalized.ScanLimits, analyzer.observe)
	if err != nil {
		return ShadowHoldoutReport{}, err
	}
	report := analyzer.finish(source)
	if err := ValidateShadowHoldoutReport(report); err != nil {
		return ShadowHoldoutReport{}, err
	}
	return report, nil
}

func normalizeShadowHoldoutConfig(config ShadowHoldoutConfig) (ShadowHoldoutConfig, time.Time, error) {
	cutoff, err := time.Parse(time.RFC3339, config.HoldoutStart)
	if err != nil || cutoff.Location() != time.UTC || cutoff.Format(time.RFC3339) != config.HoldoutStart {
		return ShadowHoldoutConfig{}, time.Time{}, ErrInvalidHoldout
	}
	if config.MinConfirmedHuman == 0 {
		config.MinConfirmedHuman = DefaultHoldoutMinimum
	}
	if config.MinConfirmedAbuse == 0 {
		config.MinConfirmedAbuse = DefaultHoldoutMinimum
	}
	if config.MaxDecisionLinks == 0 {
		config.MaxDecisionLinks = DefaultMaxDecisionLinks
	}
	if config.MinConfirmedHuman > 1_000_000_000 || config.MinConfirmedAbuse > 1_000_000_000 ||
		config.MaxDecisionLinks < 1 || config.MaxDecisionLinks > MaximumDecisionLinks {
		return ShadowHoldoutConfig{}, time.Time{}, ErrInvalidHoldout
	}
	return config, cutoff, nil
}

func (a *shadowHoldoutAnalyzer) observe(record shadowlog.Record) error {
	if record.Kind == "decision" {
		return a.observeDecision(record.Decision, record.RecordedAt)
	}
	return a.observeOutcome(record.Outcome)
}

func (a *shadowHoldoutAnalyzer) observeDecision(entry *shadowlog.DecisionEntry, recordedAt string) error {
	link, err := a.decisionLink(entry.DecisionID)
	if err != nil {
		return err
	}
	if link.decisionSeen {
		if !link.duplicate {
			link.duplicate = true
			a.linkage.DuplicateDecisionIDs++
		}
		a.linkage.DuplicateDecisionRecords++
		return nil
	}
	cohort, valid := core.NormalizeEvaluationCohort(entry.EvaluationCohort)
	if !valid {
		return ErrInvalidHoldout
	}
	observedAt, err := time.Parse(time.RFC3339, recordedAt)
	if err != nil {
		return ErrInvalidHoldout
	}
	link.decisionSeen = true
	link.endpoint = entry.EndpointClass
	link.cohort = cohort
	link.recordedAt = observedAt
	link.predictedRisky = isRisky(entry.ComputedAction)
	link.challenged = entry.Action == core.ActionChallenge
	return nil
}

func (a *shadowHoldoutAnalyzer) observeOutcome(entry *shadowlog.OutcomeEntry) error {
	if entry.DecisionID == "" {
		a.linkage.LegacyOutcomeEventsWithoutID++
		return nil
	}
	a.linkage.OutcomeEventsWithDecisionID++
	link, err := a.decisionLink(entry.DecisionID)
	if err != nil {
		return err
	}
	link.outcomeEvents++
	if link.outcomeEndpoint == "" {
		link.outcomeEndpoint = entry.EndpointClass
	} else if link.outcomeEndpoint != entry.EndpointClass {
		link.endpointConflict = true
	}
	mask := outcomeBit(entry.Outcome)
	if mask == 0 {
		return ErrInvalidHoldout
	}
	if link.outcomeMask&mask != 0 {
		a.linkage.DuplicateOutcomeEvents++
	}
	link.outcomeMask |= mask
	return nil
}

func (a *shadowHoldoutAnalyzer) decisionLink(decisionID string) (*linkedDecision, error) {
	key := sha256.Sum256([]byte(decisionID))
	if link := a.links[key]; link != nil {
		return link, nil
	}
	if len(a.links) >= a.config.MaxDecisionLinks {
		return nil, ErrLinkBudget
	}
	link := &linkedDecision{}
	a.links[key] = link
	return link, nil
}

func (a *shadowHoldoutAnalyzer) finish(source shadowlog.Verification) ShadowHoldoutReport {
	lastAt, _ := time.Parse(time.RFC3339, source.LastAt)
	matureBefore := lastAt.Add(-ChallengeOutcomeMaturity)
	baseline := newShadowPartitionAccumulator()
	holdout := newShadowPartitionAccumulator()
	for _, link := range a.links {
		if !link.decisionSeen {
			a.linkage.UnknownDecisionOutcomeEvents += link.outcomeEvents
			continue
		}
		a.linkage.UniqueDecisionIDs++
		matched := link.outcomeEvents > 0 && !link.endpointConflict && link.outcomeEndpoint == link.endpoint
		if link.outcomeEvents > 0 {
			if matched {
				a.linkage.MatchedOutcomeEvents += link.outcomeEvents
			} else {
				a.linkage.EndpointMismatchOutcomeEvents += link.outcomeEvents
			}
		}
		if link.duplicate {
			continue
		}
		partition := baseline
		if !link.recordedAt.Before(a.cutoff) {
			partition = holdout
		}
		partition.observe(link, matched, matureBefore)
	}
	baselineReport := baseline.finish()
	holdoutReport := holdout.finish()
	a.linkage.ConfirmedDecisionLabels = baselineReport.Evaluation.ConfirmedLabels + holdoutReport.Evaluation.ConfirmedLabels
	a.linkage.AmbiguousGroundTruthDecisions = baselineReport.Evaluation.AmbiguousGroundTruth + holdoutReport.Evaluation.AmbiguousGroundTruth
	a.linkage.AmbiguousChallengeDecisions = baselineReport.Evaluation.AmbiguousChallengeOutcomes + holdoutReport.Evaluation.AmbiguousChallengeOutcomes
	a.linkage.ConfirmedLabelCoverage = Proportion(a.linkage.ConfirmedDecisionLabels, source.Decisions)
	readiness := shadowHoldoutReadiness(a.config, baselineReport, holdoutReport)
	return ShadowHoldoutReport{
		SchemaVersion: ShadowHoldoutSchemaVersion,
		Source:        source,
		Split: ShadowHoldoutSplit{
			HoldoutStart: a.config.HoldoutStart,
			Rule:         "decision_recorded_before_cutoff_is_baseline_otherwise_holdout",
		},
		Readiness: readiness,
		Linkage:   a.linkage,
		Baseline:  baselineReport,
		Holdout:   holdoutReport,
		Limitations: []string{
			"chronology is assigned by authenticated decision record time; delayed outcome time never changes the partition",
			"confirmed labels are operator or deployment assertions and do not establish causality",
			"this report does not evaluate unseen attack families and never authorizes enforcement",
		},
	}
}

func newShadowPartitionAccumulator() *shadowPartitionAccumulator {
	return &shadowPartitionAccumulator{slices: make(map[evaluationSliceKey]*linkedAccumulator)}
}

func (a *shadowPartitionAccumulator) observe(link *linkedDecision, matched bool, matureBefore time.Time) {
	a.overall.observe(link, matched, matureBefore)
	key := evaluationSliceKey{endpoint: link.endpoint, cohort: link.cohort}
	slice := a.slices[key]
	if slice == nil {
		slice = &linkedAccumulator{}
		a.slices[key] = slice
	}
	slice.observe(link, matched, matureBefore)
}

func (a *shadowPartitionAccumulator) finish() ShadowHoldoutPartition {
	evaluation := a.overall.finish()
	human := evaluation.Confusion.FalsePositive + evaluation.Confusion.TrueNegative
	abuse := evaluation.Confusion.TruePositive + evaluation.Confusion.FalseNegative
	unlabeled := evaluation.Decisions - evaluation.ConfirmedLabels - evaluation.AmbiguousGroundTruth
	return ShadowHoldoutPartition{
		Decisions: evaluation.Decisions, ConfirmedHuman: human, ConfirmedAbuse: abuse,
		UnlabeledDecisions: unlabeled, Evaluation: evaluation, EvaluationSlices: sortedEvaluationSlices(a.slices),
	}
}

func shadowHoldoutReadiness(config ShadowHoldoutConfig, baseline, holdout ShadowHoldoutPartition) ShadowHoldoutReadiness {
	reasons := make([]string, 0, 6)
	if baseline.Decisions == 0 {
		reasons = append(reasons, "baseline_decisions_missing")
	}
	if holdout.Decisions == 0 {
		reasons = append(reasons, "holdout_decisions_missing")
	}
	if baseline.ConfirmedHuman < config.MinConfirmedHuman {
		reasons = append(reasons, "baseline_confirmed_human_below_minimum")
	}
	if baseline.ConfirmedAbuse < config.MinConfirmedAbuse {
		reasons = append(reasons, "baseline_confirmed_abuse_below_minimum")
	}
	if holdout.ConfirmedHuman < config.MinConfirmedHuman {
		reasons = append(reasons, "holdout_confirmed_human_below_minimum")
	}
	if holdout.ConfirmedAbuse < config.MinConfirmedAbuse {
		reasons = append(reasons, "holdout_confirmed_abuse_below_minimum")
	}
	state := "chronological_ready"
	if len(reasons) != 0 {
		state = "insufficient_confirmed_labels"
	}
	return ShadowHoldoutReadiness{
		State: state, AutomaticEnforcement: false, MinimumConfirmedHuman: config.MinConfirmedHuman,
		MinimumConfirmedAbuse: config.MinConfirmedAbuse, ReasonCodes: reasons,
	}
}
