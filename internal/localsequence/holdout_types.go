package localsequence

import (
	"errors"

	"github.com/palisade-human-trust/palisade/internal/shadowanalysis"
)

const (
	HoldoutSchemaVersion          = "palisade.local-holdout-report.v1"
	FamilyAnnotationSchemaVersion = "palisade.local-family-annotation.v1"
	DefaultMinConfirmedPerLabel   = uint64(100)
	DefaultMinUnseenAbuse         = uint64(100)
	MaximumMinEvaluationLabels    = uint64(1_000_000)
	DefaultMaxFamilyRecords       = uint64(1_000_000)
	MaximumMaxFamilyRecords       = uint64(5_000_000)
	DefaultMaxFamilyBytes         = int64(256 << 20)
	MaximumMaxFamilyBytes         = int64(1 << 30)
	DefaultMaxFamilyLineBytes     = 4 << 10
	MaximumMaxFamilyLineBytes     = 64 << 10
	maximumHoldoutReportBytes     = 2 << 20
)

var ErrFamilyAnnotationBudget = errors.New("local family annotation budget exceeded")

type HoldoutConfig struct {
	Sequence             Config
	HoldoutStart         string
	MinConfirmedPerLabel uint64
	MinUnseenAbuse       uint64
	FamilyAnnotations    string
	MaxFamilyRecords     uint64
	MaxFamilyBytes       int64
	MaxFamilyLineBytes   int
}

type HoldoutReport struct {
	SchemaVersion       string              `json:"schema_version"`
	SourceSchemaVersion string              `json:"source_schema_version"`
	Config              HoldoutReportConfig `json:"config"`
	FeatureDefinitions  FeatureDefinitions  `json:"feature_definitions"`
	RuleDefinitions     []RuleDefinition    `json:"rule_definitions"`
	Source              SourceSummary       `json:"source"`
	Split               ChronologicalSplit  `json:"split"`
	Families            FamilySummary       `json:"families"`
	Partitions          HoldoutPartitions   `json:"partitions"`
	Readiness           EvaluationReadiness `json:"readiness"`
	Limitations         []string            `json:"limitations"`
}

type HoldoutReportConfig struct {
	MaxActiveSequences   int    `json:"max_active_sequences"`
	MaxScanShards        int    `json:"max_scan_shards"`
	MaxScanEvents        uint64 `json:"max_scan_events"`
	MaxScanBytes         int64  `json:"max_scan_bytes"`
	MinConfirmedPerLabel uint64 `json:"min_confirmed_per_label"`
	MinUnseenAbuse       uint64 `json:"min_unseen_abuse"`
	MaxFamilyRecords     uint64 `json:"max_family_records"`
	MaxFamilyBytes       int64  `json:"max_family_bytes"`
	MaxFamilyLineBytes   int    `json:"max_family_line_bytes"`
}

type RuleDefinition struct {
	ID          string `json:"id"`
	Description string `json:"description"`
}

type ChronologicalSplit struct {
	Method                  string       `json:"method"`
	HoldoutStart            string       `json:"holdout_start"`
	BoundaryWindowsExcluded uint64       `json:"boundary_windows_excluded"`
	BoundaryEventsExcluded  uint64       `json:"boundary_events_excluded"`
	BoundaryLabels          LabelSummary `json:"boundary_labels"`
}

type FamilySummary struct {
	AnnotationsSupplied              bool   `json:"annotations_supplied"`
	AnnotationRecords                uint64 `json:"annotation_records"`
	AnnotationBytes                  int64  `json:"annotation_bytes"`
	AnnotationSHA256                 string `json:"annotation_sha256,omitempty"`
	AnnotatedWindows                 uint64 `json:"annotated_windows"`
	UnannotatedWindows               uint64 `json:"unannotated_windows"`
	BaselineDistinct                 uint64 `json:"baseline_distinct"`
	HoldoutDistinct                  uint64 `json:"holdout_distinct"`
	UnseenDistinct                   uint64 `json:"unseen_distinct"`
	UnseenHoldoutWindows             uint64 `json:"unseen_holdout_windows"`
	AnnotatedConfirmedAbuseWindows   uint64 `json:"annotated_confirmed_abuse_windows"`
	UnannotatedConfirmedAbuseWindows uint64 `json:"unannotated_confirmed_abuse_windows"`
}

type HoldoutPartitions struct {
	Baseline            PartitionEvaluation `json:"baseline"`
	Holdout             PartitionEvaluation `json:"holdout"`
	UnseenFamilyHoldout PartitionEvaluation `json:"unseen_family_holdout"`
}

type PartitionEvaluation struct {
	Windows    uint64                 `json:"windows"`
	Events     uint64                 `json:"events"`
	Labels     LabelSummary           `json:"labels"`
	Collection CollectionWindowCounts `json:"collection"`
	Rules      []RuleEvaluation       `json:"rules"`
	Endpoints  []EndpointEvaluation   `json:"endpoints"`
}

type CollectionWindowCounts struct {
	Clean        uint64 `json:"clean"`
	WithArtifact uint64 `json:"with_artifact"`
}

type EndpointEvaluation struct {
	EndpointClass string           `json:"endpoint_class"`
	Windows       uint64           `json:"windows"`
	Labels        LabelSummary     `json:"labels"`
	Rules         []RuleEvaluation `json:"rules"`
}

type RuleEvaluation struct {
	RuleID                    string                            `json:"rule_id"`
	Flagged                   LabelSummary                      `json:"flagged"`
	Unflagged                 LabelSummary                      `json:"unflagged"`
	ConfirmedHumanFlagRate    shadowanalysis.ProportionEstimate `json:"confirmed_human_flag_rate"`
	ConfirmedAbuseCaptureRate shadowanalysis.ProportionEstimate `json:"confirmed_abuse_capture_rate"`
	UnknownFlagRate           shadowanalysis.ProportionEstimate `json:"unknown_flag_rate"`
}

type EvaluationReadiness struct {
	State                string   `json:"state"`
	Reasons              []string `json:"reasons"`
	AutomaticEnforcement bool     `json:"automatic_enforcement"`
}

type FamilyAnnotation struct {
	SchemaVersion string `json:"schema_version"`
	SequenceKind  string `json:"sequence_kind"`
	SequenceID    string `json:"sequence_id"`
	FamilyRef     string `json:"family_ref"`
}
