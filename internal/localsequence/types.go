package localsequence

import (
	"errors"
	"time"

	"github.com/palisade-bot-defense/palisade/internal/offlineimport"
)

const (
	SchemaVersion             = "palisade.local-sequence-report.v1"
	InactivityWindow          = 5 * time.Minute
	MaximumWindowDuration     = 15 * time.Minute
	DefaultMaxActiveSequences = 100_000
	MaximumMaxActiveSequences = 1_000_000
	clusteredMinimumEvents    = 20
	clusteredMaximumDuration  = 60 * time.Second
	highRateMinimumPeakMinute = 60
	sustainedMinimumEvents    = 20
	sustainedMinimumDuration  = 5 * time.Minute
	maximumReportBytes        = 1 << 20
)

var ErrActiveSequenceBudget = errors.New("local sequence active-window budget exceeded")

type Config struct {
	ScanLimits         offlineimport.LocalScanLimits
	MaxActiveSequences int
}

type Report struct {
	SchemaVersion       string             `json:"schema_version"`
	SourceSchemaVersion string             `json:"source_schema_version"`
	Config              ReportConfig       `json:"config"`
	Definitions         FeatureDefinitions `json:"feature_definitions"`
	Source              SourceSummary      `json:"source"`
	Windows             WindowSummary      `json:"windows"`
	BurstShapes         BurstShapeCounts   `json:"burst_shapes"`
	PeakMinuteEvents    PeakMinuteCounts   `json:"peak_minute_events"`
	EndpointTransitions TransitionSummary  `json:"endpoint_transitions"`
	Endpoints           EndpointSummary    `json:"endpoints"`
	Collection          CollectionSummary  `json:"collection"`
	Evidence            EvidenceSummary    `json:"evidence"`
	Decoys              DecoySummary       `json:"decoys"`
	Challenges          ChallengeSummary   `json:"challenges"`
	Labels              LabelSummary       `json:"labels"`
	Limitations         []string           `json:"limitations"`
}

type ReportConfig struct {
	MaxActiveSequences int    `json:"max_active_sequences"`
	MaxScanShards      int    `json:"max_scan_shards"`
	MaxScanEvents      uint64 `json:"max_scan_events"`
	MaxScanBytes       int64  `json:"max_scan_bytes"`
}

type FeatureDefinitions struct {
	InactivitySeconds               int64  `json:"inactivity_seconds"`
	MaximumWindowSeconds            int64  `json:"maximum_window_seconds"`
	ClusteredMinimumEvents          uint64 `json:"clustered_minimum_events"`
	ClusteredMaximumDurationSeconds int64  `json:"clustered_maximum_duration_seconds"`
	HighRateMinimumPeakMinuteEvents uint64 `json:"high_rate_minimum_peak_minute_events"`
	SustainedMinimumEvents          uint64 `json:"sustained_minimum_events"`
	SustainedMinimumDurationSeconds int64  `json:"sustained_minimum_duration_seconds"`
}

type SourceSummary struct {
	Shards    uint64 `json:"shards"`
	Events    uint64 `json:"events"`
	Bytes     int64  `json:"bytes"`
	Sequences uint64 `json:"sequences"`
	FirstAt   string `json:"first_at,omitempty"`
	LastAt    string `json:"last_at,omitempty"`
}

type WindowSummary struct {
	Total       uint64 `json:"total"`
	Inactivity  uint64 `json:"closed_by_inactivity"`
	MaxDuration uint64 `json:"closed_by_maximum_duration"`
	EndOfInput  uint64 `json:"closed_at_end_of_input"`
}

type BurstShapeCounts struct {
	Single    uint64 `json:"single"`
	Sparse    uint64 `json:"sparse"`
	Clustered uint64 `json:"clustered"`
	Sustained uint64 `json:"sustained"`
	HighRate  uint64 `json:"high_rate"`
}

type PeakMinuteCounts struct {
	One                  uint64 `json:"one"`
	TwoToFive            uint64 `json:"two_to_five"`
	SixToTwenty          uint64 `json:"six_to_twenty"`
	TwentyOneToFiftyNine uint64 `json:"twenty_one_to_fifty_nine"`
	SixtyPlus            uint64 `json:"sixty_plus"`
}

type TransitionSummary struct {
	Total               uint64 `json:"total"`
	SameClass           uint64 `json:"same_class"`
	CrossClass          uint64 `json:"cross_class"`
	SensitiveEscalation uint64 `json:"sensitive_escalation"`
	DecoyEntry          uint64 `json:"decoy_entry"`
}

type EndpointSummary struct {
	Events    EndpointCounts `json:"events"`
	Sequences EndpointCounts `json:"sequences"`
}

type EndpointCounts struct {
	PublicContent  uint64 `json:"public_content"`
	Account        uint64 `json:"account"`
	Authentication uint64 `json:"authentication"`
	Transaction    uint64 `json:"transaction"`
	API            uint64 `json:"api"`
	Decoy          uint64 `json:"decoy"`
	Other          uint64 `json:"other"`
}

type CollectionSummary struct {
	EventsComplete      uint64 `json:"events_complete"`
	EventsPartial       uint64 `json:"events_partial"`
	EventsMissing       uint64 `json:"events_missing"`
	WindowsClean        uint64 `json:"windows_clean"`
	WindowsWithArtifact uint64 `json:"windows_with_artifact"`
}

type EvidenceSummary struct {
	Automation  EvidenceLevelCounts `json:"automation"`
	AbuseIntent EvidenceLevelCounts `json:"abuse_intent"`
	Continuity  EvidenceLevelCounts `json:"continuity"`
}

type EvidenceLevelCounts struct {
	None   uint64 `json:"none"`
	Low    uint64 `json:"low"`
	Medium uint64 `json:"medium"`
	High   uint64 `json:"high"`
}

type DecoySummary struct {
	None      uint64 `json:"none"`
	Rendered  uint64 `json:"rendered"`
	Touched   uint64 `json:"touched"`
	Submitted uint64 `json:"submitted"`
}

type ChallengeSummary struct {
	None             uint64 `json:"none"`
	IssuedUnresolved uint64 `json:"issued_unresolved"`
	Passed           uint64 `json:"passed"`
	Failed           uint64 `json:"failed"`
	Abandoned        uint64 `json:"abandoned"`
	Fallback         uint64 `json:"fallback"`
	Conflicting      uint64 `json:"conflicting"`
}

type LabelSummary struct {
	Unknown                uint64 `json:"unknown"`
	HumanConfirmed         uint64 `json:"human_confirmed"`
	OperatorConfirmedAbuse uint64 `json:"operator_confirmed_abuse"`
	Ambiguous              uint64 `json:"ambiguous"`
}
