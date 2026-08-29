package localsequence

import (
	"errors"
	"strings"
	"time"

	"github.com/palisade-bot-defense/palisade/internal/offlineimport"
)

func ValidateReport(report Report) error {
	if report.SchemaVersion != SchemaVersion || report.SourceSchemaVersion != "palisade.local-evidence-event.v1" ||
		report.Config.MaxActiveSequences < 1 || report.Config.MaxActiveSequences > MaximumMaxActiveSequences ||
		report.Config.MaxScanShards < 1 || report.Config.MaxScanShards > offlineimport.MaximumShardCount ||
		report.Config.MaxScanEvents < 1 || report.Config.MaxScanEvents > offlineimport.MaximumLocalScanEvents ||
		report.Config.MaxScanBytes < 1 || report.Config.MaxScanBytes > offlineimport.MaximumLocalScanBytes {
		return errors.New("local sequence report metadata is invalid")
	}
	windows := report.Windows.Total
	if report.Source.Sequences != windows || report.Source.Shards > uint64(report.Config.MaxScanShards) ||
		report.Source.Events > report.Config.MaxScanEvents || report.Source.Bytes < 0 || report.Source.Bytes > report.Config.MaxScanBytes ||
		!equalSum(windows, report.Windows.Inactivity, report.Windows.MaxDuration, report.Windows.EndOfInput) ||
		!equalSum(windows, report.BurstShapes.Single, report.BurstShapes.Sparse, report.BurstShapes.Clustered, report.BurstShapes.Sustained, report.BurstShapes.HighRate) ||
		!equalSum(windows, report.PeakMinuteEvents.One, report.PeakMinuteEvents.TwoToFive, report.PeakMinuteEvents.SixToTwenty, report.PeakMinuteEvents.TwentyOneToFiftyNine, report.PeakMinuteEvents.SixtyPlus) ||
		!equalSum(windows, report.Collection.WindowsClean, report.Collection.WindowsWithArtifact) ||
		!validEvidence(report.Evidence.Automation, windows) || !validEvidence(report.Evidence.AbuseIntent, windows) || !validEvidence(report.Evidence.Continuity, windows) ||
		!equalSum(windows, report.Decoys.None, report.Decoys.Rendered, report.Decoys.Touched, report.Decoys.Submitted) ||
		!equalSum(windows, report.Challenges.None, report.Challenges.IssuedUnresolved, report.Challenges.Passed, report.Challenges.Failed, report.Challenges.Abandoned, report.Challenges.Fallback, report.Challenges.Conflicting) ||
		!equalSum(windows, report.Labels.Unknown, report.Labels.HumanConfirmed, report.Labels.OperatorConfirmedAbuse, report.Labels.Ambiguous) {
		return errors.New("local sequence report window totals are inconsistent")
	}
	if !equalSum(report.Source.Events, report.Endpoints.Events.PublicContent, report.Endpoints.Events.Account, report.Endpoints.Events.Authentication, report.Endpoints.Events.Transaction, report.Endpoints.Events.API, report.Endpoints.Events.Decoy, report.Endpoints.Events.Other) ||
		!equalSum(report.Source.Events, report.Collection.EventsComplete, report.Collection.EventsPartial, report.Collection.EventsMissing) ||
		!equalSum(report.Source.Events, report.EndpointTransitions.Total, windows) ||
		!equalSum(report.EndpointTransitions.Total, report.EndpointTransitions.SameClass, report.EndpointTransitions.CrossClass) ||
		report.EndpointTransitions.SensitiveEscalation > report.EndpointTransitions.CrossClass || report.EndpointTransitions.DecoyEntry > report.EndpointTransitions.CrossClass ||
		!validEndpointWindows(report.Endpoints.Sequences, windows) {
		return errors.New("local sequence report event totals are inconsistent")
	}
	if report.Definitions.InactivitySeconds != int64(InactivityWindow.Seconds()) ||
		report.Definitions.MaximumWindowSeconds != int64(MaximumWindowDuration.Seconds()) ||
		report.Definitions.ClusteredMinimumEvents != clusteredMinimumEvents ||
		report.Definitions.ClusteredMaximumDurationSeconds != int64(clusteredMaximumDuration.Seconds()) ||
		report.Definitions.HighRateMinimumPeakMinuteEvents != highRateMinimumPeakMinute ||
		report.Definitions.SustainedMinimumEvents != sustainedMinimumEvents ||
		report.Definitions.SustainedMinimumDurationSeconds != int64(sustainedMinimumDuration.Seconds()) ||
		!equalStrings(report.Limitations, reportLimitations) {
		return errors.New("local sequence report definitions are invalid")
	}
	if report.Source.Events == 0 {
		if windows != 0 || report.Source.FirstAt != "" || report.Source.LastAt != "" {
			return errors.New("empty local sequence report has observations")
		}
	} else if windows == 0 || !validUTC(report.Source.FirstAt) || !validUTC(report.Source.LastAt) || report.Source.LastAt < report.Source.FirstAt {
		return errors.New("local sequence report source range is invalid")
	}
	return nil
}

func validEndpointWindows(counts EndpointCounts, windows uint64) bool {
	return counts.PublicContent <= windows && counts.Account <= windows && counts.Authentication <= windows && counts.Transaction <= windows &&
		counts.API <= windows && counts.Decoy <= windows && counts.Other <= windows
}

func validUTC(value string) bool {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	return err == nil && parsed.Location() == time.UTC && strings.HasSuffix(value, "Z")
}

func validEvidence(counts EvidenceLevelCounts, total uint64) bool {
	return equalSum(total, counts.None, counts.Low, counts.Medium, counts.High)
}

func equalSum(total uint64, values ...uint64) bool {
	var sum uint64
	for _, value := range values {
		if sum > ^uint64(0)-value {
			return false
		}
		sum += value
	}
	return sum == total
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
