package localsequence

import (
	"container/heap"
	"errors"
	"time"

	"github.com/palisade-bot-defense/palisade/internal/offlineimport"
)

const (
	closeInactivity  = "inactivity"
	closeMaxDuration = "maximum_duration"
	closeEndOfInput  = "end_of_input"
)

var reportLimitations = []string{
	"operator evidence mappings are declarations and are not independently verified",
	"daily pseudonyms and window keys are continuity handles, not identities",
	"aggregate sequence association is observational and does not establish causal efficacy",
	"challenge completion does not establish humanity",
	"the report emits no subject or session identifiers and no row-level events",
}

type analyzer struct {
	config      Config
	report      Report
	active      map[string]*sequence
	expirations expirationHeap
	onWindow    func(windowFeature) error
}

type sequence struct {
	key                 string
	heapIndex           int
	expires             time.Time
	first               time.Time
	last                time.Time
	events              uint64
	minuteStart         time.Time
	minuteEvents        uint64
	peakMinute          uint64
	previousEndpoint    string
	endpointSeen        [7]bool
	sensitiveEscalation uint64
	decoyEntry          uint64
	automation          uint8
	abuseIntent         uint8
	continuity          uint8
	collectionIssue     bool
	decoy               uint8
	challenge           uint8
	humanLabel          bool
	abuseLabel          bool
}

type windowFeature struct {
	key                 string
	first               time.Time
	last                time.Time
	events              uint64
	burstShape          string
	peakMinuteBucket    string
	endpointSeen        [7]bool
	sensitiveEscalation uint64
	decoyEntry          uint64
	collectionIssue     bool
	automation          uint8
	abuseIntent         uint8
	continuity          uint8
	decoy               uint8
	challenge           uint8
	humanLabel          bool
	abuseLabel          bool
}

type expirationHeap []*sequence

func (items expirationHeap) Len() int { return len(items) }
func (items expirationHeap) Less(left, right int) bool {
	if items[left].expires.Equal(items[right].expires) {
		return items[left].key < items[right].key
	}
	return items[left].expires.Before(items[right].expires)
}
func (items expirationHeap) Swap(left, right int) {
	items[left], items[right] = items[right], items[left]
	items[left].heapIndex = left
	items[right].heapIndex = right
}
func (items *expirationHeap) Push(value any) {
	item := value.(*sequence)
	item.heapIndex = len(*items)
	*items = append(*items, item)
}
func (items *expirationHeap) Pop() any {
	old := *items
	last := old[len(old)-1]
	old[len(old)-1] = nil
	*items = old[:len(old)-1]
	last.heapIndex = -1
	return last
}

func AnalyzeDirectory(directory string, config Config) (Report, error) {
	config, err := normalizeConfig(config)
	if err != nil {
		return Report{}, err
	}
	a := newAnalyzer(config)
	_, verified, err := offlineimport.ScanLocalDirectory(directory, config.ScanLimits, a.observe)
	if err != nil {
		return Report{}, err
	}
	if err := a.finish(); err != nil {
		return Report{}, err
	}
	a.report.Source.Shards = verified.Shards
	a.report.Source.Events = verified.Events
	a.report.Source.Bytes = verified.Bytes
	a.report.Source.FirstAt = verified.FirstAt
	a.report.Source.LastAt = verified.LastAt
	if err := ValidateReport(a.report); err != nil {
		return Report{}, err
	}
	return a.report, nil
}

func normalizeConfig(config Config) (Config, error) {
	if config.MaxActiveSequences == 0 {
		config.MaxActiveSequences = DefaultMaxActiveSequences
	}
	if config.MaxActiveSequences < 1 || config.MaxActiveSequences > MaximumMaxActiveSequences {
		return Config{}, errors.New("local sequence active-window limit is outside supported bounds")
	}
	if config.ScanLimits.MaxShards == 0 {
		config.ScanLimits.MaxShards = offlineimport.DefaultLocalScanMaxShards
	}
	if config.ScanLimits.MaxEvents == 0 {
		config.ScanLimits.MaxEvents = offlineimport.DefaultLocalScanMaxEvents
	}
	if config.ScanLimits.MaxBytes == 0 {
		config.ScanLimits.MaxBytes = offlineimport.DefaultLocalScanMaxBytes
	}
	return config, nil
}

func newAnalyzer(config Config) *analyzer {
	return &analyzer{
		config: config,
		active: make(map[string]*sequence),
		report: Report{
			SchemaVersion:       SchemaVersion,
			SourceSchemaVersion: offlineimport.LocalEventSchemaVersion,
			Config: ReportConfig{
				MaxActiveSequences: config.MaxActiveSequences,
				MaxScanShards:      config.ScanLimits.MaxShards,
				MaxScanEvents:      config.ScanLimits.MaxEvents,
				MaxScanBytes:       config.ScanLimits.MaxBytes,
			},
			Definitions: FeatureDefinitions{
				InactivitySeconds:               int64(InactivityWindow / time.Second),
				MaximumWindowSeconds:            int64(MaximumWindowDuration / time.Second),
				ClusteredMinimumEvents:          clusteredMinimumEvents,
				ClusteredMaximumDurationSeconds: int64(clusteredMaximumDuration / time.Second),
				HighRateMinimumPeakMinuteEvents: highRateMinimumPeakMinute,
				SustainedMinimumEvents:          sustainedMinimumEvents,
				SustainedMinimumDurationSeconds: int64(sustainedMinimumDuration / time.Second),
			},
			Limitations: append([]string(nil), reportLimitations...),
		},
	}
}

func (a *analyzer) observe(event offlineimport.LocalEvent) error {
	observedAt, err := time.Parse(time.RFC3339Nano, event.ObservedAt)
	if err != nil {
		return errors.New("normalized event time is invalid")
	}
	if err := a.expire(observedAt); err != nil {
		return err
	}
	key := "subject:" + event.SubjectID
	if event.SessionID != "" {
		key = "session:" + event.SessionID
	}
	current := a.active[key]
	if current != nil && !observedAt.Before(current.first.Add(MaximumWindowDuration)) {
		heap.Remove(&a.expirations, current.heapIndex)
		if err := a.finalize(current, closeMaxDuration); err != nil {
			return err
		}
		delete(a.active, key)
		current = nil
	}
	if current == nil {
		if len(a.active) >= a.config.MaxActiveSequences {
			return ErrActiveSequenceBudget
		}
		current = &sequence{
			key:         key,
			heapIndex:   -1,
			first:       observedAt,
			last:        observedAt,
			minuteStart: observedAt.Truncate(time.Minute),
		}
		a.active[key] = current
		current.expires = observedAt.Add(InactivityWindow)
		heap.Push(&a.expirations, current)
	}
	a.observeEvent(current, observedAt, event)
	current.expires = observedAt.Add(InactivityWindow)
	heap.Fix(&a.expirations, current.heapIndex)
	return nil
}

func (a *analyzer) observeEvent(current *sequence, observedAt time.Time, event offlineimport.LocalEvent) {
	current.last = observedAt
	current.events++
	minute := observedAt.Truncate(time.Minute)
	if !minute.Equal(current.minuteStart) {
		current.minuteStart = minute
		current.minuteEvents = 0
	}
	current.minuteEvents++
	if current.minuteEvents > current.peakMinute {
		current.peakMinute = current.minuteEvents
	}

	endpoint := endpointIndex(event.EndpointClass)
	incrementEndpoint(&a.report.Endpoints.Events, endpoint)
	current.endpointSeen[endpoint] = true
	if current.previousEndpoint != "" {
		a.report.EndpointTransitions.Total++
		if current.previousEndpoint == event.EndpointClass {
			a.report.EndpointTransitions.SameClass++
		} else {
			a.report.EndpointTransitions.CrossClass++
		}
		if !sensitiveEndpoint(current.previousEndpoint) && sensitiveEndpoint(event.EndpointClass) {
			a.report.EndpointTransitions.SensitiveEscalation++
			current.sensitiveEscalation++
		}
		if current.previousEndpoint != "decoy" && event.EndpointClass == "decoy" {
			a.report.EndpointTransitions.DecoyEntry++
			current.decoyEntry++
		}
	}
	current.previousEndpoint = event.EndpointClass

	switch event.Evidence.CollectionStatus {
	case "complete":
		a.report.Collection.EventsComplete++
	case "partial":
		a.report.Collection.EventsPartial++
		current.collectionIssue = true
	case "missing":
		a.report.Collection.EventsMissing++
		current.collectionIssue = true
	}
	current.automation = maxLevel(current.automation, evidenceLevel(event.Evidence.AutomationEvidence))
	current.abuseIntent = maxLevel(current.abuseIntent, evidenceLevel(event.Evidence.AbuseIntentEvidence))
	current.continuity = maxLevel(current.continuity, evidenceLevel(event.Evidence.ContinuityEvidence))
	current.decoy = maxLevel(current.decoy, decoyLevel(event.Evidence.DecoyInteraction))
	current.challenge |= challengeFlag(event.Evidence.ChallengeLifecycle)
	switch event.Label.Class {
	case "human_confirmed":
		current.humanLabel = true
	case "operator_confirmed_abuse":
		current.abuseLabel = true
	}
}

func (a *analyzer) expire(now time.Time) error {
	for a.expirations.Len() > 0 && !a.expirations[0].expires.After(now) {
		current := heap.Pop(&a.expirations).(*sequence)
		delete(a.active, current.key)
		if err := a.finalize(current, closeInactivity); err != nil {
			return err
		}
	}
	return nil
}

func (a *analyzer) finish() error {
	for a.expirations.Len() > 0 {
		current := heap.Pop(&a.expirations).(*sequence)
		delete(a.active, current.key)
		if err := a.finalize(current, closeEndOfInput); err != nil {
			return err
		}
	}
	return nil
}

func (a *analyzer) finalize(current *sequence, reason string) error {
	a.report.Source.Sequences++
	a.report.Windows.Total++
	switch reason {
	case closeInactivity:
		a.report.Windows.Inactivity++
	case closeMaxDuration:
		a.report.Windows.MaxDuration++
	case closeEndOfInput:
		a.report.Windows.EndOfInput++
	}
	duration := current.last.Sub(current.first)
	burstShape := "sparse"
	switch {
	case current.events == 1:
		burstShape = "single"
		a.report.BurstShapes.Single++
	case current.peakMinute >= highRateMinimumPeakMinute:
		burstShape = "high_rate"
		a.report.BurstShapes.HighRate++
	case current.events >= clusteredMinimumEvents && duration <= clusteredMaximumDuration:
		burstShape = "clustered"
		a.report.BurstShapes.Clustered++
	case current.events >= sustainedMinimumEvents && duration >= sustainedMinimumDuration:
		burstShape = "sustained"
		a.report.BurstShapes.Sustained++
	default:
		a.report.BurstShapes.Sparse++
	}
	peakBucket := "sixty_plus"
	switch {
	case current.peakMinute == 1:
		peakBucket = "one"
		a.report.PeakMinuteEvents.One++
	case current.peakMinute <= 5:
		peakBucket = "two_to_five"
		a.report.PeakMinuteEvents.TwoToFive++
	case current.peakMinute <= 20:
		peakBucket = "six_to_twenty"
		a.report.PeakMinuteEvents.SixToTwenty++
	case current.peakMinute <= 59:
		peakBucket = "twenty_one_to_fifty_nine"
		a.report.PeakMinuteEvents.TwentyOneToFiftyNine++
	default:
		a.report.PeakMinuteEvents.SixtyPlus++
	}
	for index, seen := range current.endpointSeen {
		if seen {
			incrementEndpoint(&a.report.Endpoints.Sequences, index)
		}
	}
	if current.collectionIssue {
		a.report.Collection.WindowsWithArtifact++
	} else {
		a.report.Collection.WindowsClean++
	}
	incrementEvidence(&a.report.Evidence.Automation, current.automation)
	incrementEvidence(&a.report.Evidence.AbuseIntent, current.abuseIntent)
	incrementEvidence(&a.report.Evidence.Continuity, current.continuity)
	incrementDecoy(&a.report.Decoys, current.decoy)
	incrementChallenge(&a.report.Challenges, current.challenge)
	switch {
	case current.humanLabel && current.abuseLabel:
		a.report.Labels.Ambiguous++
	case current.humanLabel:
		a.report.Labels.HumanConfirmed++
	case current.abuseLabel:
		a.report.Labels.OperatorConfirmedAbuse++
	default:
		a.report.Labels.Unknown++
	}
	if a.onWindow != nil {
		return a.onWindow(windowFeature{
			key: current.key, first: current.first, last: current.last, events: current.events,
			burstShape: burstShape, peakMinuteBucket: peakBucket, endpointSeen: current.endpointSeen,
			sensitiveEscalation: current.sensitiveEscalation, decoyEntry: current.decoyEntry,
			collectionIssue: current.collectionIssue, automation: current.automation, abuseIntent: current.abuseIntent,
			continuity: current.continuity, decoy: current.decoy, challenge: current.challenge,
			humanLabel: current.humanLabel, abuseLabel: current.abuseLabel,
		})
	}
	return nil
}

func endpointIndex(value string) int {
	switch value {
	case "public_content":
		return 0
	case "account":
		return 1
	case "authentication":
		return 2
	case "transaction":
		return 3
	case "api":
		return 4
	case "decoy":
		return 5
	default:
		return 6
	}
}

func incrementEndpoint(counts *EndpointCounts, index int) {
	values := []*uint64{&counts.PublicContent, &counts.Account, &counts.Authentication, &counts.Transaction, &counts.API, &counts.Decoy, &counts.Other}
	*values[index]++
}

func sensitiveEndpoint(value string) bool {
	return value == "account" || value == "authentication" || value == "transaction"
}

func evidenceLevel(value string) uint8 {
	switch value {
	case "low":
		return 1
	case "medium":
		return 2
	case "high":
		return 3
	default:
		return 0
	}
}

func decoyLevel(value string) uint8 {
	switch value {
	case "rendered":
		return 1
	case "touched":
		return 2
	case "submitted":
		return 3
	default:
		return 0
	}
}

func maxLevel(left, right uint8) uint8 {
	if right > left {
		return right
	}
	return left
}

func incrementEvidence(counts *EvidenceLevelCounts, level uint8) {
	values := []*uint64{&counts.None, &counts.Low, &counts.Medium, &counts.High}
	*values[level]++
}

func incrementDecoy(counts *DecoySummary, level uint8) {
	values := []*uint64{&counts.None, &counts.Rendered, &counts.Touched, &counts.Submitted}
	*values[level]++
}

const (
	challengeIssued uint8 = 1 << iota
	challengePassed
	challengeFailed
	challengeAbandoned
	challengeFallback
)

func challengeFlag(value string) uint8 {
	switch value {
	case "issued":
		return challengeIssued
	case "passed":
		return challengePassed
	case "failed":
		return challengeFailed
	case "abandoned":
		return challengeAbandoned
	case "fallback":
		return challengeFallback
	default:
		return 0
	}
}

func incrementChallenge(counts *ChallengeSummary, flags uint8) {
	terminal := flags & (challengePassed | challengeFailed | challengeAbandoned | challengeFallback)
	if terminal != 0 && terminal&(terminal-1) != 0 {
		counts.Conflicting++
		return
	}
	switch terminal {
	case challengePassed:
		counts.Passed++
	case challengeFailed:
		counts.Failed++
	case challengeAbandoned:
		counts.Abandoned++
	case challengeFallback:
		counts.Fallback++
	default:
		if flags&challengeIssued != 0 {
			counts.IssuedUnresolved++
		} else {
			counts.None++
		}
	}
}
