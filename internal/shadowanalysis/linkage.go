package shadowanalysis

import (
	"crypto/sha256"
	"math/bits"
	"sort"
	"strconv"
	"time"

	"github.com/palisade-human-trust/palisade/internal/core"
	"github.com/palisade-human-trust/palisade/internal/shadowlog"
)

const (
	outcomeSuccessful uint16 = 1 << iota
	outcomeChallengePassed
	outcomeChallengeFailed
	outcomeChallengeAbandoned
	outcomeHumanConfirmed
	outcomeAbuseConfirmed
	outcomeAppealRequested
	outcomeFallbackUsed
	outcomeUnknown
)

const challengeTerminalMask = outcomeChallengePassed | outcomeChallengeFailed | outcomeChallengeAbandoned | outcomeFallbackUsed

type linkedDecision struct {
	decisionSeen      bool
	assurance         string
	assuranceWithheld bool
	duplicate         bool
	endpoint          string
	cohort            core.EvaluationCohort
	recordedAt        time.Time
	predictedRisky    bool
	challenged        bool
	mode              core.RuntimeMode
	rolloutID         string
	outcomeEndpoint   string
	endpointConflict  bool
	outcomeEvents     uint64
	outcomeMask       uint16
}

type evaluationSliceKey struct {
	endpoint string
	cohort   core.EvaluationCohort
}

// assuranceSliceKey groups linked decisions by the human assurance level they
// backed. Records written before the level existed, and records from the risk
// surface, are counted under AssuranceLevelUnknown rather than under level 0:
// an unevaluated decision is not a measured absence of human presence, and
// merging the two would corrupt the interval that decides whether the ceiling
// may be raised.
type assuranceSliceKey struct {
	endpoint string
	level    string
	withheld bool
}

type linkedAccumulator struct {
	evaluation LinkedEvaluation
}

func (a *analyzer) observeLinkedDecision(entry *shadowlog.DecisionEntry, recordedAt string) error {
	link, err := a.decisionLink(entry.DecisionID)
	if err != nil {
		return err
	}
	if link.decisionSeen {
		if !link.duplicate {
			link.duplicate = true
			a.report.Linkage.DuplicateDecisionIDs++
		}
		a.report.Linkage.DuplicateDecisionRecords++
		return nil
	}
	cohort, valid := core.NormalizeEvaluationCohort(entry.EvaluationCohort)
	if !valid {
		return ErrInvalidReport
	}
	parsedAt, err := time.Parse(time.RFC3339, recordedAt)
	if err != nil {
		return ErrInvalidReport
	}
	link.decisionSeen = true
	link.assurance = AssuranceLevelUnknown
	if entry.AssuranceLevel != nil {
		link.assurance = strconv.Itoa(*entry.AssuranceLevel)
	}
	link.assuranceWithheld = entry.AssuranceWithheld
	link.endpoint = entry.EndpointClass
	link.cohort = cohort
	link.recordedAt = parsedAt
	link.predictedRisky = isRisky(entry.ComputedAction)
	link.challenged = entry.Action == core.ActionChallenge
	link.mode = entry.Mode
	link.rolloutID = entry.RolloutID
	return nil
}

func (a *analyzer) observeLinkedOutcome(entry *shadowlog.OutcomeEntry) error {
	if entry.DecisionID == "" {
		a.report.Linkage.LegacyOutcomeEventsWithoutID++
		return nil
	}
	a.report.Linkage.OutcomeEventsWithDecisionID++
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
	if link.outcomeMask&mask != 0 {
		a.report.Linkage.DuplicateOutcomeEvents++
	}
	link.outcomeMask |= mask
	return nil
}

func (a *analyzer) decisionLink(decisionID string) (*linkedDecision, error) {
	key := sha256.Sum256([]byte(decisionID))
	if existing := a.links[key]; existing != nil {
		return existing, nil
	}
	if len(a.links) >= a.config.MaxDecisionLinks {
		return nil, ErrLinkBudget
	}
	created := &linkedDecision{}
	a.links[key] = created
	return created, nil
}

func (a *analyzer) finishLinkage(source shadowlog.Verification) {
	lastAt, _ := time.Parse(time.RFC3339, source.LastAt)
	matureBefore := lastAt.Add(-ChallengeOutcomeMaturity)
	slices := make(map[evaluationSliceKey]*linkedAccumulator)
	assuranceSlices := make(map[assuranceSliceKey]*linkedAccumulator)
	endpoints := make(map[string]*linkedAccumulator)
	canaryBudgets := make(map[canaryEndpointKey]*linkedAccumulator)
	for _, link := range a.links {
		if !link.decisionSeen {
			a.report.Linkage.UnknownDecisionOutcomeEvents += link.outcomeEvents
			continue
		}
		a.report.Linkage.UniqueDecisionIDs++
		matched := link.outcomeEvents > 0 && !link.endpointConflict && link.outcomeEndpoint == link.endpoint
		if link.outcomeEvents > 0 {
			if matched {
				a.report.Linkage.MatchedOutcomeEvents += link.outcomeEvents
			} else {
				a.report.Linkage.EndpointMismatchOutcomeEvents += link.outcomeEvents
			}
		}
		if link.duplicate {
			continue
		}
		assuranceKey := assuranceSliceKey{
			endpoint: link.endpoint, level: link.assurance, withheld: link.assuranceWithheld,
		}
		assured := assuranceSlices[assuranceKey]
		if assured == nil {
			assured = &linkedAccumulator{}
			assuranceSlices[assuranceKey] = assured
		}
		sliceKey := evaluationSliceKey{endpoint: link.endpoint, cohort: link.cohort}
		slice := slices[sliceKey]
		if slice == nil {
			slice = &linkedAccumulator{}
			slices[sliceKey] = slice
		}
		endpoint := endpoints[link.endpoint]
		if endpoint == nil {
			endpoint = &linkedAccumulator{}
			endpoints[link.endpoint] = endpoint
		}
		slice.observe(link, matched, matureBefore)
		endpoint.observe(link, matched, matureBefore)
		if link.mode == core.RuntimeModeCanary && link.rolloutID != "" {
			key := canaryEndpointKey{rolloutID: link.rolloutID, endpoint: link.endpoint}
			budget := canaryBudgets[key]
			if budget == nil {
				budget = &linkedAccumulator{}
				canaryBudgets[key] = budget
			}
			budget.observe(link, matched, matureBefore)
		}
	}
	for name, accumulator := range endpoints {
		if endpoint := a.endpoints[name]; endpoint != nil {
			evaluation := accumulator.finish()
			endpoint.LinkedEvaluation = evaluation
			a.report.Linkage.ConfirmedDecisionLabels += evaluation.ConfirmedLabels
			a.report.Linkage.AmbiguousGroundTruthDecisions += evaluation.AmbiguousGroundTruth
			a.report.Linkage.AmbiguousChallengeDecisions += evaluation.AmbiguousChallengeOutcomes
		}
	}
	a.report.Linkage.ConfirmedLabelCoverage = Proportion(a.report.Linkage.ConfirmedDecisionLabels, source.Decisions)
	a.report.EvaluationSlices = sortedEvaluationSlices(slices)
	a.report.AssuranceSlices = sortedAssuranceSlices(assuranceSlices)
	a.report.CanaryChallengeBudgets = a.sortedCanaryChallengeBudgets(canaryBudgets)
}

func (a *linkedAccumulator) observe(link *linkedDecision, outcomesMatched bool, matureBefore time.Time) {
	a.evaluation.Decisions++
	if outcomesMatched {
		groundTruth := link.outcomeMask & (outcomeHumanConfirmed | outcomeAbuseConfirmed)
		switch groundTruth {
		case outcomeHumanConfirmed:
			a.evaluation.ConfirmedLabels++
			if link.predictedRisky {
				a.evaluation.Confusion.FalsePositive++
			} else {
				a.evaluation.Confusion.TrueNegative++
			}
		case outcomeAbuseConfirmed:
			a.evaluation.ConfirmedLabels++
			if link.predictedRisky {
				a.evaluation.Confusion.TruePositive++
			} else {
				a.evaluation.Confusion.FalseNegative++
			}
		case outcomeHumanConfirmed | outcomeAbuseConfirmed:
			a.evaluation.AmbiguousGroundTruth++
		}
	}
	if !link.challenged || link.recordedAt.After(matureBefore) {
		return
	}
	a.evaluation.MatureChallenges++
	terminal := uint(link.outcomeMask & challengeTerminalMask)
	if !outcomesMatched || terminal == 0 {
		a.evaluation.UnresolvedMatureChallenges++
		return
	}
	if bits.OnesCount(terminal) != 1 {
		a.evaluation.AmbiguousChallengeOutcomes++
		return
	}
	switch uint16(terminal) {
	case outcomeChallengePassed:
		a.evaluation.ChallengePassed++
	case outcomeChallengeFailed:
		a.evaluation.ChallengeFailed++
	case outcomeChallengeAbandoned:
		a.evaluation.ChallengeAbandoned++
	case outcomeFallbackUsed:
		a.evaluation.FallbackUsed++
	}
}

func (a *linkedAccumulator) finish() LinkedEvaluation {
	return finalizeLinkedEvaluation(a.evaluation)
}

func finalizeLinkedEvaluation(result LinkedEvaluation) LinkedEvaluation {
	confusion := result.Confusion
	result.FalsePositiveRate = Proportion(confusion.FalsePositive, confusion.FalsePositive+confusion.TrueNegative)
	result.AbuseRecall = Proportion(confusion.TruePositive, confusion.TruePositive+confusion.FalseNegative)
	result.AbusePrecision = Proportion(confusion.TruePositive, confusion.TruePositive+confusion.FalsePositive)
	result.ChallengePassRate = Proportion(result.ChallengePassed, result.MatureChallenges)
	result.ChallengeFailureRate = Proportion(result.ChallengeFailed, result.MatureChallenges)
	result.ChallengeAbandonmentRate = Proportion(result.ChallengeAbandoned, result.MatureChallenges)
	result.FallbackRate = Proportion(result.FallbackUsed, result.MatureChallenges)
	return result
}

func sortedAssuranceSlices(values map[assuranceSliceKey]*linkedAccumulator) []AssuranceSlice {
	keys := make([]assuranceSliceKey, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(left, right int) bool {
		if keys[left].endpoint != keys[right].endpoint {
			return keys[left].endpoint < keys[right].endpoint
		}
		if keys[left].level != keys[right].level {
			return keys[left].level < keys[right].level
		}
		return !keys[left].withheld && keys[right].withheld
	})
	result := make([]AssuranceSlice, 0, len(keys))
	for _, key := range keys {
		result = append(result, AssuranceSlice{
			EndpointClass:  key.endpoint,
			AssuranceLevel: key.level,
			Withheld:       key.withheld,
			Evaluation:     values[key].finish(),
		})
	}
	if result == nil {
		return []AssuranceSlice{}
	}
	return result
}

func sortedEvaluationSlices(values map[evaluationSliceKey]*linkedAccumulator) []EvaluationSlice {
	keys := make([]evaluationSliceKey, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(left, right int) bool {
		if keys[left].endpoint == keys[right].endpoint {
			return keys[left].cohort < keys[right].cohort
		}
		return keys[left].endpoint < keys[right].endpoint
	})
	result := make([]EvaluationSlice, 0, len(keys))
	for _, key := range keys {
		result = append(result, EvaluationSlice{EndpointClass: key.endpoint, EvaluationCohort: key.cohort, Evaluation: values[key].finish()})
	}
	if result == nil {
		return []EvaluationSlice{}
	}
	return result
}

func (a *analyzer) sortedCanaryChallengeBudgets(values map[canaryEndpointKey]*linkedAccumulator) []CanaryChallengeBudget {
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
	result := make([]CanaryChallengeBudget, 0, len(keys))
	for _, key := range keys {
		evaluation := LinkedEvaluation{}
		if accumulator := values[key]; accumulator != nil {
			evaluation = accumulator.finish()
		} else {
			evaluation = finalizeLinkedEvaluation(evaluation)
		}
		terminal := evaluation.ChallengePassed + evaluation.ChallengeFailed + evaluation.ChallengeAbandoned + evaluation.FallbackUsed
		result = append(result, CanaryChallengeBudget{
			RolloutID: key.rolloutID, EndpointClass: key.endpoint, MatureChallenges: evaluation.MatureChallenges,
			ChallengePassed: evaluation.ChallengePassed, ChallengeFailed: evaluation.ChallengeFailed,
			ChallengeAbandoned: evaluation.ChallengeAbandoned, FallbackUsed: evaluation.FallbackUsed,
			UnresolvedMatureChallenges: evaluation.UnresolvedMatureChallenges,
			AmbiguousChallengeOutcomes: evaluation.AmbiguousChallengeOutcomes,
			TerminalOutcomeCoverage:    Proportion(terminal, evaluation.MatureChallenges),
			ChallengeAbandonmentRate:   evaluation.ChallengeAbandonmentRate,
			FallbackRate:               evaluation.FallbackRate,
		})
	}
	if result == nil {
		return []CanaryChallengeBudget{}
	}
	return result
}

func outcomeBit(value string) uint16 {
	switch value {
	case "successful_action":
		return outcomeSuccessful
	case "challenge_passed":
		return outcomeChallengePassed
	case "challenge_failed":
		return outcomeChallengeFailed
	case "challenge_abandoned":
		return outcomeChallengeAbandoned
	case "human_confirmed":
		return outcomeHumanConfirmed
	case "operator_confirmed_abuse":
		return outcomeAbuseConfirmed
	case "appeal_requested":
		return outcomeAppealRequested
	case "fallback_used":
		return outcomeFallbackUsed
	case "unknown":
		return outcomeUnknown
	default:
		return 0
	}
}
