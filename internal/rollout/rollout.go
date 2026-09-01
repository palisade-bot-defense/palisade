package rollout

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"time"

	"github.com/palisade-human-trust/palisade/internal/core"
	"github.com/palisade-human-trust/palisade/internal/shadowanalysis"
)

const (
	SchemaVersion                      = "palisade.rollout-plan.v2"
	MaximumCanaryBasisPoints           = uint32(1000)
	FullRolloutBasisPoints             = uint32(10_000)
	MinimumCanaryDecisions             = uint64(1000)
	MaximumCanaryDuration              = 7 * 24 * time.Hour
	MaximumEnforceDuration             = 24 * time.Hour
	DefaultDelaySeconds                = 1
	DefaultThrottleSeconds             = 5
	DefaultChallengeTTLSeconds         = 300
	DefaultBlockSeconds                = 300
	DefaultMinMatureChallenges         = uint64(100)
	DefaultMinChallengeOutcomeCoverage = 0.90
	DefaultMaxChallengeAbandonmentRate = 0.10
	DefaultMaxChallengeFallbackRate    = 0.10
	maximumResponseCostTier            = 4
)

const (
	ReasonResponseCostBaseline = "RESPONSE_COST_BASELINE"
	ReasonResponseCostEndpoint = "RESPONSE_COST_ENDPOINT_VALUE"
	ReasonResponseCostEvidence = "RESPONSE_COST_CONFIDENT_EVIDENCE"
	ReasonResponseCostBehavior = "RESPONSE_COST_RECENT_BEHAVIOR"
	ReasonResponseCostRetry    = "RESPONSE_COST_RETRY_HISTORY"
)

var (
	ErrInvalidPlan      = errors.New("invalid rollout plan")
	ErrInvalidSignature = errors.New("invalid rollout signature")
	ErrAnalysisNotReady = errors.New("analysis report is not ready for requested rollout")
	stableID            = regexp.MustCompile(`^[a-z0-9][a-z0-9_.:-]{2,63}$`)
	sha256Pattern       = regexp.MustCompile(`^[a-f0-9]{64}$`)
)

type Plan struct {
	SchemaVersion               string           `json:"schema_version"`
	RolloutID                   string           `json:"rollout_id"`
	ApprovalID                  string           `json:"approval_id"`
	PredecessorRolloutID        string           `json:"predecessor_rollout_id"`
	CreatedAt                   string           `json:"created_at"`
	ExpiresAt                   string           `json:"expires_at"`
	SourceReportSHA256          string           `json:"source_report_sha256"`
	SourceReadinessState        string           `json:"source_readiness_state"`
	PolicyVersion               string           `json:"policy_version"`
	ModelVersion                string           `json:"model_version"`
	Stage                       core.RuntimeMode `json:"stage"`
	EndpointClasses             []string         `json:"endpoint_classes"`
	MaxAction                   core.Action      `json:"max_action"`
	CanaryBasisPoints           uint32           `json:"canary_basis_points"`
	ThrottleSeconds             int              `json:"throttle_seconds"`
	ChallengeTTLSeconds         int              `json:"challenge_ttl_seconds"`
	BlockSeconds                int              `json:"block_seconds"`
	MinMatureChallenges         uint64           `json:"min_mature_challenges"`
	MinChallengeOutcomeCoverage float64          `json:"min_challenge_outcome_coverage"`
	MaxChallengeAbandonmentRate float64          `json:"max_challenge_abandonment_rate"`
	MaxChallengeFallbackRate    float64          `json:"max_challenge_fallback_rate"`
}

type SignedPlan struct {
	Plan      Plan   `json:"plan"`
	Signature string `json:"signature"`
}

type PrepareOptions struct {
	RolloutID                   string
	ApprovalID                  string
	PredecessorRolloutID        string
	Stage                       core.RuntimeMode
	EndpointClasses             []string
	MaxAction                   core.Action
	CanaryBasisPoints           uint32
	ThrottleSeconds             int
	ChallengeTTLSeconds         int
	BlockSeconds                int
	MinMatureChallenges         uint64
	MinChallengeOutcomeCoverage float64
	MaxChallengeAbandonmentRate float64
	MaxChallengeFallbackRate    float64
	CreatedAt                   time.Time
	ExpiresAt                   time.Time
}

type Result struct {
	Action    core.Action
	Mode      core.RuntimeMode
	RolloutID string
	Reasons   []string
	Directive core.EnforcementDirective
}

// AdaptiveContext contains only bounded, closed runtime aggregates. It must
// never contain an address, URL, fingerprint, raw event or free-form label.
type AdaptiveContext struct {
	SuspiciousEvidenceConfidence float64
	RequestCount                 uint64
	EndpointTransitions          uint64
	RecentEnforcements           uint8
	PrematureRetries             uint8
}

type Controller struct {
	plan      Plan
	cohortKey []byte
}

func prepareSignedPlan(report shadowanalysis.Report, reportBytes []byte, options PrepareOptions, privateKey ed25519.PrivateKey) (SignedPlan, error) {
	if err := validateReportBytes(report, reportBytes, true); err != nil {
		return SignedPlan{}, err
	}
	if report.SchemaVersion != shadowanalysis.SchemaVersion || report.Readiness.State != "operator_review_candidate" ||
		report.Readiness.OperatorAction != "review_reversible_canary" || report.Readiness.AutomaticEnforcement {
		return SignedPlan{}, ErrAnalysisNotReady
	}
	policyVersion, err := dominantVersion(report.PolicyVersions, report.Decisions.Total)
	if err != nil {
		return SignedPlan{}, err
	}
	modelVersion, err := dominantVersion(report.ModelVersions, report.Decisions.Total)
	if err != nil {
		return SignedPlan{}, err
	}
	if options.Stage == core.RuntimeModeEnforce && countedValue(report.CanaryRollouts, options.PredecessorRolloutID) < MinimumCanaryDecisions {
		return SignedPlan{}, fmt.Errorf("%w: enforce requires at least %d decisions from predecessor canary %q", ErrAnalysisNotReady, MinimumCanaryDecisions, options.PredecessorRolloutID)
	}
	if options.CreatedAt.IsZero() {
		options.CreatedAt = time.Now().UTC()
	}
	if options.ThrottleSeconds == 0 {
		options.ThrottleSeconds = DefaultThrottleSeconds
	}
	if options.ChallengeTTLSeconds == 0 {
		options.ChallengeTTLSeconds = DefaultChallengeTTLSeconds
	}
	if options.BlockSeconds == 0 {
		options.BlockSeconds = DefaultBlockSeconds
	}
	if options.MinMatureChallenges == 0 {
		options.MinMatureChallenges = DefaultMinMatureChallenges
	}
	if options.MinChallengeOutcomeCoverage == 0 {
		options.MinChallengeOutcomeCoverage = DefaultMinChallengeOutcomeCoverage
	}
	if options.MaxChallengeAbandonmentRate == 0 {
		options.MaxChallengeAbandonmentRate = DefaultMaxChallengeAbandonmentRate
	}
	if options.MaxChallengeFallbackRate == 0 {
		options.MaxChallengeFallbackRate = DefaultMaxChallengeFallbackRate
	}
	endpoints := append([]string(nil), options.EndpointClasses...)
	sort.Strings(endpoints)
	plan := Plan{
		SchemaVersion: SchemaVersion, RolloutID: options.RolloutID, ApprovalID: options.ApprovalID, PredecessorRolloutID: options.PredecessorRolloutID,
		CreatedAt:          options.CreatedAt.UTC().Truncate(time.Second).Format(time.RFC3339),
		ExpiresAt:          options.ExpiresAt.UTC().Truncate(time.Second).Format(time.RFC3339),
		SourceReportSHA256: hex.EncodeToString(sha256Sum(reportBytes)), SourceReadinessState: report.Readiness.State,
		PolicyVersion: policyVersion, ModelVersion: modelVersion, Stage: options.Stage,
		EndpointClasses: endpoints, MaxAction: options.MaxAction, CanaryBasisPoints: options.CanaryBasisPoints,
		ThrottleSeconds: options.ThrottleSeconds, ChallengeTTLSeconds: options.ChallengeTTLSeconds, BlockSeconds: options.BlockSeconds,
		MinMatureChallenges: options.MinMatureChallenges, MinChallengeOutcomeCoverage: options.MinChallengeOutcomeCoverage,
		MaxChallengeAbandonmentRate: options.MaxChallengeAbandonmentRate, MaxChallengeFallbackRate: options.MaxChallengeFallbackRate,
	}
	if err := plan.Validate(options.CreatedAt); err != nil {
		return SignedPlan{}, err
	}
	return Sign(plan, privateKey)
}

func validateReportBytes(report shadowanalysis.Report, reportBytes []byte, requireRolloutWindow bool) error {
	var encodedReport shadowanalysis.Report
	decoder := json.NewDecoder(bytes.NewReader(reportBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&encodedReport); err != nil || !reflect.DeepEqual(encodedReport, report) {
		return fmt.Errorf("%w: report bytes do not match parsed aggregate", ErrAnalysisNotReady)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: report contains multiple JSON values", ErrAnalysisNotReady)
	}
	validator := shadowanalysis.ValidateReport
	if requireRolloutWindow {
		validator = shadowanalysis.ValidateForRollout
	}
	if err := validator(report); err != nil {
		return fmt.Errorf("%w: %v", ErrAnalysisNotReady, err)
	}
	return nil
}

func Sign(plan Plan, privateKey ed25519.PrivateKey) (SignedPlan, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return SignedPlan{}, errors.New("invalid rollout private key")
	}
	encoded, err := canonicalPlan(plan)
	if err != nil {
		return SignedPlan{}, err
	}
	signature := ed25519.Sign(privateKey, encoded)
	return SignedPlan{Plan: plan, Signature: base64.RawURLEncoding.EncodeToString(signature)}, nil
}

func Verify(signed SignedPlan, publicKey ed25519.PublicKey, now time.Time) error {
	if len(publicKey) != ed25519.PublicKeySize {
		return errors.New("invalid rollout public key")
	}
	if err := signed.Plan.Validate(now); err != nil {
		return err
	}
	signature, err := base64.RawURLEncoding.DecodeString(signed.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return ErrInvalidSignature
	}
	encoded, err := canonicalPlan(signed.Plan)
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, encoded, signature) {
		return ErrInvalidSignature
	}
	return nil
}

func (p Plan) Validate(now time.Time) error {
	if p.SchemaVersion != SchemaVersion || !stableID.MatchString(p.RolloutID) || !stableID.MatchString(p.ApprovalID) ||
		!sha256Pattern.MatchString(p.SourceReportSHA256) || p.SourceReadinessState != "operator_review_candidate" ||
		!stableID.MatchString(p.PolicyVersion) || !stableID.MatchString(p.ModelVersion) {
		return ErrInvalidPlan
	}
	createdAt, err := canonicalTime(p.CreatedAt)
	if err != nil {
		return ErrInvalidPlan
	}
	expiresAt, err := canonicalTime(p.ExpiresAt)
	if err != nil || createdAt.After(now.UTC().Add(time.Minute)) || !expiresAt.After(createdAt) || !expiresAt.After(now.UTC()) {
		return ErrInvalidPlan
	}
	duration := expiresAt.Sub(createdAt)
	if p.Stage == core.RuntimeModeCanary {
		if duration > MaximumCanaryDuration || p.CanaryBasisPoints < 1 || p.CanaryBasisPoints > MaximumCanaryBasisPoints ||
			(p.MaxAction != core.ActionDelay && p.MaxAction != core.ActionThrottle && p.MaxAction != core.ActionChallenge) || p.PredecessorRolloutID != "" {
			return ErrInvalidPlan
		}
	} else if p.Stage == core.RuntimeModeEnforce {
		if duration > MaximumEnforceDuration || p.CanaryBasisPoints != FullRolloutBasisPoints ||
			(p.MaxAction != core.ActionDelay && p.MaxAction != core.ActionThrottle && p.MaxAction != core.ActionChallenge && p.MaxAction != core.ActionBlock) || !stableID.MatchString(p.PredecessorRolloutID) {
			return ErrInvalidPlan
		}
	} else {
		return ErrInvalidPlan
	}
	if p.ThrottleSeconds < 1 || p.ThrottleSeconds > 60 || p.ChallengeTTLSeconds < 30 || p.ChallengeTTLSeconds > 900 || p.BlockSeconds < 60 || p.BlockSeconds > 3600 ||
		p.MinMatureChallenges < 1 || p.MinMatureChallenges > 1_000_000 || !validBudgetRate(p.MinChallengeOutcomeCoverage) ||
		!validBudgetRate(p.MaxChallengeAbandonmentRate) || !validBudgetRate(p.MaxChallengeFallbackRate) {
		return ErrInvalidPlan
	}
	if len(p.EndpointClasses) < 1 || len(p.EndpointClasses) > 4 || !sort.StringsAreSorted(p.EndpointClasses) {
		return ErrInvalidPlan
	}
	for index, endpoint := range p.EndpointClasses {
		if !allowedEndpoint(endpoint) || (index > 0 && endpoint == p.EndpointClasses[index-1]) {
			return ErrInvalidPlan
		}
	}
	return nil
}

func validBudgetRate(value float64) bool {
	return !math.IsNaN(value) && !math.IsInf(value, 0) && value > 0 && value <= 1
}

func NewController(signed SignedPlan, publicKey ed25519.PublicKey, cohortKey []byte, policyVersion, modelVersion string, now time.Time) (*Controller, error) {
	if err := Verify(signed, publicKey, now); err != nil {
		return nil, err
	}
	if signed.Plan.PolicyVersion != policyVersion || signed.Plan.ModelVersion != modelVersion || len(cohortKey) < 32 {
		return nil, errors.New("rollout plan does not match runtime policy, model or cohort key")
	}
	return &Controller{plan: signed.Plan, cohortKey: append([]byte(nil), cohortKey...)}, nil
}

func (c *Controller) Apply(sessionID, endpoint string, computed core.Action, now time.Time) Result {
	return c.ApplyWithContext(sessionID, endpoint, computed, AdaptiveContext{}, now)
}

func (c *Controller) ApplyWithContext(sessionID, endpoint string, computed core.Action, context AdaptiveContext, now time.Time) Result {
	result := Result{Action: computed, Mode: c.plan.Stage, RolloutID: c.plan.RolloutID}
	expiresAt, _ := time.Parse(time.RFC3339, c.plan.ExpiresAt)
	if !expiresAt.After(now.UTC()) {
		result := shadowResult(computed, now, "ROLLOUT_EXPIRED")
		result.RolloutID = c.plan.RolloutID
		return result
	}
	if !slices.Contains(c.plan.EndpointClasses, endpoint) {
		result := shadowResult(computed, now, "ROLLOUT_ENDPOINT_EXCLUDED")
		result.RolloutID = c.plan.RolloutID
		return result
	}
	if c.plan.Stage == core.RuntimeModeCanary && c.bucket(sessionID) >= c.plan.CanaryBasisPoints {
		result := shadowResult(computed, now, "ROLLOUT_CANARY_EXCLUDED")
		result.RolloutID = c.plan.RolloutID
		return result
	}
	if !isRisky(computed) {
		result.Directive = directive(computed, now, c.plan)
		return result
	}
	if actionRank(result.Action) > actionRank(c.plan.MaxAction) {
		result.Action = c.plan.MaxAction
		result.Reasons = append(result.Reasons, "ROLLOUT_ACTION_CAPPED")
	}
	result.Directive = directive(result.Action, now, c.plan)
	if result.Action == core.ActionThrottle || result.Action == core.ActionBlock {
		var reasons []string
		result.Directive, reasons = adaptiveDirective(result.Action, endpoint, context, now, c.plan)
		result.Reasons = append(result.Reasons, reasons...)
	}
	return result
}

func (c *Controller) Plan() Plan { return c.plan }

func DefaultDirective(action core.Action, now time.Time) core.EnforcementDirective {
	return directive(action, now, Plan{})
}

func AdaptiveContextFrom(snapshot core.SessionSnapshot, evidence []core.Evidence) AdaptiveContext {
	context := AdaptiveContext{
		RequestCount: snapshot.RequestCount, EndpointTransitions: snapshot.EndpointTransitions,
		RecentEnforcements: snapshot.RecentEnforcements, PrematureRetries: snapshot.PrematureRetries,
	}
	for _, item := range evidence {
		if item.Direction == core.DirectionSuspicious && item.Strength >= .5 && item.Strength <= 1 &&
			item.Confidence >= 0 && item.Confidence <= 1 && item.Confidence > context.SuspiciousEvidenceConfidence {
			context.SuspiciousEvidenceConfidence = item.Confidence
		}
	}
	return context
}

func (c *Controller) bucket(sessionID string) uint32 {
	mac := hmac.New(sha256.New, c.cohortKey)
	_, _ = mac.Write([]byte("palisade:rollout-cohort:v1\x00" + c.plan.RolloutID + "\x00" + sessionID))
	sum := mac.Sum(nil)
	return (uint32(sum[0])<<8 | uint32(sum[1])) % FullRolloutBasisPoints
}

func shadowResult(computed core.Action, now time.Time, reason string) Result {
	action := computed
	if isRisky(action) {
		action = core.ActionObserve
	}
	return Result{Action: action, Mode: core.RuntimeModeShadow, Reasons: []string{reason}, Directive: directive(action, now, Plan{})}
}

func directive(action core.Action, now time.Time, plan Plan) core.EnforcementDirective {
	result := core.EnforcementDirective{Handling: "pass", HTTPStatus: 200, ExpiresAt: now.Add(30 * time.Second)}
	switch action {
	case core.ActionDelay:
		result = core.EnforcementDirective{Handling: "delay", HTTPStatus: 429, RetryAfterSeconds: DefaultDelaySeconds, ExpiresAt: now.Add(DefaultDelaySeconds * time.Second)}
	case core.ActionThrottle:
		seconds := plan.ThrottleSeconds
		if seconds == 0 {
			seconds = DefaultThrottleSeconds
		}
		result = core.EnforcementDirective{Handling: "throttle", HTTPStatus: 429, RetryAfterSeconds: seconds, ExpiresAt: now.Add(time.Duration(seconds) * time.Second)}
	case core.ActionChallenge:
		seconds := plan.ChallengeTTLSeconds
		if seconds == 0 {
			seconds = DefaultChallengeTTLSeconds
		}
		result = core.EnforcementDirective{Handling: "challenge", HTTPStatus: 403, ExpiresAt: now.Add(time.Duration(seconds) * time.Second)}
	case core.ActionBlock:
		seconds := plan.BlockSeconds
		if seconds == 0 {
			seconds = DefaultBlockSeconds
		}
		result = core.EnforcementDirective{Handling: "block", HTTPStatus: 403, RetryAfterSeconds: seconds, ExpiresAt: now.Add(time.Duration(seconds) * time.Second)}
	}
	if rolloutExpiry, err := time.Parse(time.RFC3339, plan.ExpiresAt); err == nil && rolloutExpiry.Before(result.ExpiresAt) {
		result.ExpiresAt = rolloutExpiry
		if result.RetryAfterSeconds > 0 {
			remaining := int(rolloutExpiry.Sub(now).Seconds())
			if remaining < 1 {
				remaining = 1
			}
			if remaining < result.RetryAfterSeconds {
				result.RetryAfterSeconds = remaining
			}
		}
	}
	return result
}

func adaptiveDirective(action core.Action, endpoint string, context AdaptiveContext, now time.Time, plan Plan) (core.EnforcementDirective, []string) {
	tier, reasons := responseCostTier(endpoint, context)
	result := directive(action, now, plan)
	switch action {
	case core.ActionThrottle:
		result.RetryAfterSeconds = scaledResponseSeconds(1, result.RetryAfterSeconds, tier)
		result.ExpiresAt = now.Add(time.Duration(result.RetryAfterSeconds) * time.Second)
	case core.ActionBlock:
		result.RetryAfterSeconds = scaledResponseSeconds(60, result.RetryAfterSeconds, tier)
		result.ExpiresAt = now.Add(time.Duration(result.RetryAfterSeconds) * time.Second)
	}
	if rolloutExpiry, err := time.Parse(time.RFC3339, plan.ExpiresAt); err == nil && rolloutExpiry.Before(result.ExpiresAt) {
		result.ExpiresAt = rolloutExpiry
		remaining := int(rolloutExpiry.Sub(now).Seconds())
		if remaining < 1 {
			remaining = 1
		}
		if remaining < result.RetryAfterSeconds {
			result.RetryAfterSeconds = remaining
		}
	}
	return result, reasons
}

func responseCostTier(endpoint string, context AdaptiveContext) (int, []string) {
	tier := 0
	reasons := make([]string, 0, maximumResponseCostTier)
	if endpoint == "compare_index" || endpoint == "compare_noindex" {
		tier++
		reasons = append(reasons, ReasonResponseCostEndpoint)
	}
	if context.SuspiciousEvidenceConfidence >= .75 && context.SuspiciousEvidenceConfidence <= 1 {
		tier++
		reasons = append(reasons, ReasonResponseCostEvidence)
	}
	if context.RequestCount >= 50 || context.EndpointTransitions >= 6 {
		tier++
		reasons = append(reasons, ReasonResponseCostBehavior)
	}
	if context.RecentEnforcements >= 2 || context.PrematureRetries >= 1 {
		tier++
		reasons = append(reasons, ReasonResponseCostRetry)
	}
	if tier == 0 {
		reasons = append(reasons, ReasonResponseCostBaseline)
	}
	return tier, reasons
}

func scaledResponseSeconds(minimum, maximum, tier int) int {
	if maximum <= minimum || tier <= 0 {
		return minimum
	}
	if tier >= maximumResponseCostTier {
		return maximum
	}
	return minimum + ((maximum-minimum)*tier+maximumResponseCostTier-1)/maximumResponseCostTier
}

func dominantVersion(values []shadowanalysis.CountedValue, decisions uint64) (string, error) {
	if decisions == 0 || len(values) == 0 || values[0].Count < decisions-decisions/10 || !stableID.MatchString(values[0].Value) {
		return "", fmt.Errorf("%w: policy/model version is not at least 90%% of decisions", ErrAnalysisNotReady)
	}
	return values[0].Value, nil
}

func countedValue(values []shadowanalysis.CountedValue, wanted string) uint64 {
	for _, value := range values {
		if value.Value == wanted {
			return value.Count
		}
	}
	return 0
}

func canonicalPlan(plan Plan) ([]byte, error) {
	return json.Marshal(plan)
}

func canonicalTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil || parsed.UTC().Truncate(time.Second).Format(time.RFC3339) != value {
		return time.Time{}, ErrInvalidPlan
	}
	return parsed, nil
}

func allowedEndpoint(value string) bool {
	switch value {
	case "public_content", "compare_index", "compare_noindex", "other_public":
		return true
	default:
		return false
	}
}

func isRisky(action core.Action) bool {
	return action == core.ActionDelay || action == core.ActionThrottle || action == core.ActionChallenge || action == core.ActionBlock
}

func actionRank(action core.Action) int {
	switch action {
	case core.ActionObserve:
		return 1
	case core.ActionDelay:
		return 2
	case core.ActionThrottle:
		return 3
	case core.ActionChallenge:
		return 4
	case core.ActionBlock:
		return 5
	default:
		return 0
	}
}

func sha256Sum(data []byte) []byte {
	sum := sha256.Sum256(data)
	return sum[:]
}
