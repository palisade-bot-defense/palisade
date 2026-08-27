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
	"reflect"
	"regexp"
	"slices"
	"sort"
	"time"

	"github.com/palisade-bot-defense/palisade/internal/core"
	"github.com/palisade-bot-defense/palisade/internal/shadowanalysis"
)

const (
	SchemaVersion              = "palisade.rollout-plan.v1"
	MaximumCanaryBasisPoints   = uint32(1000)
	FullRolloutBasisPoints     = uint32(10_000)
	MinimumCanaryDecisions     = uint64(1000)
	MaximumCanaryDuration      = 7 * 24 * time.Hour
	MaximumEnforceDuration     = 24 * time.Hour
	DefaultThrottleSeconds     = 5
	DefaultChallengeTTLSeconds = 300
	DefaultBlockSeconds        = 300
)

var (
	ErrInvalidPlan      = errors.New("invalid rollout plan")
	ErrInvalidSignature = errors.New("invalid rollout signature")
	ErrAnalysisNotReady = errors.New("analysis report is not ready for requested rollout")
	stableID            = regexp.MustCompile(`^[a-z0-9][a-z0-9_.:-]{2,63}$`)
	sha256Pattern       = regexp.MustCompile(`^[a-f0-9]{64}$`)
)

type Plan struct {
	SchemaVersion        string           `json:"schema_version"`
	RolloutID            string           `json:"rollout_id"`
	ApprovalID           string           `json:"approval_id"`
	PredecessorRolloutID string           `json:"predecessor_rollout_id"`
	CreatedAt            string           `json:"created_at"`
	ExpiresAt            string           `json:"expires_at"`
	SourceReportSHA256   string           `json:"source_report_sha256"`
	SourceReadinessState string           `json:"source_readiness_state"`
	PolicyVersion        string           `json:"policy_version"`
	ModelVersion         string           `json:"model_version"`
	Stage                core.RuntimeMode `json:"stage"`
	EndpointClasses      []string         `json:"endpoint_classes"`
	MaxAction            core.Action      `json:"max_action"`
	CanaryBasisPoints    uint32           `json:"canary_basis_points"`
	ThrottleSeconds      int              `json:"throttle_seconds"`
	ChallengeTTLSeconds  int              `json:"challenge_ttl_seconds"`
	BlockSeconds         int              `json:"block_seconds"`
}

type SignedPlan struct {
	Plan      Plan   `json:"plan"`
	Signature string `json:"signature"`
}

type PrepareOptions struct {
	RolloutID            string
	ApprovalID           string
	PredecessorRolloutID string
	Stage                core.RuntimeMode
	EndpointClasses      []string
	MaxAction            core.Action
	CanaryBasisPoints    uint32
	ThrottleSeconds      int
	ChallengeTTLSeconds  int
	BlockSeconds         int
	CreatedAt            time.Time
	ExpiresAt            time.Time
}

type Result struct {
	Action    core.Action
	Mode      core.RuntimeMode
	RolloutID string
	Reasons   []string
	Directive core.EnforcementDirective
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
			(p.MaxAction != core.ActionThrottle && p.MaxAction != core.ActionChallenge) || p.PredecessorRolloutID != "" {
			return ErrInvalidPlan
		}
	} else if p.Stage == core.RuntimeModeEnforce {
		if duration > MaximumEnforceDuration || p.CanaryBasisPoints != FullRolloutBasisPoints ||
			(p.MaxAction != core.ActionThrottle && p.MaxAction != core.ActionChallenge && p.MaxAction != core.ActionBlock) || !stableID.MatchString(p.PredecessorRolloutID) {
			return ErrInvalidPlan
		}
	} else {
		return ErrInvalidPlan
	}
	if p.ThrottleSeconds < 1 || p.ThrottleSeconds > 60 || p.ChallengeTTLSeconds < 30 || p.ChallengeTTLSeconds > 900 || p.BlockSeconds < 60 || p.BlockSeconds > 3600 {
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
	return result
}

func (c *Controller) Plan() Plan { return c.plan }

func DefaultDirective(action core.Action, now time.Time) core.EnforcementDirective {
	return directive(action, now, Plan{})
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
	return action == core.ActionThrottle || action == core.ActionChallenge || action == core.ActionBlock
}

func actionRank(action core.Action) int {
	switch action {
	case core.ActionObserve:
		return 1
	case core.ActionThrottle:
		return 2
	case core.ActionChallenge:
		return 3
	case core.ActionBlock:
		return 4
	default:
		return 0
	}
}

func sha256Sum(data []byte) []byte {
	sum := sha256.Sum256(data)
	return sum[:]
}
