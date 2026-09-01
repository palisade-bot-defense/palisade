package httpapi

import (
	"crypto/subtle"
	"math"
	"net/http"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/palisade-human-trust/palisade/internal/adminui"
	"github.com/palisade-human-trust/palisade/internal/analysisfeed"
	"github.com/palisade-human-trust/palisade/internal/core"
	"github.com/palisade-human-trust/palisade/internal/shadowanalysis"
)

// AdminConfig contains only immutable, non-secret runtime metadata and the
// credential used by the loopback-only administrative listener.
type AdminConfig struct {
	Key                  string
	StartedAt            time.Time
	Mode                 core.RuntimeMode
	RolloutID            string
	PolicyVersion        string
	ModelVersion         string
	PolicyArtifact       *AdminArtifactStatus
	DetectorArtifact     *AdminArtifactStatus
	ShadowLogEnabled     bool
	EventShadowEnabled   bool
	EventShadowFromProof bool
	AnalysisFeed         *analysisfeed.Feed
}

type actionCounters struct {
	allow     atomic.Uint64
	observe   atomic.Uint64
	delay     atomic.Uint64
	throttle  atomic.Uint64
	challenge atomic.Uint64
	block     atomic.Uint64
}

type runtimeCounters struct {
	eventBatches        atomic.Uint64
	events              atomic.Uint64
	decisions           atomic.Uint64
	originChecks        atomic.Uint64
	recordedDecisions   atomic.Uint64
	recordedOutcomes    atomic.Uint64
	contextProofs       atomic.Uint64
	eventShadowRecorded atomic.Uint64
	eventShadowRejected atomic.Uint64
	outcomeRejected     atomic.Uint64
	outcomeDropped      atomic.Uint64
	transport           transportCounters
	crawlers            crawlerCounters
	endpointContexts    endpointCounters
	enforced            actionCounters
	computed            actionCounters
	reasons             reasonCounters
}

const maxAdminReasonCodes = 64

type reasonCounters struct {
	mu     sync.Mutex
	counts map[string]uint64
}

type CountedReason struct {
	Code  string `json:"code"`
	Count uint64 `json:"count"`
}

type AdminSummary struct {
	SchemaVersion   string                 `json:"schema_version"`
	GeneratedAt     time.Time              `json:"generated_at"`
	UptimeSeconds   uint64                 `json:"uptime_seconds"`
	Runtime         AdminRuntime           `json:"runtime"`
	Capabilities    AdminCapabilities      `json:"capabilities"`
	Traffic         AdminTraffic           `json:"traffic"`
	Recording       AdminRecording         `json:"recording"`
	Collection      AdminCollection        `json:"collection"`
	OriginCoverage  AdminOriginCoverage    `json:"origin_coverage"`
	OutcomeFlow     AdminOutcomeFlow       `json:"outcome_flow"`
	Transport       AdminTransportPosture  `json:"transport_posture"`
	CrawlerIdentity AdminCrawlerIdentity   `json:"crawler_identity"`
	AnalysisStatus  AdminAnalysisStatus    `json:"analysis_status"`
	Analysis        *shadowanalysis.Report `json:"analysis"`
}

type AdminRuntime struct {
	Mode             core.RuntimeMode     `json:"mode"`
	RolloutID        string               `json:"rollout_id,omitempty"`
	PolicyVersion    string               `json:"policy_version"`
	ModelVersion     string               `json:"model_version"`
	PolicyArtifact   *AdminArtifactStatus `json:"policy_artifact,omitempty"`
	DetectorArtifact *AdminArtifactStatus `json:"detector_artifact,omitempty"`
}

type AdminArtifactStatus struct {
	ArtifactType string    `json:"artifact_type"`
	ArtifactID   string    `json:"artifact_id"`
	Revision     uint64    `json:"revision"`
	ExpiresAt    time.Time `json:"expires_at"`
	State        string    `json:"state"`
}

type AdminCapabilities struct {
	ShadowLog                bool `json:"shadow_log"`
	EventShadow              bool `json:"event_shadow"`
	EventShadowProofContexts bool `json:"event_shadow_proof_contexts"`
	AnalysisReport           bool `json:"analysis_report"`
}

type AdminTraffic struct {
	AcceptedEventBatches uint64            `json:"accepted_event_batches"`
	AcceptedEvents       uint64            `json:"accepted_events"`
	Decisions            uint64            `json:"decisions"`
	OriginChecks         uint64            `json:"origin_checks"`
	Enforced             AdminActionCounts `json:"enforced"`
	Computed             AdminActionCounts `json:"computed"`
	Reasons              []CountedReason   `json:"reasons"`
}

type AdminActionCounts struct {
	Allow     uint64 `json:"allow"`
	Observe   uint64 `json:"observe"`
	Delay     uint64 `json:"delay"`
	Throttle  uint64 `json:"throttle"`
	Challenge uint64 `json:"challenge"`
	Block     uint64 `json:"block"`
}

type AdminRecording struct {
	Decisions          uint64 `json:"decisions"`
	Outcomes           uint64 `json:"outcomes"`
	Dropped            uint64 `json:"dropped"`
	EventShadowDropped uint64 `json:"event_shadow_dropped"`
}

type AdminCollection struct {
	State                   string               `json:"state"`
	TrafficDenominator      string               `json:"traffic_denominator"`
	ContextProofsIssued     uint64               `json:"context_proofs_issued"`
	AcceptedEventBatches    uint64               `json:"accepted_event_batches"`
	RecordedShadowDecisions uint64               `json:"recorded_shadow_decisions"`
	RejectedBeforeIngest    uint64               `json:"rejected_before_ingest"`
	DroppedAfterIngest      uint64               `json:"dropped_after_ingest"`
	BatchRecordingRate      float64              `json:"batch_recording_rate"`
	EndpointContextProofs   []AdminEndpointCount `json:"endpoint_context_proofs"`
}

type AdminEndpointCount struct {
	EndpointClass string `json:"endpoint_class"`
	Count         uint64 `json:"count"`
}

type AdminOriginCoverage struct {
	State              string                        `json:"state"`
	Scope              string                        `json:"scope"`
	TrafficDenominator string                        `json:"traffic_denominator"`
	Sources            uint64                        `json:"sources"`
	ObservedSince      *time.Time                    `json:"observed_since"`
	LastReportedAt     *time.Time                    `json:"last_reported_at"`
	ProtectedRequests  uint64                        `json:"protected_requests"`
	EvaluatedRequests  uint64                        `json:"evaluated_requests"`
	BypassedRequests   uint64                        `json:"bypassed_requests"`
	RejectedRequests   uint64                        `json:"rejected_requests"`
	GrantedRetries     uint64                        `json:"granted_retries"`
	DecisionCoverage   float64                       `json:"decision_coverage_rate"`
	Endpoints          []AdminOriginCoverageEndpoint `json:"endpoints"`
}

type AdminOriginCoverageEndpoint struct {
	EndpointClass  string `json:"endpoint_class"`
	Protected      uint64 `json:"protected_requests"`
	Evaluated      uint64 `json:"evaluated_requests"`
	Bypassed       uint64 `json:"bypassed_requests"`
	Rejected       uint64 `json:"rejected_requests"`
	GrantedRetries uint64 `json:"granted_retries"`
}

type AdminOutcomeFlow struct {
	State    string `json:"state"`
	Accepted uint64 `json:"accepted"`
	Rejected uint64 `json:"rejected"`
	Dropped  uint64 `json:"dropped"`
}

type transportCounters struct {
	samples       atomic.Uint64
	protocol      [4]atomic.Uint64
	security      [4]atomic.Uint64
	addressSource [4]atomic.Uint64
}

type AdminTransportPosture struct {
	State         string                      `json:"state"`
	Scope         string                      `json:"scope"`
	Samples       uint64                      `json:"samples"`
	Protocol      AdminTransportProtocol      `json:"protocol"`
	Security      AdminTransportSecurity      `json:"security"`
	AddressSource AdminTransportAddressSource `json:"address_source"`
}

type AdminTransportProtocol struct {
	HTTP1   uint64 `json:"http1"`
	HTTP2   uint64 `json:"http2"`
	HTTP3   uint64 `json:"http3"`
	Unknown uint64 `json:"unknown"`
}

type AdminTransportSecurity struct {
	DirectTLS       uint64 `json:"direct_tls"`
	TrustedProxyTLS uint64 `json:"trusted_proxy_tls"`
	Plaintext       uint64 `json:"plaintext"`
	Unknown         uint64 `json:"unknown"`
}

type AdminTransportAddressSource struct {
	Direct              uint64 `json:"direct"`
	TrustedProxy        uint64 `json:"trusted_proxy"`
	InvalidTrustedProxy uint64 `json:"invalid_trusted_proxy"`
	Unknown             uint64 `json:"unknown"`
}

type crawlerCounters struct {
	observations atomic.Uint64
	qualified    atomic.Uint64
	unqualified  atomic.Uint64
	classes      [8]atomic.Uint64
	verification [4]atomic.Uint64
}

type AdminCrawlerIdentity struct {
	State        string                         `json:"state"`
	Scope        string                         `json:"scope"`
	Observations uint64                         `json:"observations"`
	Qualified    uint64                         `json:"qualified_public"`
	Unqualified  uint64                         `json:"unqualified"`
	Classes      AdminCrawlerClassCounts        `json:"classes"`
	Verification AdminCrawlerVerificationCounts `json:"verification"`
}

type AdminCrawlerClassCounts struct {
	SearchIndexer      uint64 `json:"search_indexer"`
	AnswerEngine       uint64 `json:"answer_engine"`
	TrainingCrawler    uint64 `json:"training_crawler"`
	UserTriggeredAgent uint64 `json:"user_triggered_agent"`
	Preview            uint64 `json:"preview"`
	Monitoring         uint64 `json:"monitoring"`
	Other              uint64 `json:"other"`
	Unknown            uint64 `json:"unknown"`
}

type AdminCrawlerVerificationCounts struct {
	IPUARegistry  uint64 `json:"ip_ua_registry"`
	FCrDNSUA      uint64 `json:"fcrdns_ua"`
	HTTPSignature uint64 `json:"http_signature"`
	Unknown       uint64 `json:"unknown"`
}

type endpointCounters struct {
	values [9]atomic.Uint64
}

type AdminAnalysisStatus struct {
	State         string     `json:"state"`
	LoadedAt      *time.Time `json:"loaded_at"`
	LastAttemptAt *time.Time `json:"last_attempt_at"`
}

func (s *Server) WithAdmin(config AdminConfig) *Server {
	s.admin = config
	if s.admin.StartedAt.IsZero() {
		s.admin.StartedAt = time.Now().UTC()
	}
	return s
}

// AdminHandler is intentionally separate from Handler. The CLI binds it only
// to a loopback listener, keeping the operator surface off the public API.
func (s *Server) AdminHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health/live", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /health/ready", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
	})
	mux.HandleFunc("GET /v1/admin/summary", s.handleAdminSummary)
	mux.Handle("GET /", adminui.Handler())
	return s.recover(s.securityHeaders(mux))
}

func (s *Server) handleAdminSummary(w http.ResponseWriter, r *http.Request) {
	if !s.adminAuthorized(r) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="palisade-admin"`)
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	writeJSON(w, http.StatusOK, s.adminSummary(time.Now().UTC()))
}

func (s *Server) adminSummary(now time.Time) AdminSummary {
	uptime := uint64(0)
	if now.After(s.admin.StartedAt) {
		uptime = uint64(now.Sub(s.admin.StartedAt) / time.Second)
	}
	analysisStatus := AdminAnalysisStatus{State: "not_configured"}
	var analysis *shadowanalysis.Report
	if s.admin.AnalysisFeed != nil {
		snapshot := s.admin.AnalysisFeed.Snapshot()
		analysis = snapshot.Report
		analysisStatus.State = snapshot.State
		if !snapshot.LoadedAt.IsZero() {
			loadedAt := snapshot.LoadedAt
			analysisStatus.LoadedAt = &loadedAt
		}
		if !snapshot.LastAttemptAt.IsZero() {
			attemptedAt := snapshot.LastAttemptAt
			analysisStatus.LastAttemptAt = &attemptedAt
		}
	}
	return AdminSummary{
		SchemaVersion: "palisade.admin-summary.v10",
		GeneratedAt:   now,
		UptimeSeconds: uptime,
		Runtime: AdminRuntime{
			Mode: s.admin.Mode, RolloutID: s.admin.RolloutID,
			PolicyVersion: s.admin.PolicyVersion, ModelVersion: s.admin.ModelVersion,
			PolicyArtifact: artifactStatusAt(s.admin.PolicyArtifact, now), DetectorArtifact: artifactStatusAt(s.admin.DetectorArtifact, now),
		},
		Capabilities: AdminCapabilities{
			ShadowLog: s.admin.ShadowLogEnabled, EventShadow: s.admin.EventShadowEnabled,
			EventShadowProofContexts: s.admin.EventShadowFromProof, AnalysisReport: analysis != nil,
		},
		Traffic: AdminTraffic{
			AcceptedEventBatches: s.counters.eventBatches.Load(), AcceptedEvents: s.counters.events.Load(),
			Decisions: s.counters.decisions.Load(), OriginChecks: s.counters.originChecks.Load(),
			Enforced: s.counters.enforced.snapshot(), Computed: s.counters.computed.snapshot(), Reasons: s.counters.reasons.snapshot(),
		},
		Recording: AdminRecording{
			Decisions: s.counters.recordedDecisions.Load(), Outcomes: s.counters.recordedOutcomes.Load(),
			Dropped: s.shadowDrops.Load(), EventShadowDropped: s.eventShadowDrops.Load(),
		},
		Collection:      s.collectionSummary(),
		OriginCoverage:  s.originCoverageSummary(),
		OutcomeFlow:     s.outcomeFlowSummary(),
		Transport:       s.transportPostureSummary(),
		CrawlerIdentity: s.counters.crawlers.snapshot(),
		AnalysisStatus:  analysisStatus,
		Analysis:        analysis,
	}
}

func artifactStatusAt(status *AdminArtifactStatus, now time.Time) *AdminArtifactStatus {
	if status == nil {
		return nil
	}
	copy := *status
	copy.State = "current"
	if !now.Before(copy.ExpiresAt) {
		copy.State = "expired"
	}
	return &copy
}

func (c *crawlerCounters) increment(observations core.Observations, endpointClass string) {
	class, _ := core.NormalizeCrawlerClass(observations.CrawlerClass)
	verification, _ := core.NormalizeCrawlerVerification(observations.CrawlerVerification)
	if !observations.VerifiedBot && class == core.CrawlerClassUnknown && verification == core.CrawlerVerificationUnknown {
		return
	}
	c.observations.Add(1)
	c.classes[crawlerClassIndex(class)].Add(1)
	c.verification[crawlerVerificationIndex(verification)].Add(1)
	if core.VerifiedPublicCrawler(observations, endpointClass) {
		c.qualified.Add(1)
	} else {
		c.unqualified.Add(1)
	}
}

func (c *crawlerCounters) snapshot() AdminCrawlerIdentity {
	result := AdminCrawlerIdentity{
		State: "no_samples", Scope: "evaluated_identity_observations",
		Observations: c.observations.Load(), Qualified: c.qualified.Load(), Unqualified: c.unqualified.Load(),
		Classes: AdminCrawlerClassCounts{
			SearchIndexer: c.classes[0].Load(), AnswerEngine: c.classes[1].Load(), TrainingCrawler: c.classes[2].Load(),
			UserTriggeredAgent: c.classes[3].Load(), Preview: c.classes[4].Load(), Monitoring: c.classes[5].Load(),
			Other: c.classes[6].Load(), Unknown: c.classes[7].Load(),
		},
		Verification: AdminCrawlerVerificationCounts{
			IPUARegistry: c.verification[0].Load(), FCrDNSUA: c.verification[1].Load(),
			HTTPSignature: c.verification[2].Load(), Unknown: c.verification[3].Load(),
		},
	}
	if result.Observations > 0 {
		result.State = "collecting"
	}
	if result.Unqualified > 0 {
		result.State = "attention"
	}
	return result
}

func crawlerClassIndex(value core.CrawlerClass) int {
	switch value {
	case core.CrawlerClassSearchIndexer:
		return 0
	case core.CrawlerClassAnswerEngine:
		return 1
	case core.CrawlerClassTrainingCrawler:
		return 2
	case core.CrawlerClassUserTriggeredAgent:
		return 3
	case core.CrawlerClassPreview:
		return 4
	case core.CrawlerClassMonitoring:
		return 5
	case core.CrawlerClassOther:
		return 6
	default:
		return 7
	}
}

func crawlerVerificationIndex(value core.CrawlerVerification) int {
	switch value {
	case core.CrawlerVerificationIPUARegistry:
		return 0
	case core.CrawlerVerificationFCrDNSUA:
		return 1
	case core.CrawlerVerificationHTTPSignature:
		return 2
	default:
		return 3
	}
}

func (s *Server) transportPostureSummary() AdminTransportPosture {
	result := s.counters.transport.snapshot()
	result.State = "no_samples"
	result.Scope = "evaluated_decisions"
	if result.Samples == 0 {
		return result
	}
	result.State = "collecting"
	if result.Protocol.Unknown > 0 || result.Security.Plaintext > 0 || result.Security.Unknown > 0 ||
		result.AddressSource.InvalidTrustedProxy > 0 || result.AddressSource.Unknown > 0 {
		result.State = "attention"
	}
	return result
}

func (c *transportCounters) increment(observations core.Observations) {
	c.samples.Add(1)
	c.protocol[transportProtocolIndex(observations.TransportProtocol)].Add(1)
	c.security[transportSecurityIndex(observations.TransportSecurity)].Add(1)
	c.addressSource[transportAddressSourceIndex(observations.ClientAddressSource)].Add(1)
}

func (c *transportCounters) snapshot() AdminTransportPosture {
	return AdminTransportPosture{
		Samples: c.samples.Load(),
		Protocol: AdminTransportProtocol{
			HTTP1: c.protocol[0].Load(), HTTP2: c.protocol[1].Load(), HTTP3: c.protocol[2].Load(), Unknown: c.protocol[3].Load(),
		},
		Security: AdminTransportSecurity{
			DirectTLS: c.security[0].Load(), TrustedProxyTLS: c.security[1].Load(), Plaintext: c.security[2].Load(), Unknown: c.security[3].Load(),
		},
		AddressSource: AdminTransportAddressSource{
			Direct: c.addressSource[0].Load(), TrustedProxy: c.addressSource[1].Load(),
			InvalidTrustedProxy: c.addressSource[2].Load(), Unknown: c.addressSource[3].Load(),
		},
	}
}

func transportProtocolIndex(value string) int {
	switch value {
	case "http1":
		return 0
	case "http2":
		return 1
	case "http3":
		return 2
	default:
		return 3
	}
}

func transportSecurityIndex(value string) int {
	switch value {
	case "direct_tls":
		return 0
	case "trusted_proxy_tls":
		return 1
	case "plaintext":
		return 2
	default:
		return 3
	}
}

func transportAddressSourceIndex(value string) int {
	switch value {
	case "direct":
		return 0
	case "trusted_proxy":
		return 1
	case "invalid_trusted_proxy":
		return 2
	default:
		return 3
	}
}

func (s *Server) originCoverageSummary() AdminOriginCoverage {
	snapshot := s.originCoverage.snapshot()
	result := AdminOriginCoverage{
		State: "unavailable", Scope: "protected_handler_requests", TrafficDenominator: "authenticated_origin_reports",
		Sources: snapshot.Sources, ObservedSince: snapshot.ObservedSince, LastReportedAt: snapshot.LastReportedAt,
		Endpoints: make([]AdminOriginCoverageEndpoint, 0, len(snapshot.Endpoints)),
	}
	for _, counter := range snapshot.Endpoints {
		result.ProtectedRequests += counter.Protected
		result.EvaluatedRequests += counter.Evaluated
		result.BypassedRequests += counter.Bypassed
		result.RejectedRequests += counter.Rejected
		result.GrantedRetries += counter.GrantedRetries
		if counter.Protected > 0 {
			result.Endpoints = append(result.Endpoints, AdminOriginCoverageEndpoint{
				EndpointClass: counter.EndpointClass, Protected: counter.Protected, Evaluated: counter.Evaluated,
				Bypassed: counter.Bypassed, Rejected: counter.Rejected, GrantedRetries: counter.GrantedRetries,
			})
		}
	}
	if result.Sources > 0 {
		result.State = "no_samples"
	}
	if result.ProtectedRequests > 0 {
		result.State = "collecting"
		result.DecisionCoverage = math.Min(1, float64(result.EvaluatedRequests+result.GrantedRetries)/float64(result.ProtectedRequests))
	}
	if result.BypassedRequests > 0 || result.RejectedRequests > 0 {
		result.State = "degraded"
	}
	return result
}

func (s *Server) outcomeFlowSummary() AdminOutcomeFlow {
	result := AdminOutcomeFlow{
		State: "disabled", Accepted: s.counters.recordedOutcomes.Load(),
		Rejected: s.counters.outcomeRejected.Load(), Dropped: s.counters.outcomeDropped.Load(),
	}
	if s.admin.ShadowLogEnabled {
		result.State = "no_samples"
		if result.Accepted > 0 {
			result.State = "collecting"
		}
		if result.Rejected > 0 || result.Dropped > 0 {
			result.State = "degraded"
		}
	}
	return result
}

func (s *Server) collectionSummary() AdminCollection {
	accepted := s.counters.eventBatches.Load()
	recorded := s.counters.eventShadowRecorded.Load()
	rejected := s.counters.eventShadowRejected.Load()
	dropped := s.eventShadowDrops.Load()
	state := "disabled"
	if s.admin.EventShadowEnabled {
		state = "no_samples"
		if accepted > 0 {
			state = "collecting"
		}
		if rejected > 0 || dropped > 0 {
			state = "degraded"
		}
	}
	rate := 0.0
	if accepted > 0 {
		rate = math.Min(1, float64(recorded)/float64(accepted))
	}
	return AdminCollection{
		State: state, TrafficDenominator: "external_total_unavailable",
		ContextProofsIssued: s.counters.contextProofs.Load(), AcceptedEventBatches: accepted,
		RecordedShadowDecisions: recorded, RejectedBeforeIngest: rejected, DroppedAfterIngest: dropped,
		BatchRecordingRate: rate, EndpointContextProofs: s.counters.endpointContexts.snapshot(),
	}
}

func (c *endpointCounters) increment(endpoint string) {
	index := endpointIndex(endpoint)
	if index >= 0 {
		c.values[index].Add(1)
	}
}

func (c *endpointCounters) snapshot() []AdminEndpointCount {
	result := make([]AdminEndpointCount, 0, len(c.values))
	for index, endpoint := range adminEndpointClasses {
		if count := c.values[index].Load(); count > 0 {
			result = append(result, AdminEndpointCount{EndpointClass: endpoint, Count: count})
		}
	}
	return result
}

var adminEndpointClasses = [...]string{"public_content", "compare_index", "compare_noindex", "challenge_worker", "other_public", "account", "login", "checkout", "other"}

func endpointIndex(endpoint string) int {
	for index, candidate := range adminEndpointClasses {
		if endpoint == candidate {
			return index
		}
	}
	return -1
}

func (s *Server) adminAuthorized(r *http.Request) bool {
	if s.admin.Key == "" {
		return false
	}
	provided := r.Header.Get("Authorization")
	expected := "Bearer " + s.admin.Key
	return len(provided) == len(expected) && subtle.ConstantTimeCompare([]byte(provided), []byte(expected)) == 1
}

func (s *Server) recordRuntimeDecision(decision core.Decision) {
	s.counters.decisions.Add(1)
	s.counters.enforced.increment(decision.Action)
	s.counters.computed.increment(decision.ComputedAction)
	s.counters.reasons.increment(decision.ReasonCodes)
}

func (c *actionCounters) increment(action core.Action) {
	switch action {
	case core.ActionAllow:
		c.allow.Add(1)
	case core.ActionObserve:
		c.observe.Add(1)
	case core.ActionDelay:
		c.delay.Add(1)
	case core.ActionThrottle:
		c.throttle.Add(1)
	case core.ActionChallenge:
		c.challenge.Add(1)
	case core.ActionBlock:
		c.block.Add(1)
	}
}

func (c *reasonCounters) increment(codes []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.counts == nil {
		c.counts = make(map[string]uint64)
	}
	seen := make(map[string]struct{}, len(codes))
	for _, code := range codes {
		if !validAdminReason(code) {
			continue
		}
		if _, duplicate := seen[code]; duplicate {
			continue
		}
		seen[code] = struct{}{}
		if _, exists := c.counts[code]; !exists && len(c.counts) >= maxAdminReasonCodes {
			continue
		}
		if c.counts[code] < math.MaxUint64 {
			c.counts[code]++
		}
	}
}

func (c *reasonCounters) snapshot() []CountedReason {
	c.mu.Lock()
	defer c.mu.Unlock()
	result := make([]CountedReason, 0, len(c.counts))
	for code, count := range c.counts {
		result = append(result, CountedReason{Code: code, Count: count})
	}
	sort.Slice(result, func(left, right int) bool {
		if result[left].Count != result[right].Count {
			return result[left].Count > result[right].Count
		}
		return result[left].Code < result[right].Code
	})
	return result
}

func validAdminReason(value string) bool {
	if len(value) < 3 || len(value) > 64 {
		return false
	}
	for _, character := range value {
		if (character < 'A' || character > 'Z') && (character < '0' || character > '9') && character != '_' {
			return false
		}
	}
	return true
}

func (c *actionCounters) snapshot() AdminActionCounts {
	return AdminActionCounts{
		Allow: c.allow.Load(), Observe: c.observe.Load(), Delay: c.delay.Load(), Throttle: c.throttle.Load(),
		Challenge: c.challenge.Load(), Block: c.block.Load(),
	}
}
