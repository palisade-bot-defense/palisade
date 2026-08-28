package httpapi

import (
	"crypto/subtle"
	"math"
	"net/http"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/palisade-bot-defense/palisade/internal/adminui"
	"github.com/palisade-bot-defense/palisade/internal/analysisfeed"
	"github.com/palisade-bot-defense/palisade/internal/core"
	"github.com/palisade-bot-defense/palisade/internal/shadowanalysis"
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
	SchemaVersion  string                 `json:"schema_version"`
	GeneratedAt    time.Time              `json:"generated_at"`
	UptimeSeconds  uint64                 `json:"uptime_seconds"`
	Runtime        AdminRuntime           `json:"runtime"`
	Capabilities   AdminCapabilities      `json:"capabilities"`
	Traffic        AdminTraffic           `json:"traffic"`
	Recording      AdminRecording         `json:"recording"`
	Collection     AdminCollection        `json:"collection"`
	AnalysisStatus AdminAnalysisStatus    `json:"analysis_status"`
	Analysis       *shadowanalysis.Report `json:"analysis"`
}

type AdminRuntime struct {
	Mode          core.RuntimeMode `json:"mode"`
	RolloutID     string           `json:"rollout_id,omitempty"`
	PolicyVersion string           `json:"policy_version"`
	ModelVersion  string           `json:"model_version"`
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
		SchemaVersion: "palisade.admin-summary.v6",
		GeneratedAt:   now,
		UptimeSeconds: uptime,
		Runtime: AdminRuntime{
			Mode: s.admin.Mode, RolloutID: s.admin.RolloutID,
			PolicyVersion: s.admin.PolicyVersion, ModelVersion: s.admin.ModelVersion,
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
		Collection:     s.collectionSummary(),
		AnalysisStatus: analysisStatus,
		Analysis:       analysis,
	}
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
