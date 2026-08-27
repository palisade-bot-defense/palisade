package httpapi

import (
	"crypto/subtle"
	"net/http"
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
	Key                string
	StartedAt          time.Time
	Mode               core.RuntimeMode
	RolloutID          string
	PolicyVersion      string
	ModelVersion       string
	ShadowLogEnabled   bool
	EventShadowEnabled bool
	AnalysisFeed       *analysisfeed.Feed
}

type actionCounters struct {
	allow     atomic.Uint64
	observe   atomic.Uint64
	throttle  atomic.Uint64
	challenge atomic.Uint64
	block     atomic.Uint64
}

type runtimeCounters struct {
	eventBatches      atomic.Uint64
	events            atomic.Uint64
	decisions         atomic.Uint64
	originChecks      atomic.Uint64
	recordedDecisions atomic.Uint64
	recordedOutcomes  atomic.Uint64
	enforced          actionCounters
	computed          actionCounters
}

type AdminSummary struct {
	SchemaVersion  string                 `json:"schema_version"`
	GeneratedAt    time.Time              `json:"generated_at"`
	UptimeSeconds  uint64                 `json:"uptime_seconds"`
	Runtime        AdminRuntime           `json:"runtime"`
	Capabilities   AdminCapabilities      `json:"capabilities"`
	Traffic        AdminTraffic           `json:"traffic"`
	Recording      AdminRecording         `json:"recording"`
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
	ShadowLog      bool `json:"shadow_log"`
	EventShadow    bool `json:"event_shadow"`
	AnalysisReport bool `json:"analysis_report"`
}

type AdminTraffic struct {
	AcceptedEventBatches uint64                      `json:"accepted_event_batches"`
	AcceptedEvents       uint64                      `json:"accepted_events"`
	Decisions            uint64                      `json:"decisions"`
	OriginChecks         uint64                      `json:"origin_checks"`
	Enforced             shadowanalysis.ActionCounts `json:"enforced"`
	Computed             shadowanalysis.ActionCounts `json:"computed"`
}

type AdminRecording struct {
	Decisions          uint64 `json:"decisions"`
	Outcomes           uint64 `json:"outcomes"`
	Dropped            uint64 `json:"dropped"`
	EventShadowDropped uint64 `json:"event_shadow_dropped"`
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
		SchemaVersion: "palisade.admin-summary.v4",
		GeneratedAt:   now,
		UptimeSeconds: uptime,
		Runtime: AdminRuntime{
			Mode: s.admin.Mode, RolloutID: s.admin.RolloutID,
			PolicyVersion: s.admin.PolicyVersion, ModelVersion: s.admin.ModelVersion,
		},
		Capabilities: AdminCapabilities{
			ShadowLog: s.admin.ShadowLogEnabled, EventShadow: s.admin.EventShadowEnabled, AnalysisReport: analysis != nil,
		},
		Traffic: AdminTraffic{
			AcceptedEventBatches: s.counters.eventBatches.Load(), AcceptedEvents: s.counters.events.Load(),
			Decisions: s.counters.decisions.Load(), OriginChecks: s.counters.originChecks.Load(),
			Enforced: s.counters.enforced.snapshot(), Computed: s.counters.computed.snapshot(),
		},
		Recording: AdminRecording{
			Decisions: s.counters.recordedDecisions.Load(), Outcomes: s.counters.recordedOutcomes.Load(),
			Dropped: s.shadowDrops.Load(), EventShadowDropped: s.eventShadowDrops.Load(),
		},
		AnalysisStatus: analysisStatus,
		Analysis:       analysis,
	}
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
}

func (c *actionCounters) increment(action core.Action) {
	switch action {
	case core.ActionAllow:
		c.allow.Add(1)
	case core.ActionObserve:
		c.observe.Add(1)
	case core.ActionThrottle:
		c.throttle.Add(1)
	case core.ActionChallenge:
		c.challenge.Add(1)
	case core.ActionBlock:
		c.block.Add(1)
	}
}

func (c *actionCounters) snapshot() shadowanalysis.ActionCounts {
	return shadowanalysis.ActionCounts{
		Allow: c.allow.Load(), Observe: c.observe.Load(), Throttle: c.throttle.Load(),
		Challenge: c.challenge.Load(), Block: c.block.Load(),
	}
}
