// Package proxytlsdiag contains an opt-in synthetic test diagnostic and is not linked into PALISADE runtime binaries.
package proxytlsdiag

import (
	"encoding/json"
	"errors"
	"math"
	"slices"
	"strings"
	"testing"
)

const (
	PlanSchemaVersion   = "palisade.proxy-tls-load-plan.v1"
	ReportSchemaVersion = "palisade.proxy-tls-load-diagnostic.v1"
	MinimumDuration     = 1
	MaximumDuration     = 300
	MinimumConcurrency  = 1
	MaximumConcurrency  = 64
	MinimumOperations   = 1
	MaximumOperations   = 200_000
	MaximumResponseSize = 64 << 10
	RequestTimeoutSec   = 5

	ProfileOriginMiddleware = "origin_middleware_trusted_proxy_http2_tls"
	ProfileReverseProxy     = "standalone_reverse_proxy_http2_tls"
)

var (
	ErrInvalidConfig = errors.New("proxy/TLS diagnostic configuration is invalid")
	ErrBoundary      = errors.New("proxy/TLS diagnostic boundary failed")
	profileOrder     = []string{ProfileOriginMiddleware, ProfileReverseProxy}
	limitations      = []string{
		"synthetic closed signals only; no deployment or customer records",
		"single-machine loopback TLS with ephemeral self-signed certificates",
		"exercises the two Go reference adapters and a closed synthetic PALISADE fixture",
		"measures complete protected requests including adapter session management, proof and origin-check work",
		"excludes public PKI, certificate rotation, HTTP/3, external proxies and multiple replicas",
		"not a detection-efficacy, false-positive, accessibility or production-capacity claim",
		"results vary with hardware, operating system, scheduling and concurrent local workloads",
	}
)

type Config struct {
	DurationSeconds int `json:"duration_seconds"`
	Concurrency     int `json:"concurrency"`
	MaxOperations   int `json:"max_operations_per_profile"`
}

type Plan struct {
	SchemaVersion            string   `json:"schema_version"`
	SyntheticOnly            bool     `json:"synthetic_only"`
	RawDeploymentRecordsUsed bool     `json:"raw_deployment_records_used"`
	NetworkScope             string   `json:"network_scope"`
	Profiles                 []string `json:"profiles"`
	Configured               Config   `json:"configured"`
	MaxResponseBytes         int      `json:"max_response_bytes"`
	RequestTimeoutSeconds    int      `json:"request_timeout_seconds"`
	Limitations              []string `json:"limitations"`
}

type BoundaryCounts struct {
	Protocol int `json:"protocol"`
	Privacy  int `json:"privacy"`
	Service  int `json:"service_contract"`
	Upstream int `json:"upstream_contract"`
}

func (counts BoundaryCounts) Total() int {
	return counts.Protocol + counts.Privacy + counts.Service + counts.Upstream
}

type FailureCounts struct {
	Client           int `json:"client"`
	ResponseTooLarge int `json:"response_too_large"`
	AdapterResponse  int `json:"adapter_response"`
}

func (counts FailureCounts) Total() int {
	return counts.Client + counts.ResponseTooLarge + counts.AdapterResponse
}

type Latency struct {
	Samples int      `json:"samples"`
	P50     *float64 `json:"p50"`
	P95     *float64 `json:"p95"`
	P99     *float64 `json:"p99"`
	Maximum *float64 `json:"maximum"`
	Method  string   `json:"method"`
}

type ProfileReport struct {
	Name                          string         `json:"name"`
	WallDurationMS                float64        `json:"wall_duration_ms"`
	AttemptedOperations           int            `json:"attempted_operations"`
	CompletedOperations           int            `json:"completed_operations"`
	FailedOperations              int            `json:"failed_operations"`
	ServiceRequests               int            `json:"service_requests"`
	ProtectedUpstreamRequests     int            `json:"protected_upstream_requests"`
	ThroughputOperationsPerSecond float64        `json:"throughput_operations_per_second"`
	StopReason                    string         `json:"stop_reason"`
	LatencyMS                     Latency        `json:"latency_ms"`
	Failures                      FailureCounts  `json:"failures"`
	BoundaryViolations            BoundaryCounts `json:"boundary_violations"`
	Result                        string         `json:"result"`
}

type Report struct {
	SchemaVersion            string          `json:"schema_version"`
	SyntheticOnly            bool            `json:"synthetic_only"`
	RawDeploymentRecordsUsed bool            `json:"raw_deployment_records_used"`
	NetworkScope             string          `json:"network_scope"`
	Configured               Config          `json:"configured"`
	Profiles                 []ProfileReport `json:"profiles"`
	Limitations              []string        `json:"limitations"`
	Result                   string          `json:"result"`
}

func NormalizeConfig(config Config) (Config, error) {
	if config.DurationSeconds == 0 {
		config.DurationSeconds = 5
	}
	if config.Concurrency == 0 {
		config.Concurrency = 4
	}
	if config.MaxOperations == 0 {
		config.MaxOperations = MaximumOperations
	}
	if config.DurationSeconds < MinimumDuration || config.DurationSeconds > MaximumDuration ||
		config.Concurrency < MinimumConcurrency || config.Concurrency > MaximumConcurrency ||
		config.MaxOperations < MinimumOperations || config.MaxOperations > MaximumOperations {
		return Config{}, ErrInvalidConfig
	}
	return config, nil
}

func ExecutionPlan(config Config) (Plan, error) {
	config, err := NormalizeConfig(config)
	if err != nil {
		return Plan{}, err
	}
	return Plan{
		SchemaVersion: PlanSchemaVersion, SyntheticOnly: true, RawDeploymentRecordsUsed: false,
		NetworkScope: "loopback_only", Profiles: slices.Clone(profileOrder), Configured: config,
		MaxResponseBytes: MaximumResponseSize, RequestTimeoutSeconds: RequestTimeoutSec,
		Limitations: slices.Clone(limitations),
	}, nil
}

func ValidateReport(report Report) error {
	config, err := NormalizeConfig(report.Configured)
	if err != nil || config != report.Configured || report.SchemaVersion != ReportSchemaVersion || !report.SyntheticOnly ||
		report.RawDeploymentRecordsUsed || report.NetworkScope != "loopback_only" || !slices.Equal(report.Limitations, limitations) ||
		len(report.Profiles) != len(profileOrder) {
		return ErrBoundary
	}
	overall := "passed"
	for index, profile := range report.Profiles {
		if profile.Name != profileOrder[index] || profile.AttemptedOperations != profile.CompletedOperations+profile.FailedOperations ||
			profile.Failures.Total() != profile.FailedOperations || profile.LatencyMS.Samples != profile.CompletedOperations ||
			profile.AttemptedOperations < 0 || profile.AttemptedOperations > config.MaxOperations || profile.CompletedOperations < 0 ||
			profile.FailedOperations < 0 || profile.ServiceRequests < 0 || profile.ProtectedUpstreamRequests < 0 ||
			profile.ProtectedUpstreamRequests > profile.AttemptedOperations || !validFailures(profile.Failures) || !validBoundaries(profile.BoundaryViolations) ||
			profile.WallDurationMS < 0 || profile.WallDurationMS > float64((config.DurationSeconds+RequestTimeoutSec+1)*1000) || !finite(profile.WallDurationMS) || profile.ThroughputOperationsPerSecond < 0 ||
			!finite(profile.ThroughputOperationsPerSecond) || (profile.StopReason != "duration" && profile.StopReason != "max_operations") ||
			(profile.StopReason == "max_operations" && profile.AttemptedOperations != config.MaxOperations) ||
			(profile.Result != "passed" && profile.Result != "failed") || !validLatency(profile.LatencyMS) ||
			(profile.CompletedOperations == 0 && profile.ThroughputOperationsPerSecond != 0) ||
			(profile.CompletedOperations > 0 && (profile.WallDurationMS == 0 || profile.ThroughputOperationsPerSecond == 0)) {
			return ErrBoundary
		}
		expected := "passed"
		if profile.FailedOperations > 0 || profile.BoundaryViolations.Total() > 0 {
			expected = "failed"
			overall = "failed"
		}
		if profile.Result != expected {
			return ErrBoundary
		}
	}
	if report.Result != overall {
		return ErrBoundary
	}
	return nil
}

func validFailures(counts FailureCounts) bool {
	return counts.Client >= 0 && counts.ResponseTooLarge >= 0 && counts.AdapterResponse >= 0
}

func validBoundaries(counts BoundaryCounts) bool {
	return counts.Protocol >= 0 && counts.Privacy >= 0 && counts.Service >= 0 && counts.Upstream >= 0
}

func validLatency(latency Latency) bool {
	if latency.Method != "nearest_rank_successes" {
		return false
	}
	values := []*float64{latency.P50, latency.P95, latency.P99, latency.Maximum}
	if latency.Samples == 0 {
		return latency.P50 == nil && latency.P95 == nil && latency.P99 == nil && latency.Maximum == nil
	}
	for _, value := range values {
		if value == nil || *value < 0 || !finite(*value) {
			return false
		}
	}
	return *latency.P50 <= *latency.P95 && *latency.P95 <= *latency.P99 && *latency.P99 <= *latency.Maximum
}

func finite(value float64) bool { return !math.IsNaN(value) && !math.IsInf(value, 0) }

func TestNormalizeConfigBounds(t *testing.T) {
	defaults, err := NormalizeConfig(Config{})
	if err != nil || defaults != (Config{DurationSeconds: 5, Concurrency: 4, MaxOperations: MaximumOperations}) {
		t.Fatalf("defaults = %+v, %v", defaults, err)
	}
	for _, config := range []Config{
		{DurationSeconds: -1, Concurrency: 1, MaxOperations: 1},
		{DurationSeconds: MaximumDuration + 1, Concurrency: 1, MaxOperations: 1},
		{DurationSeconds: 1, Concurrency: -1, MaxOperations: 1},
		{DurationSeconds: 1, Concurrency: MaximumConcurrency + 1, MaxOperations: 1},
		{DurationSeconds: 1, Concurrency: 1, MaxOperations: -1},
		{DurationSeconds: 1, Concurrency: 1, MaxOperations: MaximumOperations + 1},
	} {
		if _, err := NormalizeConfig(config); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("NormalizeConfig(%+v) error = %v", config, err)
		}
	}
}

func TestExecutionPlanIsClosedAndDefensivelyCopied(t *testing.T) {
	first, err := ExecutionPlan(Config{DurationSeconds: 1, Concurrency: 2, MaxOperations: 3})
	if err != nil {
		t.Fatal(err)
	}
	first.Profiles[0] = "poisoned"
	first.Limitations[0] = "poisoned"
	second, err := ExecutionPlan(first.Configured)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(second)
	if err != nil {
		t.Fatal(err)
	}
	if second.SchemaVersion != PlanSchemaVersion || !second.SyntheticOnly || second.RawDeploymentRecordsUsed || second.NetworkScope != "loopback_only" ||
		!slices.Equal(second.Profiles, profileOrder) || !slices.Equal(second.Limitations, limitations) || strings.Contains(string(encoded), "poisoned") {
		t.Fatalf("unexpected plan: %s", encoded)
	}
}

func TestValidateReportRejectsPoisoning(t *testing.T) {
	base := validSyntheticReport()
	if err := ValidateReport(base); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		poison func(*Report)
	}{
		{"raw_records", func(report *Report) { report.RawDeploymentRecordsUsed = true }},
		{"profile_order", func(report *Report) { report.Profiles[0].Name = ProfileReverseProxy }},
		{"attempt_over_budget", func(report *Report) {
			report.Profiles[0].AttemptedOperations = 11
			report.Profiles[0].CompletedOperations = 11
			report.Profiles[0].LatencyMS.Samples = 11
		}},
		{"negative_failure", func(report *Report) {
			report.Profiles[0].Failures.Client = -1
			report.Profiles[0].Failures.AdapterResponse = 1
		}},
		{"negative_boundary", func(report *Report) {
			report.Profiles[0].BoundaryViolations.Privacy = -1
			report.Profiles[0].BoundaryViolations.Service = 1
		}},
		{"counter_conflict", func(report *Report) { report.Profiles[0].FailedOperations = 1 }},
		{"latency_order", func(report *Report) { *report.Profiles[0].LatencyMS.P50 = 9; *report.Profiles[0].LatencyMS.P95 = 8 }},
		{"nan", func(report *Report) { report.Profiles[0].WallDurationMS = math.NaN() }},
		{"false_pass", func(report *Report) { report.Profiles[0].BoundaryViolations.Privacy = 1 }},
		{"false_failure", func(report *Report) { report.Profiles[0].Result = "failed"; report.Result = "failed" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			report := validSyntheticReport()
			test.poison(&report)
			if !errors.Is(ValidateReport(report), ErrBoundary) {
				t.Fatalf("poisoned report accepted: %+v", report)
			}
		})
	}
}

func validSyntheticReport() Report {
	profile := func(name string) ProfileReport {
		return ProfileReport{
			Name: name, WallDurationMS: 10, AttemptedOperations: 10, CompletedOperations: 10,
			ServiceRequests: 21, ProtectedUpstreamRequests: 10, ThroughputOperationsPerSecond: 1_000,
			StopReason: "max_operations", LatencyMS: Latency{Samples: 10, P50: float64Pointer(1), P95: float64Pointer(1), P99: float64Pointer(1), Maximum: float64Pointer(1), Method: "nearest_rank_successes"},
			Result: "passed",
		}
	}
	return Report{
		SchemaVersion: ReportSchemaVersion, SyntheticOnly: true, NetworkScope: "loopback_only",
		Configured:  Config{DurationSeconds: 1, Concurrency: 2, MaxOperations: 10},
		Profiles:    []ProfileReport{profile(ProfileOriginMiddleware), profile(ProfileReverseProxy)},
		Limitations: slices.Clone(limitations), Result: "passed",
	}
}

func float64Pointer(value float64) *float64 { return &value }
