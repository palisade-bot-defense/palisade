package offlineimport

const (
	EventSchemaVersion    = "palisade.offline-event.v1"
	ManifestSchemaVersion = "palisade.offline-manifest.v1"
	ImporterVersion       = "offline-importer-v3"
	ProvenanceOffline     = "offline_export"
	AnubisPeerDirect      = "direct_peer_only"
	AnubisPeerTrustedReal = "trusted_x_real_ip"

	DefaultShardSize   = 10_000
	MinimumShardSize   = 100
	MaximumShardSize   = 100_000
	DefaultMaxLineSize = 1 << 20
	MinimumMaxLineSize = 4 << 10
	MaximumMaxLineSize = 8 << 20

	DefaultSortChunkSize               = 50_000
	MinimumSortChunkSize               = 2
	MaximumSortChunkSize               = 250_000
	DefaultMaxDecompressedBytes int64  = 128 << 30
	DefaultMaxInputRecords      uint64 = 50_000_000
	DefaultMaxEvents            uint64 = 50_000_000
	DefaultMaxShards                   = 10_000
	MaximumShardCount                  = 999_999
	MaximumSortRuns                    = 4_096
	DefaultMaxOutputBytes       int64  = 64 << 30
	DefaultMaxWorkingBytes      int64  = 256 << 30
)

type Config struct {
	InputDir             string
	OutputDir            string
	PseudonymKeyFile     string
	DatasetID            string
	PilotID              string
	Provenance           string
	AnubisPeerSource     string
	ShardSize            int
	MaxLineBytes         int
	SortChunkSize        int
	MaxDecompressedBytes int64
	MaxInputRecords      uint64
	MaxEvents            uint64
	MaxShards            int
	MaxOutputBytes       int64
	MaxWorkingBytes      int64
}

type Result struct {
	ManifestPath string
	Events       uint64
	Invalid      uint64
	Skipped      uint64
}

type Event struct {
	SchemaVersion   string   `json:"schema_version"`
	Provenance      string   `json:"provenance"`
	Source          string   `json:"source"`
	ObservedAt      string   `json:"observed_at"`
	SubjectID       string   `json:"subject_id"`
	SessionID       string   `json:"session_id,omitempty"`
	EndpointClass   string   `json:"endpoint_class"`
	ActionClass     string   `json:"action_class"`
	StatusClass     string   `json:"status_class"`
	SourceVerdict   string   `json:"source_verdict"`
	ReasonCategory  string   `json:"reason_category"`
	LabelClass      string   `json:"label_class"`
	LabelProvenance string   `json:"label_provenance"`
	LabelTrust      string   `json:"label_trust"`
	Features        Features `json:"features"`
}

type Features struct {
	UAPresent        bool `json:"ua_present"`
	ChallengePresent bool `json:"challenge_present"`
	SizeBucket       int  `json:"size_bucket"`
	WeightBucket     int  `json:"weight_bucket"`
}

type Manifest struct {
	SchemaVersion string         `json:"schema_version"`
	Importer      string         `json:"importer_version"`
	Provenance    string         `json:"provenance"`
	Config        ManifestConfig `json:"config"`
	Inputs        []InputStats   `json:"inputs"`
	Shards        []ShardStats   `json:"shards"`
	Totals        Totals         `json:"totals"`
	Warnings      []string       `json:"warnings"`
}

type ManifestConfig struct {
	ShardSize            int    `json:"shard_size"`
	MaxLineBytes         int    `json:"max_line_bytes"`
	Classifier           string `json:"classifier_version"`
	Pseudonymization     string `json:"pseudonymization"`
	DomainID             string `json:"domain_id"`
	AnubisPeerSource     string `json:"anubis_peer_source"`
	SortChunkSize        int    `json:"sort_chunk_size"`
	MaxDecompressedBytes int64  `json:"max_decompressed_bytes"`
	MaxInputRecords      uint64 `json:"max_input_records"`
	MaxEvents            uint64 `json:"max_events"`
	MaxShards            int    `json:"max_shards"`
	MaxOutputBytes       int64  `json:"max_output_bytes"`
	MaxWorkingBytes      int64  `json:"max_working_bytes"`
}

type InputStats struct {
	Filename        string `json:"filename"`
	SizeBytes       int64  `json:"size_bytes"`
	SHA256          string `json:"sha256"`
	Records         uint64 `json:"records"`
	Invalid         uint64 `json:"invalid"`
	Skipped         uint64 `json:"skipped"`
	FirstObservedAt string `json:"first_observed_at,omitempty"`
	LastObservedAt  string `json:"last_observed_at,omitempty"`
	openedModTimeNS int64
}

type ShardStats struct {
	Filename  string `json:"filename"`
	Records   uint64 `json:"records"`
	SizeBytes int64  `json:"size_bytes"`
	SHA256    string `json:"sha256"`
}

type Totals struct {
	Records uint64 `json:"records"`
	Invalid uint64 `json:"invalid"`
	Skipped uint64 `json:"skipped"`
	Events  uint64 `json:"events"`
}

var expectedInputs = []string{
	"access.log.gz",
	"anubis-strain.jsonl.gz",
	"crowdsec-alerts.json",
	"crowdsec-decisions.json",
	"error.log.gz",
}
