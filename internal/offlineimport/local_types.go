package offlineimport

const (
	LocalInputSchemaVersion    = "palisade.local-evidence-input.v1"
	LocalEventSchemaVersion    = "palisade.local-evidence-event.v1"
	LocalManifestSchemaVersion = "palisade.local-evidence-manifest.v1"
	LocalImporterVersion       = "local-evidence-importer-v1"
	ProvenanceOperatorExport   = "operator_authorized_export"

	DefaultLocalScanMaxShards = 10_000
	DefaultLocalScanMaxEvents = 50_000_000
	DefaultLocalScanMaxBytes  = int64(64 << 30)
	MaximumLocalScanEvents    = 100_000_000
	MaximumLocalScanBytes     = int64(1 << 40)
)

// LocalConfig describes a local-only import of an operator-normalized JSONL
// export. The input may contain direct subject references. Those references
// are used only while deriving daily, domain-separated pseudonyms and are never
// copied to output artifacts.
type LocalConfig struct {
	InputFile        string
	OutputDir        string
	PseudonymKeyFile string
	DatasetID        string
	PilotID          string
	Provenance       string
	ShardSize        int
	MaxLineBytes     int
	MaxInputBytes    int64
	MaxInputRecords  uint64
	MaxEvents        uint64
	MaxShards        int
	MaxOutputBytes   int64
}

type LocalResult struct {
	ManifestPath string
	Events       uint64
}

type LocalInputEvent struct {
	SchemaVersion string        `json:"schema_version"`
	ObservedAt    string        `json:"observed_at"`
	SubjectRef    string        `json:"subject_ref"`
	SessionRef    string        `json:"session_ref,omitempty"`
	Source        string        `json:"source"`
	EndpointClass string        `json:"endpoint_class"`
	ActionClass   string        `json:"action_class"`
	StatusClass   string        `json:"status_class"`
	Evidence      LocalEvidence `json:"evidence"`
	Label         LocalLabel    `json:"label"`
}

type LocalEvidence struct {
	CollectionStatus    string `json:"collection_status"`
	AutomationEvidence  string `json:"automation_evidence"`
	AbuseIntentEvidence string `json:"abuse_intent_evidence"`
	ContinuityEvidence  string `json:"continuity_evidence"`
	DecoyInteraction    string `json:"decoy_interaction"`
	ChallengeLifecycle  string `json:"challenge_lifecycle"`
}

type LocalLabel struct {
	Class      string `json:"class"`
	Provenance string `json:"provenance"`
	Confidence string `json:"confidence"`
}

type LocalEvent struct {
	SchemaVersion string        `json:"schema_version"`
	Provenance    string        `json:"provenance"`
	ObservedAt    string        `json:"observed_at"`
	SubjectID     string        `json:"subject_id"`
	SessionID     string        `json:"session_id,omitempty"`
	Source        string        `json:"source"`
	EndpointClass string        `json:"endpoint_class"`
	ActionClass   string        `json:"action_class"`
	StatusClass   string        `json:"status_class"`
	Evidence      LocalEvidence `json:"evidence"`
	Label         LocalLabel    `json:"label"`
}

type LocalManifest struct {
	SchemaVersion string              `json:"schema_version"`
	Importer      string              `json:"importer_version"`
	Provenance    string              `json:"provenance"`
	Config        LocalManifestConfig `json:"config"`
	Input         LocalInputStats     `json:"input"`
	Shards        []ShardStats        `json:"shards"`
	Totals        LocalTotals         `json:"totals"`
	Warnings      []string            `json:"warnings"`
}

type LocalManifestConfig struct {
	ShardSize             int    `json:"shard_size"`
	MaxLineBytes          int    `json:"max_line_bytes"`
	MaxInputBytes         int64  `json:"max_input_bytes"`
	MaxInputRecords       uint64 `json:"max_input_records"`
	MaxEvents             uint64 `json:"max_events"`
	MaxShards             int    `json:"max_shards"`
	MaxOutputBytes        int64  `json:"max_output_bytes"`
	Pseudonymization      string `json:"pseudonymization"`
	DomainID              string `json:"domain_id"`
	ChronologicalRequired bool   `json:"chronological_input_required"`
}

type LocalInputStats struct {
	LogicalName     string `json:"logical_name"`
	SizeBytes       int64  `json:"size_bytes"`
	SHA256          string `json:"sha256"`
	Records         uint64 `json:"records"`
	FirstObservedAt string `json:"first_observed_at,omitempty"`
	LastObservedAt  string `json:"last_observed_at,omitempty"`
}

type LocalTotals struct {
	Records uint64 `json:"records"`
	Events  uint64 `json:"events"`
}

type LocalScanLimits struct {
	MaxShards int
	MaxEvents uint64
	MaxBytes  int64
}

type LocalVerification struct {
	Shards  uint64 `json:"shards"`
	Events  uint64 `json:"events"`
	Bytes   int64  `json:"bytes"`
	FirstAt string `json:"first_at,omitempty"`
	LastAt  string `json:"last_at,omitempty"`
}
