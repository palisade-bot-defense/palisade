package offlineimport

const (
	DefaultShardSize   = 10_000
	MinimumShardSize   = 100
	MaximumShardSize   = 100_000
	DefaultMaxLineSize = 1 << 20
	MinimumMaxLineSize = 4 << 10
	MaximumMaxLineSize = 8 << 20

	DefaultMaxInputBytes   int64  = 128 << 30
	DefaultMaxInputRecords uint64 = 50_000_000
	DefaultMaxEvents       uint64 = 50_000_000
	DefaultMaxShards              = 10_000
	MaximumShardCount             = 999_999
	DefaultMaxOutputBytes  int64  = 64 << 30
)

type budgetLimits struct {
	MaxInputBytes   int64
	MaxInputRecords uint64
	MaxEvents       uint64
	MaxShards       int
	MaxOutputBytes  int64
}

type InputStats struct {
	Filename        string `json:"filename"`
	SizeBytes       int64  `json:"size_bytes"`
	SHA256          string `json:"sha256"`
	openedModTimeNS int64
}

type ShardStats struct {
	Filename  string `json:"filename"`
	Records   uint64 `json:"records"`
	SizeBytes int64  `json:"size_bytes"`
	SHA256    string `json:"sha256"`
}
