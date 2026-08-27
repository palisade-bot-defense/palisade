package offlineimport

import (
	"errors"
	"io"
)

var (
	ErrDecompressedBudget = errors.New("offline import decompressed-byte budget exceeded")
	ErrRecordBudget       = errors.New("offline import input-record budget exceeded")
	ErrEventBudget        = errors.New("offline import event budget exceeded")
	ErrShardBudget        = errors.New("offline import shard budget exceeded")
	ErrOutputBudget       = errors.New("offline import output-byte budget exceeded")
	ErrWorkingBudget      = errors.New("offline import working-byte budget exceeded")
	ErrInputChanged       = errors.New("offline import input changed during processing")
	ErrCleanup            = errors.New("offline import cleanup failed")
	ErrEventOrder         = errors.New("offline import event order is decreasing")
)

type budgets struct {
	maxDecompressed int64
	maxRecords      uint64
	maxEvents       uint64
	maxShards       int
	maxOutput       int64
	maxWorking      int64
	decompressed    int64
	records         uint64
	events          uint64
	shards          int
	output          int64
	working         int64
}

func newBudgets(config Config) *budgets {
	return &budgets{
		maxDecompressed: config.MaxDecompressedBytes,
		maxRecords:      config.MaxInputRecords,
		maxEvents:       config.MaxEvents,
		maxShards:       config.MaxShards,
		maxOutput:       config.MaxOutputBytes,
		maxWorking:      config.MaxWorkingBytes,
	}
}

func (b *budgets) addRecord() error {
	if b.records >= b.maxRecords {
		return ErrRecordBudget
	}
	b.records++
	return nil
}

func (b *budgets) addEvent() error {
	if b.events >= b.maxEvents {
		return ErrEventBudget
	}
	b.events++
	return nil
}

func (b *budgets) addShard() error {
	if b.shards >= b.maxShards {
		return ErrShardBudget
	}
	b.shards++
	return nil
}

func (b *budgets) addOutput(n int64) error {
	if n < 0 || b.output > b.maxOutput-n {
		return ErrOutputBudget
	}
	b.output += n
	return nil
}

func (b *budgets) addWorking(n int64) error {
	if n < 0 || b.working > b.maxWorking-n {
		return ErrWorkingBudget
	}
	b.working += n
	return nil
}

func (b *budgets) releaseWorking(n int64) {
	b.working -= n
	if b.working < 0 {
		b.working = 0
	}
}

type budgetReader struct {
	reader io.Reader
	budget *budgets
}

func (r *budgetReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	remaining := r.budget.maxDecompressed - r.budget.decompressed
	if remaining <= 0 {
		var probe [1]byte
		n, err := r.reader.Read(probe[:])
		if n > 0 {
			p[0] = probe[0]
			return n, ErrDecompressedBudget
		}
		return 0, err
	}
	if int64(len(p)) > remaining {
		p = p[:remaining]
	}
	n, err := r.reader.Read(p)
	r.budget.decompressed += int64(n)
	if r.budget.decompressed > r.budget.maxDecompressed {
		return n, ErrDecompressedBudget
	}
	return n, err
}
