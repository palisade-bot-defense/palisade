package offlineimport

import (
	"errors"
	"io"
)

var (
	ErrInputByteBudget = errors.New("local evidence import input-byte budget exceeded")
	ErrRecordBudget    = errors.New("local evidence import input-record budget exceeded")
	ErrEventBudget     = errors.New("local evidence import event budget exceeded")
	ErrShardBudget     = errors.New("local evidence import shard budget exceeded")
	ErrOutputBudget    = errors.New("local evidence import output-byte budget exceeded")
	ErrInputChanged    = errors.New("local evidence import input changed during processing")
	ErrCleanup         = errors.New("local evidence import cleanup failed")
)

type budgets struct {
	maxInputBytes int64
	maxRecords    uint64
	maxEvents     uint64
	maxShards     int
	maxOutput     int64
	inputBytes    int64
	records       uint64
	events        uint64
	shards        int
	output        int64
}

func newBudgets(config budgetLimits) *budgets {
	return &budgets{
		maxInputBytes: config.MaxInputBytes,
		maxRecords:    config.MaxInputRecords,
		maxEvents:     config.MaxEvents,
		maxShards:     config.MaxShards,
		maxOutput:     config.MaxOutputBytes,
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

type budgetReader struct {
	reader io.Reader
	budget *budgets
}

func (r *budgetReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	remaining := r.budget.maxInputBytes - r.budget.inputBytes
	if remaining <= 0 {
		var probe [1]byte
		n, err := r.reader.Read(probe[:])
		if n > 0 {
			p[0] = probe[0]
			return n, ErrInputByteBudget
		}
		return 0, err
	}
	if int64(len(p)) > remaining {
		p = p[:remaining]
	}
	n, err := r.reader.Read(p)
	r.budget.inputBytes += int64(n)
	if r.budget.inputBytes > r.budget.maxInputBytes {
		return n, ErrInputByteBudget
	}
	return n, err
}
