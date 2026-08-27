package offlineimport

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

type shardWriter struct {
	dir               string
	limit             int
	budget            *budgets
	index             int
	count             int
	total             uint64
	file              *os.File
	buffer            *bufio.Writer
	tempPath          string
	finalName         string
	shards            []ShardStats
	lastObservedAt    time.Time
	hasLastObservedAt bool
}

func newShardWriter(dir string, limit int, budget *budgets) *shardWriter {
	return &shardWriter{dir: dir, limit: limit, budget: budget, shards: make([]ShardStats, 0)}
}

func (writer *shardWriter) Write(event Event) error {
	if err := validateEvent(event); err != nil {
		return err
	}
	observedAt, _ := time.Parse(time.RFC3339Nano, event.ObservedAt)
	if writer.hasLastObservedAt && observedAt.Before(writer.lastObservedAt) {
		return ErrEventOrder
	}
	writer.lastObservedAt = observedAt
	writer.hasLastObservedAt = true
	if writer.file == nil {
		if err := writer.open(); err != nil {
			return err
		}
	}
	encoded, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("encode normalized event: %w", err)
	}
	if err := writer.budget.addOutput(int64(len(encoded) + 1)); err != nil {
		return err
	}
	if _, err := writer.buffer.Write(encoded); err != nil {
		return fmt.Errorf("write normalized shard: %w", err)
	}
	if err := writer.buffer.WriteByte('\n'); err != nil {
		return fmt.Errorf("write normalized shard: %w", err)
	}
	writer.count++
	writer.total++
	if writer.count == writer.limit {
		return writer.finishCurrent()
	}
	return nil
}

func (writer *shardWriter) Finish() error {
	return writer.finishCurrent()
}

func (writer *shardWriter) Abort() error {
	var result error
	if writer.file != nil {
		if err := writer.file.Close(); err != nil {
			result = errors.Join(result, fmt.Errorf("%w: close normalized shard", ErrCleanup))
		}
		writer.file = nil
	}
	if writer.tempPath != "" {
		if err := os.Remove(writer.tempPath); err != nil && !os.IsNotExist(err) {
			result = errors.Join(result, fmt.Errorf("%w: remove normalized shard", ErrCleanup))
		}
	}
	return result
}

func (writer *shardWriter) open() error {
	if err := writer.budget.addShard(); err != nil {
		return err
	}
	writer.index++
	writer.finalName = fmt.Sprintf("events-%06d.jsonl", writer.index)
	writer.tempPath = filepath.Join(writer.dir, "."+writer.finalName+".tmp")
	file, err := os.OpenFile(writer.tempPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create normalized shard: %w", err)
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		_ = os.Remove(writer.tempPath)
		return fmt.Errorf("secure normalized shard: %w", err)
	}
	writer.file = file
	writer.buffer = bufio.NewWriterSize(file, 64<<10)
	return nil
}

func (writer *shardWriter) finishCurrent() error {
	if writer.file == nil {
		return nil
	}
	if err := writer.buffer.Flush(); err != nil {
		return errors.Join(fmt.Errorf("flush normalized shard: %w", err), writer.Abort())
	}
	if err := writer.file.Sync(); err != nil {
		return errors.Join(fmt.Errorf("sync normalized shard: %w", err), writer.Abort())
	}
	if err := writer.file.Close(); err != nil {
		writer.file = nil
		_ = os.Remove(writer.tempPath)
		return fmt.Errorf("close normalized shard: %w", err)
	}
	writer.file = nil

	finalPath := filepath.Join(writer.dir, writer.finalName)
	if err := os.Rename(writer.tempPath, finalPath); err != nil {
		_ = os.Remove(writer.tempPath)
		return fmt.Errorf("publish normalized shard: %w", err)
	}
	info, digest, err := fileDigest(finalPath)
	if err != nil {
		return fmt.Errorf("fingerprint normalized shard: %w", err)
	}
	writer.shards = append(writer.shards, ShardStats{
		Filename:  writer.finalName,
		Records:   uint64(writer.count),
		SizeBytes: info.Size(),
		SHA256:    digest,
	})
	writer.buffer = nil
	writer.tempPath = ""
	writer.finalName = ""
	writer.count = 0
	return nil
}

func fileDigest(path string) (os.FileInfo, string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, "", err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, "", err
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return nil, "", err
	}
	return info, hex.EncodeToString(hash.Sum(nil)), nil
}
