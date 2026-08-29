package offlineimport

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type localShardWriter struct {
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

func newLocalShardWriter(dir string, limit int, budget *budgets) *localShardWriter {
	return &localShardWriter{dir: dir, limit: limit, budget: budget, shards: make([]ShardStats, 0)}
}

func (writer *localShardWriter) Write(event LocalEvent) error {
	if err := validateLocalOutputEvent(event); err != nil {
		return err
	}
	observedAt, _ := time.Parse(time.RFC3339Nano, event.ObservedAt)
	if writer.hasLastObservedAt && observedAt.Before(writer.lastObservedAt) {
		return ErrLocalEventOrder
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
		return errors.New("encode local evidence event")
	}
	if err := writer.budget.addOutput(int64(len(encoded) + 1)); err != nil {
		return err
	}
	if _, err := writer.buffer.Write(encoded); err != nil {
		return errors.New("write local evidence shard")
	}
	if err := writer.buffer.WriteByte('\n'); err != nil {
		return errors.New("write local evidence shard")
	}
	writer.count++
	writer.total++
	if writer.count == writer.limit {
		return writer.finishCurrent()
	}
	return nil
}

func (writer *localShardWriter) Finish() error { return writer.finishCurrent() }

func (writer *localShardWriter) Abort() error {
	var result error
	if writer.file != nil {
		if err := writer.file.Close(); err != nil {
			result = errors.Join(result, fmt.Errorf("%w: close local evidence shard", ErrCleanup))
		}
		writer.file = nil
	}
	if writer.tempPath != "" {
		if err := os.Remove(writer.tempPath); err != nil && !os.IsNotExist(err) {
			result = errors.Join(result, fmt.Errorf("%w: remove local evidence shard", ErrCleanup))
		}
	}
	return result
}

func (writer *localShardWriter) open() error {
	if err := writer.budget.addShard(); err != nil {
		return err
	}
	writer.index++
	writer.finalName = fmt.Sprintf("evidence-%06d.jsonl", writer.index)
	writer.tempPath = filepath.Join(writer.dir, "."+writer.finalName+".tmp")
	file, err := os.OpenFile(writer.tempPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return errors.New("create local evidence shard")
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		_ = os.Remove(writer.tempPath)
		return errors.New("secure local evidence shard")
	}
	writer.file = file
	writer.buffer = bufio.NewWriterSize(file, 64<<10)
	return nil
}

func (writer *localShardWriter) finishCurrent() error {
	if writer.file == nil {
		return nil
	}
	if err := writer.buffer.Flush(); err != nil {
		return errors.Join(errors.New("flush local evidence shard"), writer.Abort())
	}
	if err := writer.file.Sync(); err != nil {
		return errors.Join(errors.New("sync local evidence shard"), writer.Abort())
	}
	if err := writer.file.Close(); err != nil {
		writer.file = nil
		_ = os.Remove(writer.tempPath)
		return errors.New("close local evidence shard")
	}
	writer.file = nil
	finalPath := filepath.Join(writer.dir, writer.finalName)
	if err := os.Rename(writer.tempPath, finalPath); err != nil {
		_ = os.Remove(writer.tempPath)
		return errors.New("publish local evidence shard")
	}
	info, digest, err := fileDigest(finalPath)
	if err != nil {
		return errors.New("fingerprint local evidence shard")
	}
	writer.shards = append(writer.shards, ShardStats{Filename: writer.finalName, Records: uint64(writer.count), SizeBytes: info.Size(), SHA256: digest})
	writer.buffer = nil
	writer.tempPath = ""
	writer.finalName = ""
	writer.count = 0
	return nil
}

func validateLocalOutputEvent(event LocalEvent) error {
	if event.SchemaVersion != LocalEventSchemaVersion || event.Provenance != ProvenanceOperatorExport || !validPseudonym(event.SubjectID) || (event.SessionID != "" && !validPseudonym(event.SessionID)) {
		return errors.New("local evidence output violates its closed identity contract")
	}
	input := LocalInputEvent{
		SchemaVersion: LocalInputSchemaVersion,
		ObservedAt:    event.ObservedAt,
		SubjectRef:    event.SubjectID,
		SessionRef:    event.SessionID,
		Source:        event.Source,
		EndpointClass: event.EndpointClass,
		ActionClass:   event.ActionClass,
		StatusClass:   event.StatusClass,
		Evidence:      event.Evidence,
		Label:         event.Label,
	}
	_, err := validateLocalInputEvent(input)
	return err
}

func writeLocalJSON(path string, value any, budget *budgets) error {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return errors.New("encode local evidence manifest")
	}
	encoded = append(encoded, '\n')
	if err := budget.addOutput(int64(len(encoded))); err != nil {
		return err
	}
	return writePrivateFile(path, encoded, "local evidence manifest")
}

func writeLocalCompletion(path string, budget *budgets) error {
	content := []byte(LocalManifestSchemaVersion + "\n")
	if err := budget.addOutput(int64(len(content))); err != nil {
		return err
	}
	return writePrivateFile(path, content, "local evidence completion marker")
}

func writePrivateFile(path string, content []byte, description string) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create %s", description)
	}
	if err := file.Chmod(0o600); err != nil {
		return errors.Join(fmt.Errorf("secure %s", description), closeAndRemove(file, path))
	}
	if _, err := file.Write(content); err != nil {
		return errors.Join(fmt.Errorf("write %s", description), closeAndRemove(file, path))
	}
	if err := file.Sync(); err != nil {
		return errors.Join(fmt.Errorf("sync %s", description), closeAndRemove(file, path))
	}
	if err := file.Close(); err != nil {
		return errors.Join(fmt.Errorf("close %s", description), removeFile(path))
	}
	return nil
}
