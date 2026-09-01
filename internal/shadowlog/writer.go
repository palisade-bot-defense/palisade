package shadowlog

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"
	"time"

	"github.com/palisade-human-trust/palisade/internal/core"
)

var (
	fileMagic      = [8]byte{'P', 'L', 'S', 'H', 'D', 'W', '1', '\n'}
	managedLogName = regexp.MustCompile(`^shadow-[0-9]{8}T[0-9]{6}Z-[a-f0-9]{16}\.plog$`)
)

const headerSize = 24

type Sink struct {
	config   Config
	aead     cipher.AEAD
	indexKey []byte
	keyID    [8]byte
	records  chan Record
	done     chan struct{}

	mu       sync.Mutex
	closed   bool
	writeErr error
}

type activeFile struct {
	file      *os.File
	createdAt time.Time
	size      int64
	prefix    [8]byte
	counter   uint32
}

func New(config Config) (*Sink, error) {
	config, err := normalizeConfig(config)
	if err != nil {
		return nil, err
	}
	directory, err := prepareDirectory(config.Directory)
	if err != nil {
		return nil, err
	}
	keyPath, master, err := readKey(config.KeyFile)
	if err != nil {
		return nil, err
	}
	defer wipe(master)
	if insideWorktree(keyPath) {
		return nil, errors.New("shadow log key must be outside every Git worktree")
	}
	config.Directory = directory
	config.KeyFile = keyPath
	encryptionKey := deriveKey(master, "palisade:shadow-log:v1:encryption")
	defer wipe(encryptionKey)
	indexKey := deriveKey(master, "palisade:shadow-log:v1:session-index")
	aead, err := newAEAD(encryptionKey)
	if err != nil {
		wipe(indexKey)
		return nil, err
	}
	sink := &Sink{
		config: config, aead: aead, indexKey: indexKey,
		keyID: keyIdentifier(encryptionKey), records: make(chan Record, config.QueueSize), done: make(chan struct{}),
	}
	if err := cleanupExpired(config.Directory, config.Now().UTC(), config.Retention); err != nil {
		wipe(indexKey)
		return nil, err
	}
	if err := ensureDirectoryKey(config.Directory, sink.keyID); err != nil {
		wipe(indexKey)
		return nil, err
	}
	go sink.run()
	return sink, nil
}

func (s *Sink) RecordDecision(request core.DecisionRequest, decision core.Decision, now time.Time) error {
	if !validSessionID(request.SessionID) {
		return errors.New("invalid shadow decision session")
	}
	linkedSession, err := s.makeSessionKey(request.SessionID)
	if err != nil {
		return err
	}
	reasons := make([]string, 0, len(decision.ReasonCodes))
	evaluationCohort, valid := core.NormalizeEvaluationCohort(request.EvaluationCohort)
	if !valid {
		return errors.New("invalid shadow decision evaluation cohort")
	}
	for _, reason := range decision.ReasonCodes {
		if len(reasons) == 32 {
			break
		}
		if stableValue.MatchString(reason) {
			reasons = append(reasons, reason)
		}
	}
	record := Record{
		SchemaVersion: SchemaVersion,
		Kind:          "decision",
		RecordedAt:    now.UTC().Truncate(time.Second).Format(time.RFC3339),
		SessionKey:    linkedSession,
		Decision: &DecisionEntry{
			DecisionID: sanitizeStable(decision.DecisionID), RequestAction: normalizeRequestAction(request.Action), EndpointClass: normalizeEndpoint(request.EndpointClass), EvaluationCohort: evaluationCohort,
			Action: decision.Action, ComputedAction: decision.ComputedAction, Mode: decision.Mode, RolloutID: sanitizeOptionalStable(decision.RolloutID), Scores: decision.Scores,
			ReasonCodes: reasons, PolicyVersion: sanitizeStable(decision.PolicyVersion), ModelVersion: sanitizeStable(decision.ModelVersion),
		},
	}
	return s.enqueue(record)
}

func (s *Sink) RecordOutcome(request OutcomeRequest, now time.Time) error {
	if err := request.Validate(); err != nil {
		return err
	}
	linkedSession, err := s.makeSessionKey(request.SessionID)
	if err != nil {
		return err
	}
	record := Record{
		SchemaVersion: SchemaVersion,
		Kind:          "outcome",
		RecordedAt:    now.UTC().Truncate(time.Second).Format(time.RFC3339),
		SessionKey:    linkedSession,
		Outcome: &OutcomeEntry{
			DecisionID: request.DecisionID, EndpointClass: normalizeEndpoint(request.EndpointClass), Outcome: request.Outcome,
			Provenance: request.Provenance, Confidence: request.Confidence,
		},
	}
	return s.enqueue(record)
}

func (s *Sink) makeSessionKey(sessionID string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return "", ErrClosed
	}
	return sessionKey(s.indexKey, sessionID), nil
}

func (s *Sink) enqueue(record Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	if s.writeErr != nil {
		return errors.Join(ErrWriterFailed, s.writeErr)
	}
	select {
	case s.records <- record:
		return nil
	default:
		return ErrQueueFull
	}
}

func (s *Sink) Close() error {
	s.mu.Lock()
	if !s.closed {
		s.closed = true
		close(s.records)
	}
	s.mu.Unlock()
	<-s.done
	s.mu.Lock()
	defer s.mu.Unlock()
	wipe(s.indexKey)
	return s.writeErr
}

func (s *Sink) run() {
	defer close(s.done)
	var current *activeFile
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	defer func() {
		if err := closeActive(current); err != nil {
			s.setWriteError(err)
		}
	}()
	for {
		select {
		case record, ok := <-s.records:
			if !ok {
				return
			}
			if s.currentError() != nil {
				continue
			}
			next, err := s.writeRecord(current, record)
			current = next
			if err != nil {
				s.setWriteError(err)
			}
		case <-ticker.C:
			if current != nil {
				if err := current.file.Sync(); err != nil {
					s.setWriteError(err)
				}
			}
		}
	}
}

func (s *Sink) writeRecord(current *activeFile, record Record) (*activeFile, error) {
	plaintext, err := json.Marshal(record)
	if err != nil {
		return current, err
	}
	now := s.config.Now().UTC()
	frameSize := int64(8 + len(plaintext) + s.aead.Overhead())
	if int64(headerSize)+frameSize > s.config.MaxFileBytes {
		return current, errors.New("shadow log record exceeds configured file size")
	}
	if current == nil || current.size+frameSize > s.config.MaxFileBytes || now.Sub(current.createdAt) >= s.config.MaxFileAge {
		if err := closeActive(current); err != nil {
			return nil, err
		}
		current, err = s.openFile(now)
		if err != nil {
			return nil, err
		}
		if err := cleanupExpired(s.config.Directory, now, s.config.Retention); err != nil {
			_ = closeActive(current)
			return nil, err
		}
	}
	if current.counter == ^uint32(0) {
		return current, errors.New("shadow log record counter exhausted")
	}
	current.counter++
	var counter [4]byte
	binary.BigEndian.PutUint32(counter[:], current.counter)
	nonce := make([]byte, s.aead.NonceSize())
	copy(nonce[:8], current.prefix[:])
	copy(nonce[8:], counter[:])
	aad := make([]byte, 0, len(fileMagic)+len(current.prefix)+len(counter))
	aad = append(aad, fileMagic[:]...)
	aad = append(aad, current.prefix[:]...)
	aad = append(aad, counter[:]...)
	ciphertext := s.aead.Seal(nil, nonce, plaintext, aad)
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(ciphertext)))
	frame := make([]byte, 0, 8+len(ciphertext))
	frame = append(frame, counter[:]...)
	frame = append(frame, length[:]...)
	frame = append(frame, ciphertext...)
	if err := writeAll(current.file, frame); err != nil {
		return current, err
	}
	current.size += int64(len(frame))
	return current, nil
}

func (s *Sink) openFile(now time.Time) (*activeFile, error) {
	var random [8]byte
	if _, err := rand.Read(random[:]); err != nil {
		return nil, err
	}
	name := fmt.Sprintf("shadow-%s-%s.plog", now.Format("20060102T150405Z"), hex.EncodeToString(random[:]))
	path := filepath.Join(s.config.Directory, name)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return nil, err
	}
	current := &activeFile{file: file, createdAt: now, size: headerSize}
	if _, err := rand.Read(current.prefix[:]); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return nil, err
	}
	header := make([]byte, 0, headerSize)
	header = append(header, fileMagic[:]...)
	header = append(header, s.keyID[:]...)
	header = append(header, current.prefix[:]...)
	if err := writeAll(file, header); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return nil, err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return nil, err
	}
	if err := syncDirectory(s.config.Directory); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		_ = syncDirectory(s.config.Directory)
		return nil, err
	}
	return current, nil
}

func (s *Sink) setWriteError(err error) {
	s.mu.Lock()
	if s.writeErr == nil {
		s.writeErr = err
	}
	s.mu.Unlock()
}

func (s *Sink) currentError() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.writeErr
}

func closeActive(current *activeFile) error {
	if current == nil || current.file == nil {
		return nil
	}
	err := current.file.Sync()
	err = errors.Join(err, current.file.Close())
	current.file = nil
	return err
}

func writeAll(writer io.Writer, value []byte) error {
	for len(value) > 0 {
		written, err := writer.Write(value)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		value = value[written:]
	}
	return nil
}

func sanitizeStable(value string) string {
	if stableValue.MatchString(value) {
		return value
	}
	return "unknown"
}

func sanitizeOptionalStable(value string) string {
	if value == "" {
		return ""
	}
	return sanitizeStable(value)
}

func normalizeConfig(config Config) (Config, error) {
	if config.Directory == "" || config.KeyFile == "" {
		return config, errors.New("shadow log directory and key file are required")
	}
	if config.MaxFileBytes == 0 {
		config.MaxFileBytes = DefaultMaxFileBytes
	}
	if config.MaxFileBytes < 4<<10 || config.MaxFileBytes > 1<<30 {
		return config, errors.New("shadow log max file bytes must be between 4 KiB and 1 GiB")
	}
	if config.MaxFileAge == 0 {
		config.MaxFileAge = DefaultMaxFileAge
	}
	if config.MaxFileAge < time.Minute || config.MaxFileAge > 24*time.Hour {
		return config, errors.New("shadow log max file age must be between one minute and one day")
	}
	if config.Retention == 0 {
		config.Retention = DefaultRetention
	}
	if config.Retention < config.MaxFileAge || config.Retention > 90*24*time.Hour {
		return config, errors.New("shadow log retention must cover max file age and be at most 90 days")
	}
	if config.QueueSize == 0 {
		config.QueueSize = DefaultQueueSize
	}
	if config.QueueSize < 1 || config.QueueSize > 1_000_000 {
		return config, errors.New("shadow log queue size must be between 1 and 1000000")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	return config, nil
}

func prepareDirectory(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	parent := filepath.Dir(absolute)
	resolvedParent, err := filepath.EvalSymlinks(parent)
	if err != nil {
		return "", errors.New("shadow log parent is unavailable")
	}
	parentInfo, err := os.Stat(resolvedParent)
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode().Perm()&0o077 != 0 {
		return "", errors.New("shadow log parent must be an owner-only directory")
	}
	resolved := filepath.Join(resolvedParent, filepath.Base(absolute))
	if insideWorktree(resolved) {
		return "", errors.New("shadow log directory must be outside every Git worktree")
	}
	info, err := os.Lstat(resolved)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(resolved, 0o700); err != nil {
			return "", err
		}
		if err := os.Chmod(resolved, 0o700); err != nil {
			_ = os.Remove(resolved)
			return "", err
		}
		if err := syncDirectory(resolved); err != nil {
			_ = os.Remove(resolved)
			return "", err
		}
		if err := syncDirectory(resolvedParent); err != nil {
			_ = os.Remove(resolved)
			return "", err
		}
		return resolved, nil
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return "", errors.New("shadow log directory must be a real owner-only directory")
	}
	return resolved, nil
}

func readKey(path string) (string, []byte, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", nil, err
	}
	info, err := os.Lstat(absolute)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 || info.Size() < 32 || info.Size() > 4096 {
		return "", nil, errors.New("shadow log key must be a 32-4096 byte owner-only regular file")
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", nil, errors.New("shadow log key is unavailable")
	}
	parentInfo, err := os.Stat(filepath.Dir(resolved))
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode().Perm()&0o077 != 0 {
		return "", nil, errors.New("shadow log key parent must be an owner-only directory")
	}
	file, err := os.Open(resolved)
	if err != nil {
		return "", nil, err
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil || !os.SameFile(info, openedInfo) || !openedInfo.Mode().IsRegular() || openedInfo.Mode().Perm()&0o077 != 0 || openedInfo.Size() < 32 || openedInfo.Size() > 4096 {
		return "", nil, errors.New("shadow log key changed while opening")
	}
	value, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil || len(value) < 32 || len(value) > 4096 {
		wipe(value)
		return "", nil, errors.New("shadow log key could not be read safely")
	}
	finalInfo, err := file.Stat()
	if err != nil || !os.SameFile(openedInfo, finalInfo) || finalInfo.Size() != openedInfo.Size() || finalInfo.Mode() != openedInfo.Mode() {
		wipe(value)
		return "", nil, errors.New("shadow log key changed while reading")
	}
	return resolved, value, nil
}

func insideWorktree(path string) bool {
	current := filepath.Clean(path)
	if info, err := os.Lstat(current); err == nil && !info.IsDir() {
		current = filepath.Dir(current)
	}
	for {
		if _, err := os.Lstat(filepath.Join(current, ".git")); err == nil {
			return true
		}
		parent := filepath.Dir(current)
		if parent == current {
			return false
		}
		current = parent
	}
}

func cleanupExpired(directory string, now time.Time, retention time.Duration) error {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return err
	}
	cutoff := now.Add(-retention)
	var candidates []string
	for _, entry := range entries {
		if !isManagedLogName(entry.Name()) {
			continue
		}
		path := filepath.Join(directory, entry.Name())
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("shadow log retention encountered a non-regular managed path")
		}
		if info.ModTime().Before(cutoff) {
			candidates = append(candidates, path)
		}
	}
	sort.Strings(candidates)
	for _, path := range candidates {
		if err := os.Remove(path); err != nil {
			return err
		}
	}
	if len(candidates) > 0 {
		return syncDirectory(directory)
	}
	return nil
}

func syncDirectory(directory string) error {
	directoryFile, err := os.Open(directory)
	if err != nil {
		return err
	}
	err = directoryFile.Sync()
	err = errors.Join(err, directoryFile.Close())
	return err
}

func ensureDirectoryKey(directory string, expectedKeyID [8]byte) error {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !isManagedLogName(entry.Name()) {
			continue
		}
		path := filepath.Join(directory, entry.Name())
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 {
			return errors.New("managed shadow log must be a 0600 regular file")
		}
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		header := make([]byte, headerSize)
		_, readErr := io.ReadFull(file, header)
		closeErr := file.Close()
		if readErr != nil || closeErr != nil {
			return errors.New("managed shadow log has a truncated header")
		}
		if string(header[:8]) != string(fileMagic[:]) || string(header[8:16]) != string(expectedKeyID[:]) {
			return errors.New("managed shadow log uses a different key or format")
		}
	}
	return nil
}

func isManagedLogName(name string) bool {
	if !managedLogName.MatchString(name) {
		return false
	}
	_, err := time.Parse("20060102T150405Z", name[7:23])
	return err == nil
}
