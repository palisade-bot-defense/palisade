package shadowlog

import (
	"bufio"
	"crypto/cipher"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/palisade-bot-defense/palisade/internal/core"
)

func VerifyDirectory(directory, keyFile string) (Verification, error) {
	return ScanDirectory(directory, keyFile, ScanLimits{}, nil)
}

// ScanDirectory authenticates and decodes managed shadow-log records in
// filename order. The callback receives privacy-limited plaintext records and
// must not retain or print session keys. A zero-valued ScanLimits uses the
// conservative defaults declared in this package.
func ScanDirectory(directory, keyFile string, limits ScanLimits, visit func(Record) error) (Verification, error) {
	var result Verification
	limits, err := normalizeScanLimits(limits)
	if err != nil {
		return result, err
	}
	resolvedDirectory, err := existingPrivateDirectory(directory)
	if err != nil {
		return result, err
	}
	resolvedKey, master, err := readKey(keyFile)
	if err != nil {
		return result, err
	}
	defer wipe(master)
	if insideWorktree(resolvedKey) {
		return result, errors.New("shadow log key must be outside every Git worktree")
	}
	encryptionKey := deriveKey(master, "palisade:shadow-log:v1:encryption")
	defer wipe(encryptionKey)
	aead, err := newAEAD(encryptionKey)
	if err != nil {
		return result, err
	}
	keyID := keyIdentifier(encryptionKey)
	entries, err := os.ReadDir(resolvedDirectory)
	if err != nil {
		return result, err
	}
	var paths []string
	for _, entry := range entries {
		if isManagedLogName(entry.Name()) {
			if uint64(len(paths)) >= limits.MaxFiles {
				return Verification{}, ErrScanFileLimit
			}
			paths = append(paths, filepath.Join(resolvedDirectory, entry.Name()))
		}
	}
	sort.Strings(paths)
	for _, path := range paths {
		fileBytes, err := verifyFile(path, aead, keyID, limits.MaxRecords, limits.MaxEncryptedBytes-result.EncryptedBytes, &result, visit)
		if err != nil {
			return Verification{}, fmt.Errorf("verify %s: %w", filepath.Base(path), err)
		}
		result.EncryptedBytes += fileBytes
		result.Files++
	}
	return result, nil
}

func verifyFile(path string, aead cipher.AEAD, expectedKeyID [8]byte, maxRecords uint64, remainingBytes int64, result *Verification, visit func(Record) error) (int64, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 {
		return 0, errors.New("managed log must be a 0600 regular file")
	}
	if info.Size() < headerSize || info.Size() > remainingBytes {
		return 0, ErrScanByteLimit
	}
	file, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil || !os.SameFile(info, openedInfo) || openedInfo.Size() != info.Size() || openedInfo.Mode() != info.Mode() {
		return 0, errors.New("managed log changed while opening")
	}
	fileBytes := openedInfo.Size()
	reader := bufio.NewReader(io.LimitReader(file, fileBytes))
	header := make([]byte, headerSize)
	if _, err := io.ReadFull(reader, header); err != nil {
		return 0, errors.New("truncated header")
	}
	if string(header[:8]) != string(fileMagic[:]) || string(header[8:16]) != string(expectedKeyID[:]) {
		return 0, errors.New("header or encryption key mismatch")
	}
	var prefix [8]byte
	copy(prefix[:], header[16:24])
	var previousCounter uint32
	for {
		var counterBytes [4]byte
		_, err := io.ReadFull(reader, counterBytes[:])
		if errors.Is(err, io.EOF) {
			return fileBytes, nil
		}
		if err != nil {
			return 0, errors.New("truncated record counter")
		}
		counter := binary.BigEndian.Uint32(counterBytes[:])
		if counter != previousCounter+1 {
			return 0, errors.New("non-sequential record counter")
		}
		previousCounter = counter
		var lengthBytes [4]byte
		if _, err := io.ReadFull(reader, lengthBytes[:]); err != nil {
			return 0, errors.New("truncated record length")
		}
		length := binary.BigEndian.Uint32(lengthBytes[:])
		if length < uint32(aead.Overhead()) || length > 1<<20 {
			return 0, errors.New("invalid encrypted record length")
		}
		ciphertext := make([]byte, length)
		if _, err := io.ReadFull(reader, ciphertext); err != nil {
			return 0, errors.New("truncated encrypted record")
		}
		nonce := make([]byte, aead.NonceSize())
		copy(nonce[:8], prefix[:])
		copy(nonce[8:], counterBytes[:])
		aad := make([]byte, 0, len(fileMagic)+len(prefix)+len(counterBytes))
		aad = append(aad, fileMagic[:]...)
		aad = append(aad, prefix[:]...)
		aad = append(aad, counterBytes[:]...)
		plaintext, err := aead.Open(nil, nonce, ciphertext, aad)
		if err != nil {
			return 0, errors.New("record authentication failed")
		}
		record, err := decodeRecord(plaintext)
		if err != nil {
			return 0, err
		}
		if result.Records >= maxRecords {
			return 0, ErrScanRecordLimit
		}
		result.Records++
		if record.Kind == "decision" {
			result.Decisions++
		} else {
			result.Outcomes++
		}
		if result.FirstAt == "" || record.RecordedAt < result.FirstAt {
			result.FirstAt = record.RecordedAt
		}
		if result.LastAt == "" || record.RecordedAt > result.LastAt {
			result.LastAt = record.RecordedAt
		}
		if visit != nil {
			if err := visit(record); err != nil {
				return 0, fmt.Errorf("record visitor: %w", err)
			}
		}
	}
}

func normalizeScanLimits(limits ScanLimits) (ScanLimits, error) {
	if limits.MaxFiles == 0 {
		limits.MaxFiles = DefaultScanMaxFiles
	}
	if limits.MaxRecords == 0 {
		limits.MaxRecords = DefaultScanMaxRecords
	}
	if limits.MaxEncryptedBytes == 0 {
		limits.MaxEncryptedBytes = DefaultScanMaxEncryptedBytes
	}
	if limits.MaxFiles > MaximumScanMaxFiles || limits.MaxRecords > MaximumScanMaxRecords ||
		limits.MaxEncryptedBytes < headerSize || limits.MaxEncryptedBytes > MaximumScanMaxEncryptedBytes {
		return ScanLimits{}, errors.New("shadow log scan limits are outside supported bounds")
	}
	return limits, nil
}

func decodeRecord(encoded []byte) (Record, error) {
	var record Record
	decoder := json.NewDecoder(strings.NewReader(string(encoded)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return record, errors.New("invalid record JSON")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Record{}, errors.New("multiple record JSON values")
	}
	if err := validateRecord(record); err != nil {
		return Record{}, err
	}
	return record, nil
}

func validateRecord(record Record) error {
	if record.SchemaVersion != SchemaVersion || (record.Kind != "decision" && record.Kind != "outcome") {
		return errors.New("unsupported shadow record")
	}
	parsedAt, err := time.Parse(time.RFC3339, record.RecordedAt)
	if err != nil || parsedAt.UTC().Format(time.RFC3339) != record.RecordedAt {
		return errors.New("invalid record time")
	}
	linked, err := base64.RawURLEncoding.DecodeString(record.SessionKey)
	if err != nil || len(linked) != 16 {
		return errors.New("invalid session key")
	}
	if record.Kind == "decision" {
		if record.Decision == nil || record.Outcome != nil {
			return errors.New("invalid decision record shape")
		}
		entry := record.Decision
		if !stableValue.MatchString(entry.DecisionID) || normalizeRequestAction(entry.RequestAction) != entry.RequestAction || normalizeEndpoint(entry.EndpointClass) != entry.EndpointClass ||
			!validAction(entry.Action) || !validAction(entry.ComputedAction) || (entry.Mode != core.RuntimeModeShadow && entry.Mode != core.RuntimeModeEnforce) ||
			entry.Scores.AutomationRisk < 0 || entry.Scores.AutomationRisk > 1 || entry.Scores.AbuseIntentRisk < 0 || entry.Scores.AbuseIntentRisk > 1 || entry.Scores.AccountContinuity < 0 || entry.Scores.AccountContinuity > 1 ||
			!stableValue.MatchString(entry.PolicyVersion) || !stableValue.MatchString(entry.ModelVersion) || len(entry.ReasonCodes) > 32 {
			return errors.New("invalid decision record")
		}
		for _, reason := range entry.ReasonCodes {
			if !stableValue.MatchString(reason) {
				return errors.New("invalid decision reason")
			}
		}
		return nil
	}
	if record.Outcome == nil || record.Decision != nil {
		return errors.New("invalid outcome record shape")
	}
	return OutcomeRequest{
		SessionID: "verified-session-placeholder", DecisionID: record.Outcome.DecisionID,
		EndpointClass: record.Outcome.EndpointClass, Outcome: record.Outcome.Outcome,
		Provenance: record.Outcome.Provenance, Confidence: record.Outcome.Confidence,
	}.Validate()
}

func validAction(action core.Action) bool {
	switch action {
	case core.ActionAllow, core.ActionObserve, core.ActionThrottle, core.ActionChallenge, core.ActionBlock:
		return true
	default:
		return false
	}
}

func existingPrivateDirectory(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	info, err := os.Lstat(absolute)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return "", errors.New("shadow log directory must be a real owner-only directory")
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil || insideWorktree(resolved) {
		return "", errors.New("shadow log directory must be outside every Git worktree")
	}
	parentInfo, err := os.Stat(filepath.Dir(resolved))
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode().Perm()&0o077 != 0 {
		return "", errors.New("shadow log parent must be an owner-only directory")
	}
	return resolved, nil
}
