package offlineimport

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

const localControlFileMaxBytes = 1 << 20

// ScanLocalDirectory authenticates the deterministic manifest, verifies every
// declared shard and streams closed normalized events in chronological order.
// Identifiers are passed only to the in-process callback and are never included
// in errors or verification output.
func ScanLocalDirectory(directory string, limits LocalScanLimits, consume func(LocalEvent) error) (LocalManifest, LocalVerification, error) {
	var manifest LocalManifest
	var verified LocalVerification
	if consume == nil {
		return manifest, verified, errors.New("local evidence scan requires a consumer")
	}
	limits, err := normalizeLocalScanLimits(limits)
	if err != nil {
		return manifest, verified, err
	}
	root, err := validateInputDir(directory)
	if err != nil {
		return manifest, verified, fmt.Errorf("local evidence directory: %w", err)
	}
	manifestPath, err := validateInputFile(filepath.Join(root, "local-manifest.json"), "local-manifest.json")
	if err != nil {
		return manifest, verified, err
	}
	markerPath, err := validateInputFile(filepath.Join(root, "LOCAL_COMPLETE"), "LOCAL_COMPLETE")
	if err != nil {
		return manifest, verified, err
	}
	manifestBytes, manifestStats, err := readLocalControlFile(manifestPath, "local-manifest.json", localControlFileMaxBytes)
	if err != nil {
		return manifest, verified, err
	}
	if err := DecodeStrictJSON(manifestBytes, &manifest); err != nil {
		return manifest, verified, errors.New("local evidence manifest violates the closed contract")
	}
	if err := validateLocalManifest(manifest, limits); err != nil {
		return manifest, verified, err
	}
	marker, markerStats, err := readLocalControlFile(markerPath, "LOCAL_COMPLETE", 128)
	if err != nil {
		return manifest, verified, err
	}
	if string(marker) != LocalManifestSchemaVersion+"\n" {
		return manifest, verified, errors.New("local evidence completion marker is invalid")
	}
	verified.Bytes = manifestStats.SizeBytes + markerStats.SizeBytes
	if verified.Bytes > limits.MaxBytes || verified.Bytes > manifest.Config.MaxOutputBytes {
		return manifest, verified, errors.New("local evidence scan byte budget exceeded")
	}
	for _, shard := range manifest.Shards {
		if shard.SizeBytes > limits.MaxBytes-verified.Bytes || shard.SizeBytes > manifest.Config.MaxOutputBytes-verified.Bytes {
			return manifest, verified, errors.New("local evidence scan byte budget exceeded")
		}
		verified.Bytes += shard.SizeBytes
	}
	if err := verifyLocalDirectoryEntries(root, manifest.Shards); err != nil {
		return manifest, verified, err
	}

	var lastObserved time.Time
	for _, shard := range manifest.Shards {
		path, err := validateInputFile(filepath.Join(root, shard.Filename), shard.Filename)
		if err != nil {
			return manifest, verified, err
		}
		count, err := scanLocalShard(path, shard, manifest.Config.MaxLineBytes, limits.MaxEvents, &verified, &lastObserved, consume)
		if err != nil {
			return manifest, verified, fmt.Errorf("verify local evidence shard %s: %w", shard.Filename, err)
		}
		if count != shard.Records {
			return manifest, verified, fmt.Errorf("local evidence shard %s record count does not match manifest", shard.Filename)
		}
		verified.Shards++
	}
	if verified.Events != manifest.Totals.Events {
		return manifest, verified, errors.New("local evidence event total does not match manifest")
	}
	if verified.Events > 0 && (verified.FirstAt != manifest.Input.FirstObservedAt || verified.LastAt != manifest.Input.LastObservedAt) {
		return manifest, verified, errors.New("local evidence observed range does not match manifest")
	}
	if err := verifyLocalDirectoryEntries(root, manifest.Shards); err != nil {
		return manifest, verified, err
	}
	return manifest, verified, nil
}

func normalizeLocalScanLimits(limits LocalScanLimits) (LocalScanLimits, error) {
	if limits.MaxShards == 0 {
		limits.MaxShards = DefaultLocalScanMaxShards
	}
	if limits.MaxEvents == 0 {
		limits.MaxEvents = DefaultLocalScanMaxEvents
	}
	if limits.MaxBytes == 0 {
		limits.MaxBytes = DefaultLocalScanMaxBytes
	}
	if limits.MaxShards < 1 || limits.MaxShards > MaximumShardCount || limits.MaxEvents < 1 || limits.MaxEvents > MaximumLocalScanEvents || limits.MaxBytes < 1 || limits.MaxBytes > MaximumLocalScanBytes {
		return limits, errors.New("local evidence scan limits are outside supported bounds")
	}
	return limits, nil
}

func validateLocalManifest(manifest LocalManifest, limits LocalScanLimits) error {
	if manifest.SchemaVersion != LocalManifestSchemaVersion || manifest.Importer != LocalImporterVersion || manifest.Provenance != ProvenanceOperatorExport {
		return errors.New("unsupported local evidence manifest")
	}
	config := manifest.Config
	if config.ShardSize < MinimumShardSize || config.ShardSize > MaximumShardSize ||
		config.MaxLineBytes < MinimumMaxLineSize || config.MaxLineBytes > MaximumMaxLineSize ||
		config.MaxInputBytes < 1 || config.MaxInputRecords < 1 || config.MaxEvents < 1 ||
		config.MaxShards < 1 || config.MaxShards > MaximumShardCount || config.MaxOutputBytes < 1 ||
		config.Pseudonymization != "domain_daily_hmac_sha256_v2" || !config.ChronologicalRequired || !validDomainID(config.DomainID) {
		return errors.New("local evidence manifest configuration is invalid")
	}
	if manifest.Input.LogicalName != "operator-events.jsonl" || manifest.Input.SizeBytes < 0 || !validSHA256(manifest.Input.SHA256) ||
		manifest.Input.SizeBytes > config.MaxInputBytes || manifest.Input.Records > config.MaxInputRecords ||
		manifest.Input.Records != manifest.Totals.Records || manifest.Totals.Records != manifest.Totals.Events {
		return errors.New("local evidence manifest input totals are invalid")
	}
	if !slices.Equal(manifest.Warnings, localManifestWarnings()) {
		return errors.New("local evidence manifest warnings are incomplete or reordered")
	}
	if len(manifest.Shards) > config.MaxShards || len(manifest.Shards) > limits.MaxShards || manifest.Totals.Events > config.MaxEvents || manifest.Totals.Events > limits.MaxEvents {
		return errors.New("local evidence manifest exceeds scan limits")
	}
	if manifest.Totals.Events == 0 {
		if len(manifest.Shards) != 0 || manifest.Input.FirstObservedAt != "" || manifest.Input.LastObservedAt != "" {
			return errors.New("empty local evidence manifest contains non-empty ranges or shards")
		}
		return nil
	}
	first, firstErr := parseLocalUTC(manifest.Input.FirstObservedAt)
	last, lastErr := parseLocalUTC(manifest.Input.LastObservedAt)
	if firstErr != nil || lastErr != nil || last.Before(first) || len(manifest.Shards) == 0 {
		return errors.New("local evidence manifest observation range is invalid")
	}
	var records uint64
	for index, shard := range manifest.Shards {
		wantName := fmt.Sprintf("evidence-%06d.jsonl", index+1)
		if shard.Filename != wantName || shard.Records == 0 || shard.Records > uint64(config.ShardSize) || shard.SizeBytes < 1 || !validSHA256(shard.SHA256) {
			return errors.New("local evidence manifest shard descriptor is invalid")
		}
		if index < len(manifest.Shards)-1 && shard.Records != uint64(config.ShardSize) {
			return errors.New("local evidence manifest contains a short non-final shard")
		}
		if records > ^uint64(0)-shard.Records {
			return errors.New("local evidence manifest record total overflows")
		}
		records += shard.Records
	}
	if records != manifest.Totals.Events {
		return errors.New("local evidence manifest shard totals do not match")
	}
	return nil
}

func readLocalControlFile(path, name string, maxBytes int64) ([]byte, InputStats, error) {
	file, stats, err := openInput(path, name)
	if err != nil {
		return nil, stats, err
	}
	if stats.SizeBytes > maxBytes {
		_ = file.Close()
		return nil, stats, fmt.Errorf("%s exceeds its size limit", name)
	}
	consumed := newConsumedInput(file)
	content, err := io.ReadAll(io.LimitReader(consumed, maxBytes+1))
	if err != nil || int64(len(content)) > maxBytes || consumed.bytes != stats.SizeBytes || consumed.digest() != stats.SHA256 {
		_ = file.Close()
		return nil, stats, fmt.Errorf("read %s", name)
	}
	if err := verifyInput(file, path, stats); err != nil {
		_ = file.Close()
		return nil, stats, err
	}
	if err := file.Close(); err != nil {
		return nil, stats, fmt.Errorf("close %s", name)
	}
	return content, stats, nil
}

func scanLocalShard(path string, expected ShardStats, maxLineBytes int, maxEvents uint64, verified *LocalVerification, lastObserved *time.Time, consume func(LocalEvent) error) (uint64, error) {
	file, stats, err := openInput(path, expected.Filename)
	if err != nil {
		return 0, err
	}
	if stats.SizeBytes != expected.SizeBytes || stats.SHA256 != expected.SHA256 {
		_ = file.Close()
		return 0, errors.New("local evidence shard fingerprint does not match manifest")
	}
	consumed := newConsumedInput(file)
	scanner := bufio.NewScanner(consumed)
	initialBuffer := 64 << 10
	if maxLineBytes < initialBuffer {
		initialBuffer = maxLineBytes
	}
	scanner.Buffer(make([]byte, initialBuffer), maxLineBytes)
	var count uint64
	for scanner.Scan() {
		if verified.Events >= maxEvents {
			_ = file.Close()
			return count, errors.New("local evidence scan event budget exceeded")
		}
		var event LocalEvent
		if err := DecodeStrictJSON(scanner.Bytes(), &event); err != nil || ValidateLocalEvent(event) != nil {
			_ = file.Close()
			return count, errors.New("local evidence shard contains an invalid event")
		}
		observedAt, _ := parseLocalUTC(event.ObservedAt)
		if !lastObserved.IsZero() && observedAt.Before(*lastObserved) {
			_ = file.Close()
			return count, ErrLocalEventOrder
		}
		*lastObserved = observedAt
		if verified.FirstAt == "" {
			verified.FirstAt = event.ObservedAt
		}
		verified.LastAt = event.ObservedAt
		if err := consume(event); err != nil {
			_ = file.Close()
			return count, errors.New("local evidence consumer rejected an event")
		}
		verified.Events++
		count++
	}
	if err := scanner.Err(); err != nil {
		_ = file.Close()
		if strings.Contains(err.Error(), "token too long") {
			return count, errors.New("local evidence shard line exceeds the configured limit")
		}
		return count, errors.New("read local evidence shard")
	}
	if consumed.bytes != stats.SizeBytes || consumed.digest() != stats.SHA256 {
		_ = file.Close()
		return count, ErrInputChanged
	}
	if err := verifyInput(file, path, stats); err != nil {
		_ = file.Close()
		return count, err
	}
	if err := file.Close(); err != nil {
		return count, errors.New("close local evidence shard")
	}
	return count, nil
}

func verifyLocalDirectoryEntries(root string, shards []ShardStats) error {
	want := map[string]bool{"local-manifest.json": true, "LOCAL_COMPLETE": true}
	for _, shard := range shards {
		want[shard.Filename] = true
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return errors.New("read local evidence directory")
	}
	if len(entries) != len(want) {
		return errors.New("local evidence directory contains undeclared entries")
	}
	for _, entry := range entries {
		if !want[entry.Name()] || entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			return errors.New("local evidence directory contains an invalid entry")
		}
	}
	return nil
}

// DecodeStrictJSON decodes exactly one JSON value and rejects duplicate keys,
// unknown fields, empty input and trailing content.
func DecodeStrictJSON(encoded []byte, destination any) error {
	if len(bytes.TrimSpace(encoded)) == 0 {
		return errors.New("empty JSON is not accepted")
	}
	if err := rejectDuplicateJSONKeys(encoded); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	return ensureJSONEOF(decoder)
}

func parseLocalUTC(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || parsed.Location() != time.UTC || !strings.HasSuffix(value, "Z") {
		return time.Time{}, errors.New("invalid UTC observation time")
	}
	return parsed, nil
}

func validSHA256(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32 && value == strings.ToLower(value)
}

func validDomainID(value string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == 12
}
