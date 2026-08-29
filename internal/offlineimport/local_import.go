package offlineimport

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

var ErrLocalEventOrder = errors.New("local evidence input observation time is decreasing")

func RunLocal(config LocalConfig) (result LocalResult, returnErr error) {
	config, err := normalizeLocalConfig(config)
	if err != nil {
		return result, err
	}
	inputPath, err := validatePrivateFile(config.InputFile, "local evidence input")
	if err != nil {
		return result, err
	}
	keyPath, err := validatePrivateFile(config.PseudonymKeyFile, "pseudonym key file")
	if err != nil {
		return result, err
	}
	if inputPath == keyPath {
		return result, errors.New("local evidence input and pseudonym key must be different files")
	}
	key, err := loadKey(keyPath)
	if err != nil {
		return result, err
	}
	defer wipe(key)
	pseudonyms := newPseudonymizer(key, config.DatasetID, config.PilotID)
	defer pseudonyms.Wipe()

	stagingDir, outputDir, outputParent, err := createOutputStaging(config.OutputDir)
	if err != nil {
		return result, err
	}
	completed := false
	budget := newBudgets(Config{
		MaxDecompressedBytes: config.MaxInputBytes,
		MaxInputRecords:      config.MaxInputRecords,
		MaxEvents:            config.MaxEvents,
		MaxShards:            config.MaxShards,
		MaxOutputBytes:       config.MaxOutputBytes,
		MaxWorkingBytes:      1,
	})
	writer := newLocalShardWriter(stagingDir, config.ShardSize, budget)
	defer func() {
		if completed {
			return
		}
		returnErr = errors.Join(returnErr, writer.Abort())
		if err := os.RemoveAll(stagingDir); err != nil {
			returnErr = errors.Join(returnErr, fmt.Errorf("%w: remove local import staging directory", ErrCleanup))
		}
	}()

	file, openedStats, err := openInput(inputPath, "operator-events.jsonl")
	if err != nil {
		return result, err
	}
	inputStats := LocalInputStats{
		LogicalName: "operator-events.jsonl",
		SizeBytes:   openedStats.SizeBytes,
		SHA256:      openedStats.SHA256,
	}
	consumed := newConsumedInput(file)
	scanner := bufio.NewScanner(&budgetReader{reader: consumed, budget: budget})
	initialBuffer := 64 << 10
	if config.MaxLineBytes < initialBuffer {
		initialBuffer = config.MaxLineBytes
	}
	scanner.Buffer(make([]byte, initialBuffer), config.MaxLineBytes)
	var lastObserved time.Time
	lineNumber := uint64(0)
	for scanner.Scan() {
		lineNumber++
		if err := budget.addRecord(); err != nil {
			_ = file.Close()
			return result, err
		}
		inputEvent, observedAt, err := decodeLocalInputEvent(scanner.Bytes())
		if err != nil {
			_ = file.Close()
			return result, fmt.Errorf("local evidence line %d violates the closed contract: %w", lineNumber, err)
		}
		if !lastObserved.IsZero() && observedAt.Before(lastObserved) {
			_ = file.Close()
			return result, fmt.Errorf("local evidence line %d: %w", lineNumber, ErrLocalEventOrder)
		}
		lastObserved = observedAt
		if inputStats.FirstObservedAt == "" {
			inputStats.FirstObservedAt = observedAt.Format(time.RFC3339Nano)
		}
		inputStats.LastObservedAt = observedAt.Format(time.RFC3339Nano)
		inputStats.Records++
		if err := budget.addEvent(); err != nil {
			_ = file.Close()
			return result, err
		}
		event := normalizeLocalEvent(inputEvent, observedAt, config.Provenance, pseudonyms)
		if err := writer.Write(event); err != nil {
			_ = file.Close()
			return result, err
		}
	}
	if err := scanner.Err(); err != nil {
		_ = file.Close()
		if strings.Contains(err.Error(), "token too long") {
			return result, errors.New("local evidence input line exceeds the configured limit")
		}
		return result, fmt.Errorf("read local evidence input: %w", err)
	}
	if consumed.bytes != openedStats.SizeBytes || consumed.digest() != openedStats.SHA256 {
		_ = file.Close()
		return result, ErrInputChanged
	}
	if err := verifyInput(file, inputPath, openedStats); err != nil {
		_ = file.Close()
		return result, err
	}
	if err := file.Close(); err != nil {
		return result, errors.New("close local evidence input")
	}
	if err := writer.Finish(); err != nil {
		return result, err
	}

	manifest := LocalManifest{
		SchemaVersion: LocalManifestSchemaVersion,
		Importer:      LocalImporterVersion,
		Provenance:    config.Provenance,
		Config: LocalManifestConfig{
			ShardSize:             config.ShardSize,
			MaxLineBytes:          config.MaxLineBytes,
			MaxInputBytes:         config.MaxInputBytes,
			MaxInputRecords:       config.MaxInputRecords,
			MaxEvents:             config.MaxEvents,
			MaxShards:             config.MaxShards,
			MaxOutputBytes:        config.MaxOutputBytes,
			Pseudonymization:      "domain_daily_hmac_sha256_v2",
			DomainID:              pseudonyms.domainID,
			ChronologicalRequired: true,
		},
		Input:    inputStats,
		Shards:   writer.shards,
		Totals:   LocalTotals{Records: inputStats.Records, Events: writer.total},
		Warnings: localManifestWarnings(),
	}
	if err := writeLocalJSON(filepath.Join(stagingDir, "local-manifest.json"), manifest, budget); err != nil {
		return result, err
	}
	if err := writeLocalCompletion(filepath.Join(stagingDir, "LOCAL_COMPLETE"), budget); err != nil {
		return result, err
	}
	if err := syncDirectory(stagingDir); err != nil {
		return result, errors.New("sync local import staging directory")
	}
	if _, err := os.Lstat(outputDir); err == nil {
		return result, errors.New("output directory appeared during local import; refusing overwrite")
	} else if !os.IsNotExist(err) {
		return result, errors.New("inspect local import output directory before publish")
	}
	if err := os.Rename(stagingDir, outputDir); err != nil {
		return result, errors.New("publish local import output directory")
	}
	if err := syncDirectory(outputParent); err != nil {
		rollbackErr := os.Rename(outputDir, stagingDir)
		if rollbackErr == nil {
			rollbackErr = syncDirectory(outputParent)
		}
		return result, errors.Join(errors.New("sync local import output parent directory"), rollbackErr)
	}
	completed = true
	return LocalResult{ManifestPath: filepath.Join(outputDir, "local-manifest.json"), Events: writer.total}, nil
}

func localManifestWarnings() []string {
	return []string{
		"operator-supplied evidence classes depend on the operator adapter mapping and are not independently verified",
		"unknown labels are not confirmed-human labels",
		"challenge completion is an outcome and does not establish humanity",
		"direct subject and session references are used only transiently for local pseudonymization",
	}
}

func normalizeLocalConfig(config LocalConfig) (LocalConfig, error) {
	if config.InputFile == "" || config.OutputDir == "" || config.PseudonymKeyFile == "" || config.DatasetID == "" || config.PilotID == "" {
		return config, errors.New("--input-file, --output-dir, --pseudonym-key-file, --dataset-id and --pilot-id are required")
	}
	if !domainNamePattern.MatchString(config.DatasetID) || !domainNamePattern.MatchString(config.PilotID) {
		return config, errors.New("dataset and pilot identifiers must use 1-128 safe ASCII characters")
	}
	if config.Provenance == "" {
		config.Provenance = ProvenanceOperatorExport
	}
	if config.Provenance != ProvenanceOperatorExport {
		return config, fmt.Errorf("unsupported provenance %q: only operator_authorized_export is accepted", config.Provenance)
	}
	if config.ShardSize == 0 {
		config.ShardSize = DefaultShardSize
	}
	if config.ShardSize < MinimumShardSize || config.ShardSize > MaximumShardSize {
		return config, fmt.Errorf("shard size must be between %d and %d records", MinimumShardSize, MaximumShardSize)
	}
	if config.MaxLineBytes == 0 {
		config.MaxLineBytes = DefaultMaxLineSize
	}
	if config.MaxLineBytes < MinimumMaxLineSize || config.MaxLineBytes > MaximumMaxLineSize {
		return config, fmt.Errorf("maximum line size must be between %d and %d bytes", MinimumMaxLineSize, MaximumMaxLineSize)
	}
	if config.MaxInputBytes == 0 {
		config.MaxInputBytes = DefaultMaxDecompressedBytes
	}
	if config.MaxInputRecords == 0 {
		config.MaxInputRecords = DefaultMaxInputRecords
	}
	if config.MaxEvents == 0 {
		config.MaxEvents = DefaultMaxEvents
	}
	if config.MaxShards == 0 {
		config.MaxShards = DefaultMaxShards
	}
	if config.MaxOutputBytes == 0 {
		config.MaxOutputBytes = DefaultMaxOutputBytes
	}
	if config.MaxInputBytes < 1 || config.MaxInputRecords < 1 || config.MaxEvents < 1 || config.MaxShards < 1 || config.MaxOutputBytes < 1 {
		return config, errors.New("local evidence import budgets must be positive")
	}
	if config.MaxShards > MaximumShardCount {
		return config, fmt.Errorf("maximum shards must not exceed %d", MaximumShardCount)
	}
	return config, nil
}

func decodeLocalInputEvent(encoded []byte) (LocalInputEvent, time.Time, error) {
	if len(bytes.TrimSpace(encoded)) == 0 {
		return LocalInputEvent{}, time.Time{}, errors.New("empty lines are not accepted")
	}
	if err := rejectDuplicateJSONKeys(encoded); err != nil {
		return LocalInputEvent{}, time.Time{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var event LocalInputEvent
	if err := decoder.Decode(&event); err != nil {
		return LocalInputEvent{}, time.Time{}, errors.New("invalid JSON object")
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return LocalInputEvent{}, time.Time{}, err
	}
	observedAt, err := validateLocalInputEvent(event)
	if err != nil {
		return LocalInputEvent{}, time.Time{}, err
	}
	return event, observedAt, nil
}

func validateLocalInputEvent(event LocalInputEvent) (time.Time, error) {
	allowed := func(value string, values ...string) bool {
		for _, candidate := range values {
			if value == candidate {
				return true
			}
		}
		return false
	}
	if event.SchemaVersion != LocalInputSchemaVersion {
		return time.Time{}, errors.New("unsupported schema_version")
	}
	if !validLocalReference(event.SubjectRef) || (event.SessionRef != "" && !validLocalReference(event.SessionRef)) {
		return time.Time{}, errors.New("subject_ref or session_ref is invalid")
	}
	if !allowed(event.Source, "access_gateway", "browser_sensor", "challenge_service", "policy_engine", "decoy_service", "outcome_service") ||
		!allowed(event.EndpointClass, "public_content", "account", "authentication", "transaction", "api", "decoy", "other") ||
		!allowed(event.ActionClass, "read", "write", "authenticate", "other") ||
		!allowed(event.StatusClass, "success", "redirect", "client_error", "server_error", "unknown") ||
		!allowed(event.Evidence.CollectionStatus, "complete", "partial", "missing") ||
		!allowed(event.Evidence.AutomationEvidence, "none", "low", "medium", "high") ||
		!allowed(event.Evidence.AbuseIntentEvidence, "none", "low", "medium", "high") ||
		!allowed(event.Evidence.ContinuityEvidence, "none", "low", "medium", "high") ||
		!allowed(event.Evidence.DecoyInteraction, "none", "rendered", "touched", "submitted") ||
		!allowed(event.Evidence.ChallengeLifecycle, "none", "issued", "passed", "failed", "abandoned", "fallback") {
		return time.Time{}, errors.New("event violates a closed enum")
	}
	if !allowed(event.Label.Class, "unknown", "human_confirmed", "operator_confirmed_abuse") ||
		!allowed(event.Label.Provenance, "none", "authenticated_account", "operator_review") ||
		!allowed(event.Label.Confidence, "unknown", "confirmed") {
		return time.Time{}, errors.New("label violates a closed enum")
	}
	switch event.Label.Class {
	case "unknown":
		if event.Label.Provenance != "none" || event.Label.Confidence != "unknown" {
			return time.Time{}, errors.New("unknown label must use none/unknown provenance and confidence")
		}
	case "human_confirmed":
		if event.Label.Confidence != "confirmed" || (event.Label.Provenance != "authenticated_account" && event.Label.Provenance != "operator_review") {
			return time.Time{}, errors.New("confirmed-human label requires authenticated_account or operator_review provenance")
		}
	case "operator_confirmed_abuse":
		if event.Label.Provenance != "operator_review" || event.Label.Confidence != "confirmed" {
			return time.Time{}, errors.New("confirmed-abuse label requires operator_review provenance")
		}
	}
	observedAt, err := time.Parse(time.RFC3339Nano, event.ObservedAt)
	if err != nil || observedAt.Location() != time.UTC || !strings.HasSuffix(event.ObservedAt, "Z") {
		return time.Time{}, errors.New("observed_at must be UTC RFC3339 with a Z suffix")
	}
	return observedAt, nil
}

func normalizeLocalEvent(input LocalInputEvent, observedAt time.Time, provenance string, pseudonyms *pseudonymizer) LocalEvent {
	event := LocalEvent{
		SchemaVersion: LocalEventSchemaVersion,
		Provenance:    provenance,
		ObservedAt:    observedAt.Format(time.RFC3339Nano),
		SubjectID:     pseudonyms.pseudonym("subject", observedAt, input.SubjectRef, ""),
		Source:        input.Source,
		EndpointClass: input.EndpointClass,
		ActionClass:   input.ActionClass,
		StatusClass:   input.StatusClass,
		Evidence:      input.Evidence,
		Label:         input.Label,
	}
	if input.SessionRef != "" {
		event.SessionID = pseudonyms.pseudonym("session", observedAt, input.SubjectRef, input.SessionRef)
	}
	return event
}

func validLocalReference(value string) bool {
	if value == "" || len(value) > 512 || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	return strings.IndexFunc(value, unicode.IsControl) < 0
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("multiple JSON values are not accepted")
	}
	return nil
}

func rejectDuplicateJSONKeys(encoded []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	var walk func() error
	walk = func() error {
		token, err := decoder.Token()
		if err != nil {
			return errors.New("invalid JSON object")
		}
		delimiter, compound := token.(json.Delim)
		if !compound {
			return nil
		}
		switch delimiter {
		case '{':
			seen := map[string]bool{}
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return errors.New("invalid JSON object")
				}
				key, ok := keyToken.(string)
				if !ok || seen[key] {
					return errors.New("duplicate or invalid JSON object key")
				}
				seen[key] = true
				if err := walk(); err != nil {
					return err
				}
			}
		case '[':
			for decoder.More() {
				if err := walk(); err != nil {
					return err
				}
			}
		default:
			return errors.New("invalid JSON delimiter")
		}
		if _, err := decoder.Token(); err != nil {
			return errors.New("invalid JSON object")
		}
		return nil
	}
	if err := walk(); err != nil {
		return err
	}
	if decoder.More() {
		return errors.New("multiple JSON values are not accepted")
	}
	return nil
}
