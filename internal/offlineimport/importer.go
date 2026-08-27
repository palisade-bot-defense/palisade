package offlineimport

import (
	"bufio"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var domainNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

func Run(config Config) (result Result, returnErr error) {
	config, err := normalizeConfig(config)
	if err != nil {
		return result, err
	}
	inputDir, err := validateInputDir(config.InputDir)
	if err != nil {
		return result, err
	}
	inputPaths := make(map[string]string, len(expectedInputs))
	for _, name := range expectedInputs {
		path, err := validateInputFile(filepath.Join(inputDir, name), name)
		if err != nil {
			return result, err
		}
		inputPaths[name] = path
	}
	keyPath, err := validatePrivateFile(config.PseudonymKeyFile, "pseudonym key file")
	if err != nil {
		return result, err
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
	budget := newBudgets(config)
	sorter := newEventSorter(stagingDir, config.SortChunkSize, budget)
	writer := newShardWriter(stagingDir, config.ShardSize, budget)
	defer func() {
		if completed {
			return
		}
		returnErr = errors.Join(returnErr, sorter.Abort(), writer.Abort())
		if err := os.RemoveAll(stagingDir); err != nil {
			returnErr = errors.Join(returnErr, fmt.Errorf("%w: remove staging directory", ErrCleanup))
		}
	}()

	manifest := Manifest{
		SchemaVersion: ManifestSchemaVersion,
		Importer:      ImporterVersion,
		Provenance:    ProvenanceOffline,
		Config: ManifestConfig{
			ShardSize:            config.ShardSize,
			MaxLineBytes:         config.MaxLineBytes,
			Classifier:           classifierVersion,
			Pseudonymization:     "domain_daily_hmac_sha256_v2",
			DomainID:             pseudonyms.domainID,
			AnubisPeerSource:     config.AnubisPeerSource,
			SortChunkSize:        config.SortChunkSize,
			MaxDecompressedBytes: config.MaxDecompressedBytes,
			MaxInputRecords:      config.MaxInputRecords,
			MaxEvents:            config.MaxEvents,
			MaxShards:            config.MaxShards,
			MaxOutputBytes:       config.MaxOutputBytes,
			MaxWorkingBytes:      config.MaxWorkingBytes,
		},
		Warnings: manifestWarnings(config.AnubisPeerSource),
	}

	processors := []struct {
		name string
		run  func(io.Reader, *InputStats) error
	}{
		{"access.log.gz", func(file io.Reader, stats *InputStats) error {
			return processAccess(file, stats, sorter, pseudonyms, config.MaxLineBytes, budget)
		}},
		{"anubis-strain.jsonl.gz", func(file io.Reader, stats *InputStats) error {
			return processAnubis(file, stats, sorter, pseudonyms, config.AnubisPeerSource, config.MaxLineBytes, budget)
		}},
		{"crowdsec-alerts.json", func(file io.Reader, stats *InputStats) error {
			return processCrowdSec(file, stats, sorter, pseudonyms, "crowdsec_alert", config.MaxLineBytes, budget)
		}},
		{"crowdsec-decisions.json", func(file io.Reader, stats *InputStats) error {
			return processCrowdSec(file, stats, sorter, pseudonyms, "crowdsec_decision", config.MaxLineBytes, budget)
		}},
		{"error.log.gz", func(file io.Reader, stats *InputStats) error {
			return processErrorLog(file, stats, config.MaxLineBytes, budget)
		}},
	}
	for _, processor := range processors {
		file, stats, err := openInput(inputPaths[processor.name], processor.name)
		if err != nil {
			return result, err
		}
		consumed := newConsumedInput(file)
		err = processor.run(consumed, &stats)
		if err == nil && (consumed.bytes != stats.SizeBytes || consumed.digest() != stats.SHA256) {
			err = ErrInputChanged
		}
		if err == nil {
			err = verifyInput(file, inputPaths[processor.name], stats)
		}
		closeErr := file.Close()
		if err != nil {
			return result, fmt.Errorf("process %s: %w", processor.name, err)
		}
		if closeErr != nil {
			return result, fmt.Errorf("close %s: %w", processor.name, closeErr)
		}
		manifest.Inputs = append(manifest.Inputs, stats)
		manifest.Totals.Records += stats.Records
		manifest.Totals.Invalid += stats.Invalid
		manifest.Totals.Skipped += stats.Skipped
	}
	if err := sorter.Finish(writer); err != nil {
		return result, err
	}
	manifest.Shards = writer.shards
	manifest.Totals.Events = writer.total

	if err := writeManifest(filepath.Join(stagingDir, "manifest.json"), manifest, budget); err != nil {
		return result, err
	}
	if err := writeCompletionMarker(filepath.Join(stagingDir, "COMPLETE"), budget); err != nil {
		return result, err
	}
	if err := syncDirectory(stagingDir); err != nil {
		return result, errors.New("sync staging directory")
	}
	if _, err := os.Lstat(outputDir); err == nil {
		return result, errors.New("output directory appeared during import; refusing overwrite")
	} else if !os.IsNotExist(err) {
		return result, errors.New("inspect output directory before publish")
	}
	if err := os.Rename(stagingDir, outputDir); err != nil {
		return result, errors.New("publish output directory")
	}
	if err := syncDirectory(outputParent); err != nil {
		rollbackErr := os.Rename(outputDir, stagingDir)
		if rollbackErr == nil {
			rollbackErr = syncDirectory(outputParent)
		}
		return result, errors.Join(errors.New("sync output parent directory"), rollbackErr)
	}
	completed = true
	return Result{
		ManifestPath: filepath.Join(outputDir, "manifest.json"),
		Events:       manifest.Totals.Events,
		Invalid:      manifest.Totals.Invalid,
		Skipped:      manifest.Totals.Skipped,
	}, nil
}

func manifestWarnings(anubisPeerSource string) []string {
	warnings := []string{"crowdsec labels are weak policy labels and are not ground truth"}
	if anubisPeerSource == AnubisPeerTrustedReal {
		return append(warnings, "Anubis x-real-ip is trusted under an operator-asserted Cloudflare edge boundary and used only transiently")
	}
	return append(warnings, "forwarded client addresses are ignored; direct peer identifiers are used only transiently")
}

func normalizeConfig(config Config) (Config, error) {
	if config.InputDir == "" || config.OutputDir == "" || config.PseudonymKeyFile == "" || config.DatasetID == "" || config.PilotID == "" {
		return config, errors.New("--input-dir, --output-dir, --pseudonym-key-file, --dataset-id and --pilot-id are required")
	}
	if !domainNamePattern.MatchString(config.DatasetID) || !domainNamePattern.MatchString(config.PilotID) {
		return config, errors.New("dataset and pilot identifiers must use 1-128 safe ASCII characters")
	}
	if config.Provenance == "" {
		config.Provenance = ProvenanceOffline
	}
	if config.Provenance != ProvenanceOffline {
		return config, fmt.Errorf("unsupported provenance %q: only offline_export is accepted", config.Provenance)
	}
	if config.AnubisPeerSource == "" {
		config.AnubisPeerSource = AnubisPeerDirect
	}
	if config.AnubisPeerSource != AnubisPeerDirect && config.AnubisPeerSource != AnubisPeerTrustedReal {
		return config, fmt.Errorf("unsupported Anubis peer source %q", config.AnubisPeerSource)
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
	if config.SortChunkSize == 0 {
		config.SortChunkSize = DefaultSortChunkSize
	}
	if config.SortChunkSize < MinimumSortChunkSize || config.SortChunkSize > MaximumSortChunkSize {
		return config, fmt.Errorf("sort chunk size must be between %d and %d events", MinimumSortChunkSize, MaximumSortChunkSize)
	}
	if config.MaxDecompressedBytes == 0 {
		config.MaxDecompressedBytes = DefaultMaxDecompressedBytes
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
	if config.MaxShards > MaximumShardCount {
		return config, fmt.Errorf("maximum shards must not exceed %d", MaximumShardCount)
	}
	if config.MaxOutputBytes == 0 {
		config.MaxOutputBytes = DefaultMaxOutputBytes
	}
	if config.MaxWorkingBytes == 0 {
		config.MaxWorkingBytes = DefaultMaxWorkingBytes
	}
	if config.MaxDecompressedBytes < 1 || config.MaxInputRecords < 1 || config.MaxEvents < 1 || config.MaxShards < 1 || config.MaxOutputBytes < 1 || config.MaxWorkingBytes < 1 {
		return config, errors.New("offline import budgets must be positive")
	}
	sortRuns := config.MaxEvents / uint64(config.SortChunkSize)
	if config.MaxEvents%uint64(config.SortChunkSize) != 0 {
		sortRuns++
	}
	if sortRuns > MaximumSortRuns {
		return config, fmt.Errorf("configured event budget requires more than %d initial sort runs", MaximumSortRuns)
	}
	return config, nil
}

func validateInputDir(path string) (string, error) {
	resolved, err := canonicalExistingPath(path)
	if err != nil {
		return "", errors.New("input directory is unavailable")
	}
	info, err := os.Lstat(resolved)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("input directory must be a real directory, not a symlink")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return "", errors.New("input directory must be owner-only")
	}
	if insideGitWorktree(resolved) {
		return "", errors.New("input directory must be outside every Git worktree")
	}
	return resolved, nil
}

func validateInputFile(path, name string) (string, error) {
	resolved, err := canonicalExistingPath(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("required input %s is missing", name)
		}
		return "", fmt.Errorf("inspect required input %s", name)
	}
	info, err := os.Lstat(resolved)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return "", fmt.Errorf("required input %s must be a non-symlink regular file", name)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("required input %s must be owner-only", name)
	}
	if insideGitWorktree(resolved) {
		return "", fmt.Errorf("required input %s must be outside every Git worktree", name)
	}
	return resolved, nil
}

func validatePrivateFile(path, description string) (string, error) {
	resolved, err := canonicalExistingPath(path)
	if err != nil {
		return "", fmt.Errorf("%s is unavailable", description)
	}
	info, err := os.Lstat(resolved)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return "", fmt.Errorf("%s must be a non-symlink regular file", description)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("%s must be owner-only", description)
	}
	if insideGitWorktree(resolved) {
		return "", fmt.Errorf("%s must be outside every Git worktree", description)
	}
	return resolved, nil
}

func canonicalExistingPath(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	if info, err := os.Lstat(absolute); err != nil {
		return "", err
	} else if info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("symlink is not accepted")
	}
	if err := rejectUnsafeParentSymlinks(absolute); err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(absolute)
}

func rejectUnsafeParentSymlinks(absolute string) error {
	volume := filepath.VolumeName(absolute)
	separator := string(filepath.Separator)
	current := volume + separator
	remainder := strings.TrimPrefix(absolute, current)
	parts := strings.Split(remainder, separator)
	for index, part := range parts {
		if part == "" {
			continue
		}
		current = filepath.Join(current, part)
		if index == len(parts)-1 {
			break
		}
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink == 0 {
			continue
		}
		resolved, err := filepath.EvalSymlinks(current)
		if err != nil || !safeSystemPathAlias(current, resolved) {
			return errors.New("parent symlink is not accepted")
		}
	}
	return nil
}

func safeSystemPathAlias(path, resolved string) bool {
	return (path == "/var" && resolved == "/private/var") || (path == "/tmp" && resolved == "/private/tmp")
}

func loadKey(path string) ([]byte, error) {
	resolved, err := canonicalExistingPath(path)
	if err != nil || resolved != filepath.Clean(path) || insideGitWorktree(resolved) {
		return nil, errors.New("pseudonym key file changed before opening")
	}
	lstat, err := os.Lstat(path)
	if err != nil || lstat.Mode()&os.ModeSymlink != 0 || !lstat.Mode().IsRegular() || lstat.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("pseudonym key file changed before opening")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("open pseudonym key file")
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || opened.Mode().Perm()&0o077 != 0 || !os.SameFile(lstat, opened) {
		return nil, errors.New("pseudonym key file changed while opening")
	}
	key, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil {
		wipe(key)
		return nil, errors.New("read pseudonym key file")
	}
	afterRead, statErr := file.Stat()
	pathInfo, pathErr := os.Lstat(path)
	if statErr != nil || pathErr != nil || afterRead.Size() != opened.Size() || afterRead.ModTime() != opened.ModTime() || !os.SameFile(afterRead, pathInfo) {
		wipe(key)
		return nil, errors.New("pseudonym key file changed while reading")
	}
	if len(key) < 32 {
		wipe(key)
		return nil, errors.New("pseudonym key must contain at least 32 bytes")
	}
	if len(key) > 4096 {
		wipe(key)
		return nil, errors.New("pseudonym key file is unexpectedly large")
	}
	return key, nil
}

func wipe(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func createOutputStaging(path string) (string, string, string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", "", "", errors.New("resolve output directory")
	}
	if _, err := os.Lstat(absolute); err == nil {
		return "", "", "", errors.New("output directory already exists; refusing overwrite")
	} else if !os.IsNotExist(err) {
		return "", "", "", errors.New("inspect output directory")
	}
	parent, err := canonicalExistingPath(filepath.Dir(absolute))
	if err != nil {
		return "", "", "", errors.New("output parent directory must already exist")
	}
	if insideGitWorktree(parent) {
		return "", "", "", errors.New("output directory must be outside every Git worktree")
	}
	finalPath := filepath.Join(parent, filepath.Base(absolute))
	staging, err := os.MkdirTemp(parent, ".palisade-import-")
	if err != nil {
		return "", "", "", errors.New("create output staging directory")
	}
	if err := os.Chmod(staging, 0o700); err != nil {
		removeErr := os.Remove(staging)
		return "", "", "", errors.Join(errors.New("secure output staging directory"), removeErr)
	}
	return staging, finalPath, parent, nil
}

func insideGitWorktree(path string) bool {
	current := filepath.Clean(path)
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

func openInput(path, name string) (*os.File, InputStats, error) {
	resolved, err := canonicalExistingPath(path)
	if err != nil || resolved != filepath.Clean(path) || insideGitWorktree(resolved) {
		return nil, InputStats{}, fmt.Errorf("inspect %s", name)
	}
	lstat, err := os.Lstat(path)
	if err != nil || lstat.Mode()&os.ModeSymlink != 0 || !lstat.Mode().IsRegular() {
		return nil, InputStats{}, fmt.Errorf("inspect %s", name)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, InputStats{}, fmt.Errorf("open %s", name)
	}
	info, digest, err := digestOpenFile(file)
	if err != nil {
		_ = file.Close()
		return nil, InputStats{}, fmt.Errorf("fingerprint %s", name)
	}
	if !os.SameFile(lstat, info) || info.Mode().Perm()&0o077 != 0 {
		_ = file.Close()
		return nil, InputStats{}, fmt.Errorf("%s changed while opening", name)
	}
	return file, InputStats{Filename: name, SizeBytes: info.Size(), SHA256: digest, openedModTimeNS: info.ModTime().UnixNano()}, nil
}

func verifyInput(file *os.File, path string, original InputStats) error {
	resolved, err := canonicalExistingPath(path)
	if err != nil || resolved != filepath.Clean(path) || insideGitWorktree(resolved) {
		return ErrInputChanged
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return ErrInputChanged
	}
	info, digest, err := digestOpenFile(file)
	if err != nil || info.Size() != original.SizeBytes || info.ModTime().UnixNano() != original.openedModTimeNS || digest != original.SHA256 {
		return ErrInputChanged
	}
	afterHash, err := file.Stat()
	if err != nil || afterHash.Size() != info.Size() || afterHash.ModTime() != info.ModTime() {
		return ErrInputChanged
	}
	pathInfo, err := os.Lstat(path)
	if err != nil || pathInfo.Mode()&os.ModeSymlink != 0 || pathInfo.Mode().Perm()&0o077 != 0 || !os.SameFile(info, pathInfo) {
		return ErrInputChanged
	}
	return nil
}

func writeManifest(path string, manifest Manifest, budget *budgets) error {
	encoded, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return errors.New("encode manifest")
	}
	encoded = append(encoded, '\n')
	if err := budget.addOutput(int64(len(encoded))); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return errors.New("create manifest")
	}
	if err := file.Chmod(0o600); err != nil {
		return errors.Join(errors.New("secure manifest"), closeAndRemove(file, path))
	}
	if _, err := file.Write(encoded); err != nil {
		return errors.Join(errors.New("write manifest"), closeAndRemove(file, path))
	}
	if err := file.Sync(); err != nil {
		return errors.Join(errors.New("sync manifest"), closeAndRemove(file, path))
	}
	if err := file.Close(); err != nil {
		return errors.Join(errors.New("close manifest"), removeFile(path))
	}
	return nil
}

func writeCompletionMarker(path string, budget *budgets) error {
	content := []byte(ManifestSchemaVersion + "\n")
	if err := budget.addOutput(int64(len(content))); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return errors.New("create completion marker")
	}
	if err := file.Chmod(0o600); err != nil {
		return errors.Join(errors.New("secure completion marker"), closeAndRemove(file, path))
	}
	if _, err := file.Write(content); err != nil {
		return errors.Join(errors.New("write completion marker"), closeAndRemove(file, path))
	}
	if err := file.Sync(); err != nil {
		return errors.Join(errors.New("sync completion marker"), closeAndRemove(file, path))
	}
	if err := file.Close(); err != nil {
		return errors.Join(errors.New("close completion marker"), removeFile(path))
	}
	return nil
}

func closeAndRemove(file *os.File, path string) error {
	return errors.Join(file.Close(), removeFile(path))
}

func removeFile(path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("%w: remove incomplete output file", ErrCleanup)
	}
	return nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	err = directory.Sync()
	return errors.Join(err, directory.Close())
}

func digestOpenFile(file *os.File) (os.FileInfo, string, error) {
	info, err := file.Stat()
	if err != nil {
		return nil, "", err
	}
	if !info.Mode().IsRegular() {
		return nil, "", errors.New("not a regular file")
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return nil, "", err
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, "", err
	}
	return info, hex.EncodeToString(hash.Sum(nil)), nil
}

type consumedInput struct {
	reader io.Reader
	hash   hash.Hash
	bytes  int64
}

func newConsumedInput(reader io.Reader) *consumedInput {
	return &consumedInput{reader: reader, hash: sha256.New()}
}

func (reader *consumedInput) Read(p []byte) (int, error) {
	n, err := reader.reader.Read(p)
	if n > 0 {
		_, _ = reader.hash.Write(p[:n])
		reader.bytes += int64(n)
	}
	return n, err
}

func (reader *consumedInput) digest() string {
	return hex.EncodeToString(reader.hash.Sum(nil))
}

func gzipScanner(file io.Reader, maxLineBytes int, budget *budgets) (*bufio.Scanner, *gzip.Reader, error) {
	reader, err := gzip.NewReader(file)
	if err != nil {
		return nil, nil, errors.New("invalid gzip stream")
	}
	scanner := bufio.NewScanner(&budgetReader{reader: reader, budget: budget})
	initialBuffer := 64 << 10
	if maxLineBytes < initialBuffer {
		initialBuffer = maxLineBytes
	}
	scanner.Buffer(make([]byte, initialBuffer), maxLineBytes)
	return scanner, reader, nil
}
