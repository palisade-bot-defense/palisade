package crawlerregistryops

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/palisade-bot-defense/palisade/internal/rollout"
	"github.com/palisade-bot-defense/palisade/pkg/palisadehttp"
)

const (
	maximumRegistryBytes = int64(1 << 20)
	minimumLifetime      = 10 * time.Minute
	maximumLifetime      = 31 * 24 * time.Hour
)

var ErrInvalidOperation = errors.New("invalid crawler registry operation")

type SignConfig struct {
	EntriesPath    string
	PrivateKeyPath string
	OutputPath     string
	Revision       uint64
	Lifetime       time.Duration
}

func GenerateKeyPair(privatePath, publicPath string) error {
	return rollout.GenerateKeyPair(privatePath, publicPath)
}

func SignAndPublish(config SignConfig, now time.Time) (palisadehttp.CrawlerRegistryStatus, error) {
	if config.EntriesPath == "" || config.PrivateKeyPath == "" || config.OutputPath == "" || config.Revision == 0 ||
		config.Lifetime < minimumLifetime || config.Lifetime > maximumLifetime {
		return palisadehttp.CrawlerRegistryStatus{}, ErrInvalidOperation
	}
	entries, err := readEntries(config.EntriesPath)
	if err != nil {
		return palisadehttp.CrawlerRegistryStatus{}, err
	}
	privateKey, err := rollout.ReadPrivateKey(config.PrivateKeyPath)
	if err != nil {
		return palisadehttp.CrawlerRegistryStatus{}, err
	}
	defer clear(privateKey)
	now = now.UTC().Truncate(time.Second)
	payload := palisadehttp.CrawlerRegistryPayload{
		SchemaVersion: palisadehttp.CrawlerRegistrySchemaVersion,
		Revision:      config.Revision,
		IssuedAt:      now.Format(time.RFC3339),
		ExpiresAt:     now.Add(config.Lifetime).Format(time.RFC3339),
		Entries:       entries,
	}
	encoded, err := palisadehttp.EncodeSignedCrawlerRegistry(payload, privateKey)
	if err != nil {
		return palisadehttp.CrawlerRegistryStatus{}, err
	}
	publicKey := privateKey.Public().(ed25519.PublicKey)
	status, err := palisadehttp.InspectSignedCrawlerRegistryJSON(encoded, publicKey, now)
	if err != nil {
		return palisadehttp.CrawlerRegistryStatus{}, err
	}
	if err := publishSignedRegistry(config.OutputPath, encoded, publicKey, status.Revision, now); err != nil {
		return palisadehttp.CrawlerRegistryStatus{}, err
	}
	return status, nil
}

func Inspect(registryPath, publicKeyPath string, now time.Time) (palisadehttp.CrawlerRegistryStatus, error) {
	if registryPath == "" || publicKeyPath == "" {
		return palisadehttp.CrawlerRegistryStatus{}, ErrInvalidOperation
	}
	encoded, _, err := readSecureRegular(registryPath, maximumRegistryBytes)
	if err != nil {
		return palisadehttp.CrawlerRegistryStatus{}, err
	}
	publicKey, err := rollout.ReadPublicKey(publicKeyPath)
	if err != nil {
		return palisadehttp.CrawlerRegistryStatus{}, err
	}
	return palisadehttp.InspectSignedCrawlerRegistryJSON(encoded, publicKey, now.UTC())
}

func readEntries(path string) ([]palisadehttp.CrawlerIdentity, error) {
	data, _, err := readSecureRegular(path, maximumRegistryBytes)
	if err != nil {
		return nil, err
	}
	var entries []palisadehttp.CrawlerIdentity
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&entries); err != nil {
		return nil, errors.New("invalid crawler registry entries JSON")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("multiple crawler registry entries JSON values")
	}
	if entries == nil {
		return nil, errors.New("crawler registry entries must be a non-empty array")
	}
	return entries, nil
}

func publishSignedRegistry(path string, encoded []byte, publicKey ed25519.PublicKey, revision uint64, now time.Time) (returnErr error) {
	target, previous, previousBytes, err := safeRegistryTarget(path)
	if err != nil {
		return err
	}
	if previous != nil {
		status, err := palisadehttp.InspectSignedCrawlerRegistryJSON(previousBytes, publicKey, now)
		if err != nil {
			return errors.New("existing crawler registry was not signed by this key")
		}
		if revision <= status.Revision {
			return errors.New("crawler registry revision must increase")
		}
	}
	parent := filepath.Dir(target)
	temporary, err := os.CreateTemp(parent, ".palisade-crawler-registry-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer func() {
		if returnErr != nil {
			_ = temporary.Close()
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return err
	}
	if written, err := temporary.Write(encoded); err != nil || written != len(encoded) {
		if err == nil {
			err = io.ErrShortWrite
		}
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	current, err := os.Lstat(target)
	if previous == nil {
		if !errors.Is(err, os.ErrNotExist) {
			return errors.New("crawler registry target changed before publication")
		}
	} else if err != nil || !os.SameFile(previous, current) || current.Mode() != previous.Mode() || current.Size() != previous.Size() || !current.ModTime().Equal(previous.ModTime()) {
		return errors.New("crawler registry target changed before publication")
	}
	if err := os.Rename(temporaryPath, target); err != nil {
		return err
	}
	return syncDirectory(parent)
}

func safeRegistryTarget(path string) (string, os.FileInfo, []byte, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", nil, nil, err
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(absolute))
	if err != nil || parent != filepath.Clean(filepath.Dir(absolute)) {
		return "", nil, nil, errors.New("crawler registry output parent must be canonical and contain no symlinks")
	}
	parentInfo, err := os.Stat(parent)
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode().Perm()&0o077 != 0 {
		return "", nil, nil, errors.New("crawler registry output parent must be owner-only")
	}
	target := filepath.Join(parent, filepath.Base(absolute))
	if insideWorktree(target) {
		return "", nil, nil, errors.New("crawler registry artifacts must remain outside every Git worktree")
	}
	info, err := os.Lstat(target)
	if errors.Is(err, os.ErrNotExist) {
		return target, nil, nil, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 || info.Size() < 1 || info.Size() > maximumRegistryBytes {
		return "", nil, nil, errors.New("existing crawler registry must be a bounded 0600 regular file")
	}
	resolved, err := filepath.EvalSymlinks(target)
	if err != nil || resolved != target {
		return "", nil, nil, errors.New("crawler registry target must be canonical and contain no symlinks")
	}
	data, opened, err := readSecureRegular(target, maximumRegistryBytes)
	if err != nil || !os.SameFile(info, opened) {
		return "", nil, nil, errors.New("crawler registry target changed while reading")
	}
	return target, info, data, nil
}

func readSecureRegular(path string, maximum int64) ([]byte, os.FileInfo, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != filepath.Clean(path) {
		return nil, nil, errors.New("crawler registry input path must be canonical and contain no symlinks")
	}
	info, err := os.Lstat(resolved)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 || info.Size() < 1 || info.Size() > maximum {
		return nil, nil, errors.New("crawler registry input must be a bounded owner-only regular file")
	}
	if insideWorktree(resolved) {
		return nil, nil, errors.New("crawler registry artifacts must remain outside every Git worktree")
	}
	parentInfo, err := os.Stat(filepath.Dir(resolved))
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode().Perm()&0o077 != 0 {
		return nil, nil, errors.New("crawler registry input parent must be owner-only")
	}
	file, err := os.Open(resolved)
	if err != nil {
		return nil, nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, nil, errors.New("crawler registry input changed while opening")
	}
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(data)) > maximum {
		return nil, nil, errors.New("crawler registry input exceeded its size limit")
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(info, after) || after.Size() != int64(len(data)) || after.Mode() != info.Mode() || !after.ModTime().Equal(info.ModTime()) {
		return nil, nil, errors.New("crawler registry input changed while reading")
	}
	return data, info, nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	return errors.Join(directory.Sync(), directory.Close())
}

func insideWorktree(path string) bool {
	current := filepath.Dir(path)
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
