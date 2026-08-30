package offlineimport

import (
	"crypto/sha256"
	"encoding/hex"
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

func fileDigest(path string) (os.FileInfo, string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, "", err
	}
	defer file.Close()
	return digestOpenFile(file)
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
