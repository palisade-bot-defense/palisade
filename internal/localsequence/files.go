package localsequence

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

func WriteReport(path string, report Report) error {
	if err := ValidateReport(report); err != nil {
		return err
	}
	var encoded bytes.Buffer
	encoder := json.NewEncoder(&encoded)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		return errors.New("encode local sequence report")
	}
	if encoded.Len() > maximumReportBytes {
		return errors.New("local sequence report exceeds its size limit")
	}
	target, err := safeReportPath(path)
	if err != nil {
		return err
	}
	if err := writeExclusive(target, encoded.Bytes()); err != nil {
		return errors.New("write local sequence report")
	}
	if err := syncDirectory(filepath.Dir(target)); err != nil {
		return errors.New("sync local sequence report directory")
	}
	return nil
}

func safeReportPath(path string) (string, error) {
	if path == "" {
		return "", errors.New("local sequence report path is required")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", errors.New("resolve local sequence report path")
	}
	parentPath := filepath.Clean(filepath.Dir(absolute))
	parent, err := filepath.EvalSymlinks(parentPath)
	if err != nil || parent != parentPath {
		return "", errors.New("local sequence report parent must be canonical and contain no symlinks")
	}
	info, err := os.Stat(parent)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return "", errors.New("local sequence report parent must be an owner-only directory")
	}
	target := filepath.Join(parent, filepath.Base(absolute))
	if insideGitWorktree(target) {
		return "", errors.New("local sequence report must remain outside every Git worktree")
	}
	if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
		return "", errors.New("local sequence report already exists")
	}
	return target, nil
}

func writeExclusive(path string, data []byte) (returnErr error) {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer func() {
		if returnErr != nil {
			_ = file.Close()
			_ = os.Remove(path)
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	return file.Close()
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	return errors.Join(directory.Sync(), directory.Close())
}

func insideGitWorktree(path string) bool {
	current := filepath.Clean(path)
	if info, err := os.Stat(current); err != nil || !info.IsDir() {
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
