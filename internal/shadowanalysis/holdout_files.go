package shadowanalysis

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

const maximumShadowHoldoutReportBytes = 2 << 20

func WriteShadowHoldoutReport(path string, report ShadowHoldoutReport) error {
	if err := ValidateShadowHoldoutReport(report); err != nil {
		return err
	}
	var encoded bytes.Buffer
	encoder := json.NewEncoder(&encoded)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil || encoded.Len() > maximumShadowHoldoutReportBytes {
		return errors.New("encode shadow holdout report")
	}
	target, err := safeShadowHoldoutPath(path)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return errors.New("create shadow holdout report")
	}
	remove := true
	defer func() {
		_ = file.Close()
		if remove {
			_ = os.Remove(target)
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		return errors.New("secure shadow holdout report")
	}
	if written, err := file.Write(encoded.Bytes()); err != nil || written != encoded.Len() {
		return errors.New("write shadow holdout report")
	}
	if err := file.Sync(); err != nil {
		return errors.New("sync shadow holdout report")
	}
	if err := file.Close(); err != nil {
		return errors.New("close shadow holdout report")
	}
	directory, err := os.Open(filepath.Dir(target))
	if err != nil {
		return errors.New("open shadow holdout report directory")
	}
	if err := errors.Join(directory.Sync(), directory.Close()); err != nil {
		return errors.New("sync shadow holdout report directory")
	}
	remove = false
	return nil
}

func safeShadowHoldoutPath(path string) (string, error) {
	if path == "" {
		return "", errors.New("shadow holdout output path is required")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", errors.New("resolve shadow holdout output path")
	}
	parentPath := filepath.Clean(filepath.Dir(absolute))
	parent, err := filepath.EvalSymlinks(parentPath)
	if err != nil || parent != parentPath {
		return "", errors.New("shadow holdout output parent must be canonical and contain no symlinks")
	}
	info, err := os.Stat(parent)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return "", errors.New("shadow holdout output parent must be owner-only")
	}
	target := filepath.Join(parent, filepath.Base(absolute))
	if shadowHoldoutInsideWorktree(target) {
		return "", errors.New("shadow holdout report must remain outside every Git worktree")
	}
	if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
		return "", errors.New("shadow holdout report already exists")
	}
	return target, nil
}

func shadowHoldoutInsideWorktree(path string) bool {
	current := filepath.Dir(filepath.Clean(path))
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
