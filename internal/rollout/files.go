package rollout

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/palisade-bot-defense/palisade/internal/shadowanalysis"
)

const (
	maximumPlanBytes           = 64 << 10
	maximumReviewBytes         = 64 << 10
	maximumAnalysisReportBytes = 1 << 20
)

func GenerateKeyPair(privatePath, publicPath string) error {
	if privatePath == "" || publicPath == "" || privatePath == publicPath {
		return errors.New("distinct rollout private and public key paths are required")
	}
	privatePath, err := safeNewPath(privatePath)
	if err != nil {
		return err
	}
	publicPath, err = safeNewPath(publicPath)
	if err != nil {
		return err
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	if err := writeExclusive(privatePath, []byte(base64.RawURLEncoding.EncodeToString(privateKey)+"\n"), 0o600); err != nil {
		return err
	}
	if err := writeExclusive(publicPath, []byte(base64.RawURLEncoding.EncodeToString(publicKey)+"\n"), 0o600); err != nil {
		_ = os.Remove(privatePath)
		return err
	}
	return nil
}

func ReadPrivateKey(path string) (ed25519.PrivateKey, error) {
	encoded, err := readKeyFile(path, ed25519.PrivateKeySize)
	if err != nil {
		return nil, err
	}
	return ed25519.PrivateKey(encoded), nil
}

func ReadPublicKey(path string) (ed25519.PublicKey, error) {
	encoded, err := readKeyFile(path, ed25519.PublicKeySize)
	if err != nil {
		return nil, err
	}
	return ed25519.PublicKey(encoded), nil
}

func ReadSignedPlan(path string) (SignedPlan, error) {
	var signed SignedPlan
	data, err := readRegular(path, maximumPlanBytes, true)
	if err != nil {
		return signed, err
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&signed); err != nil {
		return signed, errors.New("invalid signed rollout plan JSON")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return SignedPlan{}, errors.New("multiple rollout plan JSON values")
	}
	return signed, nil
}

func WriteSignedPlan(path string, signed SignedPlan) error {
	resolved, err := safeNewPath(path)
	if err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(signed, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	return writeExclusive(resolved, encoded, 0o600)
}

func ReadReviewProposal(path string) (ReviewProposal, error) {
	var proposal ReviewProposal
	data, err := readRegular(path, maximumReviewBytes, true)
	if err != nil {
		return proposal, err
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&proposal); err != nil {
		return ReviewProposal{}, errors.New("invalid rollout review proposal JSON")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ReviewProposal{}, errors.New("multiple rollout review proposal JSON values")
	}
	if err := proposal.Validate(); err != nil {
		return ReviewProposal{}, err
	}
	return proposal, nil
}

func WriteReviewProposal(path string, proposal ReviewProposal) error {
	if err := proposal.Validate(); err != nil {
		return err
	}
	resolved, err := safeNewPath(path)
	if err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(proposal, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	if len(encoded) > maximumReviewBytes {
		return errors.New("rollout review proposal exceeds its size limit")
	}
	return writeExclusive(resolved, encoded, 0o600)
}

func ReadAnalysisReport(path string) (shadowReportBytes []byte, report shadowanalysis.Report, err error) {
	data, err := readRegular(path, maximumAnalysisReportBytes, true)
	if err != nil {
		return nil, report, err
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&report); err != nil {
		return nil, report, errors.New("invalid shadow analysis report JSON")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, shadowanalysis.Report{}, errors.New("multiple analysis report JSON values")
	}
	return data, report, nil
}

func WriteAnalysisReport(path string, report shadowanalysis.Report) error {
	resolved, err := safeNewPath(path)
	if err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	return writeExclusive(resolved, encoded, 0o600)
}

// ReplaceAnalysisReport publishes a validated aggregate report atomically in
// an owner-controlled directory. It is intentionally separate from the
// exclusive writer used for signed rollout inputs.
func ReplaceAnalysisReport(path string, report shadowanalysis.Report) (returnErr error) {
	if err := shadowanalysis.ValidateReport(report); err != nil {
		return errors.New("refusing to publish invalid shadow analysis report")
	}
	target, previous, err := safeReplacePath(path)
	if err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	if len(encoded) > maximumAnalysisReportBytes {
		return errors.New("shadow analysis report exceeds its size limit")
	}
	parent := filepath.Dir(target)
	temporary, err := os.CreateTemp(parent, ".palisade-analysis-*.tmp")
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
			return errors.New("analysis report target changed before publication")
		}
	} else if err != nil || !os.SameFile(previous, current) || current.Mode() != previous.Mode() || current.Size() != previous.Size() || !current.ModTime().Equal(previous.ModTime()) {
		return errors.New("analysis report target changed before publication")
	}
	if err := os.Rename(temporaryPath, target); err != nil {
		return err
	}
	if err := syncDirectory(parent); err != nil {
		return err
	}
	return nil
}

func readKeyFile(path string, expectedBytes int) ([]byte, error) {
	data, err := readRegular(path, 1024, true)
	if err != nil {
		return nil, err
	}
	decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimSuffix(string(data), "\n"))
	if err != nil || len(decoded) != expectedBytes {
		return nil, errors.New("invalid rollout key encoding or length")
	}
	return decoded, nil
}

func readRegular(path string, maximum int64, ownerOnly bool) ([]byte, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != filepath.Clean(path) {
		return nil, errors.New("rollout input path must be canonical and contain no symlinks")
	}
	info, err := os.Lstat(resolved)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > maximum || (ownerOnly && info.Mode().Perm()&0o077 != 0) {
		return nil, errors.New("rollout input must be a bounded owner-only regular file")
	}
	if insideWorktree(resolved) {
		return nil, errors.New("rollout keys, reports and plans must remain outside every Git worktree")
	}
	parentInfo, err := os.Stat(filepath.Dir(resolved))
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("rollout input parent must be an owner-only directory")
	}
	file, err := os.Open(resolved)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, errors.New("rollout input changed while opening")
	}
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(data)) > maximum {
		return nil, errors.New("rollout input exceeded its size limit")
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(info, after) || after.Size() != int64(len(data)) || after.Mode() != info.Mode() || !after.ModTime().Equal(info.ModTime()) {
		return nil, errors.New("rollout input changed while reading")
	}
	return data, nil
}

func safeNewPath(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(absolute))
	if err != nil || parent != filepath.Clean(filepath.Dir(absolute)) {
		return "", errors.New("rollout output parent must be canonical and contain no symlinks")
	}
	info, err := os.Stat(parent)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return "", errors.New("rollout output parent must be an owner-only directory")
	}
	resolved := filepath.Join(parent, filepath.Base(absolute))
	if insideWorktree(resolved) {
		return "", errors.New("rollout keys, reports and plans must remain outside every Git worktree")
	}
	if _, err := os.Lstat(resolved); !errors.Is(err, os.ErrNotExist) {
		return "", errors.New("rollout output already exists")
	}
	return resolved, nil
}

func safeReplacePath(path string) (string, os.FileInfo, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", nil, err
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(absolute))
	if err != nil || parent != filepath.Clean(filepath.Dir(absolute)) {
		return "", nil, errors.New("analysis report parent must be canonical and contain no symlinks")
	}
	parentInfo, err := os.Stat(parent)
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode().Perm()&0o077 != 0 {
		return "", nil, errors.New("analysis report parent must be an owner-only directory")
	}
	target := filepath.Join(parent, filepath.Base(absolute))
	if insideWorktree(target) {
		return "", nil, errors.New("analysis report must remain outside every Git worktree")
	}
	info, err := os.Lstat(target)
	if errors.Is(err, os.ErrNotExist) {
		return target, nil, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 {
		return "", nil, errors.New("existing analysis report must be a 0600 regular file")
	}
	resolved, err := filepath.EvalSymlinks(target)
	if err != nil || resolved != target {
		return "", nil, errors.New("analysis report target must be canonical and contain no symlinks")
	}
	return target, info, nil
}

func writeExclusive(path string, data []byte, mode os.FileMode) (returnErr error) {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	defer func() {
		if returnErr != nil {
			_ = file.Close()
			_ = os.Remove(path)
		}
	}()
	if err := file.Chmod(mode); err != nil {
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
	err = directory.Sync()
	return errors.Join(err, directory.Close())
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

func ParseDurationFromNow(value string, now time.Time) (time.Time, error) {
	duration, err := time.ParseDuration(value)
	if err != nil || duration <= 0 {
		return time.Time{}, fmt.Errorf("invalid rollout duration %q", value)
	}
	return now.UTC().Add(duration), nil
}
