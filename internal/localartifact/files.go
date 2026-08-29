package localartifact

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func GenerateKeyPair(privatePath, publicPath string) error {
	if privatePath == "" || publicPath == "" || privatePath == publicPath {
		return errors.New("distinct local artifact private and public key paths are required")
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
	if err := writeExclusive(privatePath, []byte(base64.RawURLEncoding.EncodeToString(privateKey)+"\n")); err != nil {
		return err
	}
	if err := writeExclusive(publicPath, []byte(base64.RawURLEncoding.EncodeToString(publicKey)+"\n")); err != nil {
		_ = os.Remove(privatePath)
		return err
	}
	return nil
}

func ReadDocument(path string) ([]byte, error) {
	return readOwnerOnly(path, MaximumDocumentBytes)
}

func ReadPublicKey(path string) (ed25519.PublicKey, error) {
	data, err := readOwnerOnly(path, 1024)
	if err != nil {
		return nil, err
	}
	decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimSuffix(string(data), "\n"))
	if err != nil || len(decoded) != ed25519.PublicKeySize {
		return nil, errors.New("invalid local artifact public key")
	}
	return ed25519.PublicKey(decoded), nil
}

func ReadPrivateKey(path string) (ed25519.PrivateKey, error) {
	data, err := readOwnerOnly(path, 1024)
	if err != nil {
		return nil, err
	}
	decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimSuffix(string(data), "\n"))
	if err != nil || len(decoded) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid local artifact private key")
	}
	return ed25519.PrivateKey(decoded), nil
}

func WriteDocument(path string, data []byte) error {
	if len(data) == 0 || len(data) > MaximumDocumentBytes {
		return errors.New("invalid local artifact document size")
	}
	resolved, err := safeNewPath(path)
	if err != nil {
		return err
	}
	return writeExclusive(resolved, data)
}

func readOwnerOnly(path string, maximum int64) ([]byte, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != filepath.Clean(path) {
		return nil, errors.New("local artifact input path must be canonical and contain no symlinks")
	}
	info, err := os.Lstat(resolved)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() < 1 || info.Size() > maximum || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("local artifact input must be a bounded owner-only regular file")
	}
	if insideWorktree(resolved) {
		return nil, errors.New("local artifacts and keys must remain outside every Git worktree")
	}
	parent, err := os.Stat(filepath.Dir(resolved))
	if err != nil || !parent.IsDir() || parent.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("local artifact input parent must be an owner-only directory")
	}
	file, err := os.Open(resolved)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, errors.New("local artifact input changed while opening")
	}
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(data)) > maximum {
		return nil, errors.New("local artifact input exceeded its size limit")
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(info, after) || after.Size() != int64(len(data)) || after.Mode() != info.Mode() || !after.ModTime().Equal(info.ModTime()) {
		return nil, errors.New("local artifact input changed while reading")
	}
	return data, nil
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

func safeNewPath(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(absolute))
	if err != nil || parent != filepath.Clean(filepath.Dir(absolute)) {
		return "", errors.New("local artifact output parent must be canonical and contain no symlinks")
	}
	info, err := os.Stat(parent)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return "", errors.New("local artifact output parent must be an owner-only directory")
	}
	resolved := filepath.Join(parent, filepath.Base(absolute))
	if insideWorktree(resolved) {
		return "", errors.New("local artifacts and keys must remain outside every Git worktree")
	}
	if _, err := os.Lstat(resolved); !errors.Is(err, os.ErrNotExist) {
		return "", errors.New("local artifact output already exists")
	}
	return resolved, nil
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
	if written, err := file.Write(data); err != nil || written != len(data) {
		if err == nil {
			err = io.ErrShortWrite
		}
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	return file.Close()
}
