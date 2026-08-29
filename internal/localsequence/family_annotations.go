package localsequence

import (
	"bufio"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/palisade-bot-defense/palisade/internal/offlineimport"
)

type familyIndex struct {
	assignments map[[32]byte][32]byte
	records     uint64
	bytes       int64
	sha256      string
}

type countedHashReader struct {
	reader io.Reader
	digest hash.Hash
	bytes  int64
}

func (reader *countedHashReader) Read(buffer []byte) (int, error) {
	count, err := reader.reader.Read(buffer)
	if count > 0 {
		reader.bytes += int64(count)
		_, _ = reader.digest.Write(buffer[:count])
	}
	return count, err
}

func loadFamilyAnnotations(path string, config HoldoutConfig) (familyIndex, error) {
	index := familyIndex{assignments: make(map[[32]byte][32]byte)}
	if path == "" {
		return index, nil
	}
	resolved, initial, err := privateFamilyInput(path)
	if err != nil {
		return index, err
	}
	if initial.Size() > config.MaxFamilyBytes {
		return index, ErrFamilyAnnotationBudget
	}
	file, err := os.Open(resolved)
	if err != nil {
		return index, errors.New("open local family annotations")
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(initial, opened) {
		return index, errors.New("local family annotations changed while opening")
	}
	firstBytes, firstHash, err := fingerprintFamilyFile(file, config.MaxFamilyBytes)
	if err != nil {
		return index, err
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return index, errors.New("rewind local family annotations")
	}
	consumed := &countedHashReader{reader: io.LimitReader(file, config.MaxFamilyBytes+1), digest: sha256.New()}
	scanner := bufio.NewScanner(consumed)
	bufferSize := config.MaxFamilyLineBytes
	if bufferSize > 64<<10 {
		bufferSize = 64 << 10
	}
	scanner.Buffer(make([]byte, bufferSize), config.MaxFamilyLineBytes)
	for scanner.Scan() {
		if index.records >= config.MaxFamilyRecords {
			return index, ErrFamilyAnnotationBudget
		}
		var annotation FamilyAnnotation
		if err := offlineimport.DecodeStrictJSON(scanner.Bytes(), &annotation); err != nil || validateFamilyAnnotation(annotation) != nil {
			return index, errors.New("local family annotations violate the closed contract")
		}
		key := sequenceDigest(annotation.SequenceKind + ":" + annotation.SequenceID)
		if _, exists := index.assignments[key]; exists {
			return index, errors.New("local family annotations contain a duplicate sequence assignment")
		}
		index.assignments[key] = sha256.Sum256([]byte("palisade-family-v1\x00" + annotation.FamilyRef))
		index.records++
	}
	if err := scanner.Err(); err != nil {
		return index, errors.New("read local family annotations")
	}
	if consumed.bytes > config.MaxFamilyBytes {
		return index, ErrFamilyAnnotationBudget
	}
	secondHash := hex.EncodeToString(consumed.digest.Sum(nil))
	if consumed.bytes != firstBytes || secondHash != firstHash {
		return index, errors.New("local family annotations changed while reading")
	}
	final, err := file.Stat()
	current, pathErr := os.Lstat(resolved)
	if err != nil || pathErr != nil || !os.SameFile(opened, final) || !os.SameFile(opened, current) ||
		!current.Mode().IsRegular() || current.Mode()&os.ModeSymlink != 0 || current.Mode().Perm() != 0o600 ||
		final.Size() != opened.Size() || !final.ModTime().Equal(opened.ModTime()) {
		return index, errors.New("local family annotations changed while reading")
	}
	index.bytes = consumed.bytes
	index.sha256 = secondHash
	return index, nil
}

func privateFamilyInput(path string) (string, os.FileInfo, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", nil, errors.New("resolve local family annotations")
	}
	clean := filepath.Clean(absolute)
	resolved, err := filepath.EvalSymlinks(clean)
	if err != nil || resolved != clean {
		return "", nil, errors.New("local family annotations must be canonical and contain no symlinks")
	}
	info, err := os.Lstat(resolved)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 {
		return "", nil, errors.New("local family annotations must be an owner-only regular file")
	}
	parent, err := os.Stat(filepath.Dir(resolved))
	if err != nil || !parent.IsDir() || parent.Mode().Perm()&0o077 != 0 {
		return "", nil, errors.New("local family annotation parent must be owner-only")
	}
	if insideGitWorktree(resolved) {
		return "", nil, errors.New("local family annotations must remain outside every Git worktree")
	}
	return resolved, info, nil
}

func fingerprintFamilyFile(file *os.File, maxBytes int64) (int64, string, error) {
	digest := sha256.New()
	written, err := io.Copy(digest, io.LimitReader(file, maxBytes+1))
	if err != nil {
		return 0, "", errors.New("fingerprint local family annotations")
	}
	if written > maxBytes {
		return 0, "", ErrFamilyAnnotationBudget
	}
	return written, hex.EncodeToString(digest.Sum(nil)), nil
}

func validateFamilyAnnotation(annotation FamilyAnnotation) error {
	if annotation.SchemaVersion != FamilyAnnotationSchemaVersion ||
		(annotation.SequenceKind != "subject" && annotation.SequenceKind != "session") || !validSequenceID(annotation.SequenceID) ||
		!validFamilyReference(annotation.FamilyRef) {
		return errors.New("invalid local family annotation")
	}
	return nil
}

func validSequenceID(value string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == 32
}

func validFamilyReference(value string) bool {
	if len(value) < 1 || len(value) > 256 || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func sequenceDigest(key string) [32]byte {
	return sha256.Sum256([]byte("palisade-sequence-key-v1\x00" + key))
}

func (index familyIndex) familyFor(key string) ([32]byte, bool) {
	family, found := index.assignments[sequenceDigest(key)]
	return family, found
}
