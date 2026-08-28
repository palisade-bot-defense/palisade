package crawlerregistryops

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSignPublishInspectAndMonotonicReplacement(t *testing.T) {
	directory := canonicalPrivateTempDir(t)
	privatePath := filepath.Join(directory, "crawler.private")
	publicPath := filepath.Join(directory, "crawler.public")
	entriesPath := filepath.Join(directory, "entries.json")
	registryPath := filepath.Join(directory, "registry.json")
	if err := GenerateKeyPair(privatePath, publicPath); err != nil {
		t.Fatal(err)
	}
	writeEntries(t, entriesPath, 0o600)
	now := time.Date(2026, time.August, 28, 12, 0, 0, 0, time.UTC)
	status, err := SignAndPublish(SignConfig{
		EntriesPath: entriesPath, PrivateKeyPath: privatePath, OutputPath: registryPath,
		Revision: 1, Lifetime: 7 * 24 * time.Hour,
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if status.State != "current" || status.Revision != 1 || status.IdentityCount != 1 || status.PrefixCount != 1 || len(status.DigestSHA256) != 64 {
		t.Fatalf("signed status=%+v", status)
	}
	info, err := os.Stat(registryPath)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("registry mode=%v error=%v", info, err)
	}
	inspected, err := Inspect(registryPath, publicPath, now)
	if err != nil || inspected != status {
		t.Fatalf("inspected=%+v status=%+v error=%v", inspected, status, err)
	}
	status, err = SignAndPublish(SignConfig{
		EntriesPath: entriesPath, PrivateKeyPath: privatePath, OutputPath: registryPath,
		Revision: 2, Lifetime: 24 * time.Hour,
	}, now.Add(8*24*time.Hour))
	if err != nil || status.Revision != 2 {
		t.Fatalf("replacement status=%+v error=%v", status, err)
	}
	if _, err := SignAndPublish(SignConfig{
		EntriesPath: entriesPath, PrivateKeyPath: privatePath, OutputPath: registryPath,
		Revision: 2, Lifetime: 24 * time.Hour,
	}, now.Add(8*24*time.Hour)); err == nil || err.Error() != "crawler registry revision must increase" {
		t.Fatalf("non-increasing revision error=%v", err)
	}
}

func TestOperationsRejectUnsafeFilesAndInvalidInputs(t *testing.T) {
	directory := canonicalPrivateTempDir(t)
	privatePath := filepath.Join(directory, "crawler.private")
	publicPath := filepath.Join(directory, "crawler.public")
	if err := GenerateKeyPair(privatePath, publicPath); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.August, 28, 12, 0, 0, 0, time.UTC)
	for name, contents := range map[string]string{
		"unknown field": `[{"name":"example-search","class":"search_indexer","user_agent_tokens":["ExampleSearchBot"],"cidrs":["192.0.2.0/24"],"raw":"no"}]`,
		"empty array":   `[]`,
		"trailing":      `[] {}`,
	} {
		t.Run(name, func(t *testing.T) {
			entriesPath := filepath.Join(directory, name+".json")
			if err := os.WriteFile(entriesPath, []byte(contents), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := SignAndPublish(SignConfig{
				EntriesPath: entriesPath, PrivateKeyPath: privatePath, OutputPath: filepath.Join(directory, name+".signed"),
				Revision: 1, Lifetime: time.Hour,
			}, now)
			if err == nil {
				t.Fatal("unsafe entries accepted")
			}
		})
	}
	insecure := filepath.Join(directory, "insecure.json")
	writeEntries(t, insecure, 0o644)
	if _, err := SignAndPublish(SignConfig{
		EntriesPath: insecure, PrivateKeyPath: privatePath, OutputPath: filepath.Join(directory, "insecure.signed"),
		Revision: 1, Lifetime: time.Hour,
	}, now); err == nil {
		t.Fatal("group-readable entries accepted")
	}
	if _, err := SignAndPublish(SignConfig{
		EntriesPath: insecure, PrivateKeyPath: privatePath, OutputPath: filepath.Join(directory, "short.signed"),
		Revision: 1, Lifetime: time.Minute,
	}, now); !errors.Is(err, ErrInvalidOperation) {
		t.Fatalf("short lifetime error=%v", err)
	}

	_, otherPrivate, _ := ed25519.GenerateKey(rand.Reader)
	otherKeyPath := filepath.Join(directory, "other.private")
	if err := os.WriteFile(otherKeyPath, []byte(base64.RawURLEncoding.EncodeToString(otherPrivate)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	entriesPath := filepath.Join(directory, "valid.json")
	writeEntries(t, entriesPath, 0o600)
	registryPath := filepath.Join(directory, "wrong-signer.json")
	if _, err := SignAndPublish(SignConfig{EntriesPath: entriesPath, PrivateKeyPath: privatePath, OutputPath: registryPath, Revision: 1, Lifetime: time.Hour}, now); err != nil {
		t.Fatal(err)
	}
	if _, err := SignAndPublish(SignConfig{EntriesPath: entriesPath, PrivateKeyPath: otherKeyPath, OutputPath: registryPath, Revision: 2, Lifetime: time.Hour}, now); err == nil {
		t.Fatal("different signer replaced registry")
	}
}

func TestOperationsRejectGitWorktreeAndSymlinkTargets(t *testing.T) {
	directory := canonicalPrivateTempDir(t)
	worktree := filepath.Join(directory, "worktree")
	if err := os.Mkdir(worktree, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(worktree, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	entriesPath := filepath.Join(worktree, "entries.json")
	writeEntries(t, entriesPath, 0o600)
	if _, _, err := readSecureRegular(entriesPath, maximumRegistryBytes); err == nil {
		t.Fatal("worktree input accepted")
	}

	outside := filepath.Join(directory, "outside.json")
	writeEntries(t, outside, 0o600)
	symlink := filepath.Join(directory, "link.json")
	if err := os.Symlink(outside, symlink); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readSecureRegular(symlink, maximumRegistryBytes); err == nil {
		t.Fatal("symlink input accepted")
	}
}

func canonicalPrivateTempDir(t *testing.T) string {
	t.Helper()
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	return directory
}

func writeEntries(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	contents := `[{"name":"example-search","class":"search_indexer","user_agent_tokens":["ExampleSearchBot"],"cidrs":["192.0.2.0/24"]}]`
	if err := os.WriteFile(path, []byte(contents), mode); err != nil {
		t.Fatal(err)
	}
}
