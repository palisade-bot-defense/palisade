package localartifact

import (
	"os"
	"path/filepath"
	"testing"
)

func TestArtifactFilesAreOwnerOnlyOutsideWorktreesAndExclusive(t *testing.T) {
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	privatePath := filepath.Join(directory, "artifact.private")
	publicPath := filepath.Join(directory, "artifact.public")
	if err := GenerateKeyPair(privatePath, publicPath); err != nil {
		t.Fatal(err)
	}
	privateKey, err := ReadPrivateKey(privatePath)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := ReadPublicKey(publicPath)
	if err != nil || len(privateKey) != 64 || len(publicKey) != 32 {
		t.Fatalf("keys private=%d public=%d err=%v", len(privateKey), len(publicKey), err)
	}
	output := filepath.Join(directory, "artifact.json")
	if err := WriteDocument(output, []byte("{}\n")); err != nil {
		t.Fatal(err)
	}
	if err := WriteDocument(output, []byte("{}\n")); err == nil {
		t.Fatal("existing artifact was overwritten")
	}
	for _, path := range []string{privatePath, publicPath, output} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("permissions path=%s info=%v err=%v", path, info, err)
		}
	}
	if err := os.Chmod(output, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadDocument(output); err == nil {
		t.Fatal("insecure artifact permissions were accepted")
	}
}

func TestArtifactReaderRejectsSymlinkAndWorktree(t *testing.T) {
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(directory, "target")
	if err := os.WriteFile(target, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadDocument(link); err == nil {
		t.Fatal("symlink input was accepted")
	}
	worktree := filepath.Join(directory, "checkout")
	if err := os.MkdirAll(filepath.Join(worktree, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	inside := filepath.Join(worktree, "artifact.json")
	if err := os.WriteFile(inside, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadDocument(inside); err == nil {
		t.Fatal("artifact inside a Git worktree was accepted")
	}
}
