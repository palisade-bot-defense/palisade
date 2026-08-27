package rollout

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/palisade-bot-defense/palisade/internal/shadowanalysis"
)

func TestKeyPairAndSignedPlanFiles(t *testing.T) {
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	privatePath := filepath.Join(directory, "approval.private")
	publicPath := filepath.Join(directory, "approval.public")
	if err := GenerateKeyPair(privatePath, publicPath); err != nil {
		t.Fatal(err)
	}
	privateKey, err := ReadPrivateKey(privatePath)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := ReadPublicKey(publicPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(privateKey) != 64 || len(publicKey) != 32 {
		t.Fatalf("unexpected key lengths: private=%d public=%d", len(privateKey), len(publicKey))
	}
	for _, path := range []string{privatePath, publicPath} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("key permissions for %s: info=%v err=%v", path, info, err)
		}
	}
	if err := GenerateKeyPair(privatePath, publicPath); err == nil {
		t.Fatal("existing key pair was overwritten")
	}
}

func TestAnalysisReportFileIsOwnerOnlyAndCannotBeOverwritten(t *testing.T) {
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "analysis.json")
	report := shadowanalysis.Report{SchemaVersion: shadowanalysis.SchemaVersion}
	if err := WriteAnalysisReport(path, report); err != nil {
		t.Fatal(err)
	}
	data, decoded, err := ReadAnalysisReport(path)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.SchemaVersion != shadowanalysis.SchemaVersion || !json.Valid(data) {
		t.Fatalf("invalid report round trip: %+v %q", decoded, data)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("report permissions: info=%v err=%v", info, err)
	}
	if err := WriteAnalysisReport(path, report); err == nil {
		t.Fatal("existing report was overwritten")
	}
}
