package rollout

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/palisade-human-trust/palisade/internal/core"
	"github.com/palisade-human-trust/palisade/internal/shadowanalysis"
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

func TestReviewProposalFileIsOwnerOnlyClosedAndCannotBeOverwritten(t *testing.T) {
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	report := candidateReport(2000, 0)
	reportBytes := encodedReport(t, report)
	proposal, err := BuildReviewProposal(report, reportBytes, ReviewOptions{Stage: core.RuntimeModeCanary})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "review.json")
	if err := WriteReviewProposal(path, proposal); err != nil {
		t.Fatal(err)
	}
	decoded, err := ReadReviewProposal(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decoded, proposal) {
		t.Fatalf("proposal round trip differs: decoded=%+v proposal=%+v", decoded, proposal)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("proposal permissions: info=%v err=%v", info, err)
	}
	if err := WriteReviewProposal(path, proposal); err == nil {
		t.Fatal("existing review proposal was overwritten")
	}
	if err := os.WriteFile(path, append([]byte(`{"unknown":true}`), '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadReviewProposal(path); err == nil {
		t.Fatal("unknown review proposal fields were accepted")
	}
}

func TestAnalysisReportCanBeAtomicallyReplacedButNotRedirected(t *testing.T) {
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "analysis.json")
	first := candidateReport(1000, 0)
	first.Source.FirstAt = "2026-08-26T00:00:00Z"
	first.Source.LastAt = "2026-08-27T00:00:00Z"
	if err := ReplaceAnalysisReport(path, first); err != nil {
		t.Fatal(err)
	}
	second := candidateReport(2000, 0)
	if err := ReplaceAnalysisReport(path, second); err != nil {
		t.Fatal(err)
	}
	_, decoded, err := ReadAnalysisReport(path)
	if err != nil || decoded.Decisions.Total != 2000 {
		t.Fatalf("replacement report = %+v, %v", decoded, err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("replacement permissions = %v, %v", info, err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(directory, "elsewhere"), path); err != nil {
		t.Fatal(err)
	}
	if err := ReplaceAnalysisReport(path, second); err == nil {
		t.Fatal("symlink target was replaced")
	}
}
