package localsequence

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestWriteReportUsesOwnerOnlyNoReplaceOutput(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("owner-only mode semantics require a Unix filesystem")
	}
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	config, _ := normalizeConfig(Config{})
	report := newAnalyzer(config).report
	path := filepath.Join(parent, "sequence-report.json")
	if err := WriteReport(path, report); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("report mode = %v", info.Mode())
	}
	if err := WriteReport(path, report); err == nil {
		t.Fatal("existing report was overwritten")
	}
	if content, err := os.ReadFile(path); err != nil || len(content) == 0 {
		t.Fatalf("published report is unavailable: bytes=%d error=%v", len(content), err)
	}
}

func TestWriteReportRejectsGitWorktree(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("owner-only mode semantics require a Unix filesystem")
	}
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(parent, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	config, _ := normalizeConfig(Config{})
	if err := WriteReport(filepath.Join(parent, "report.json"), newAnalyzer(config).report); err == nil {
		t.Fatal("Git-contained report was accepted")
	}
}
