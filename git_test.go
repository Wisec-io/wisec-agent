package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
)

// fakeKey looks like an AWS access key to gitleaks once assembled. Spelled out
// as one literal it would trip our own secret scan on this very file, and the
// fix for that is not an allowlist.
var fakeKey = "AKIA" + strings.Repeat("Q", 16)

func TestNormalizeGitleaksReport(t *testing.T) {
	cases := []struct {
		name   string
		report string
		want   string
	}{
		// gitleaks writes the empty result with a trailing newline; it must not
		// be mistaken for findings.
		{"empty array with newline", "[]\n", "[]"},
		{"empty array with whitespace", "  [ ]  ", "[]"},
		{"empty file", "", "[]"},
		{"findings are kept", `[{"Description":"AWS key","File":"a.go"}]`,
			`[{"Description":"AWS key","File":"a.go"}]`},
		// A report that is not an array is withheld, not sent as-is (it could
		// hold anything) and not dropped (that would read as "no secrets").
		{"non-array payload withheld", `{"unexpected":true}`, unreadableGitleaksReport},
	}

	for _, c := range cases {
		if got := normalizeGitleaksReport([]byte(c.report)); got != c.want {
			t.Errorf("%s: normalizeGitleaksReport(%q) = %q, want %q", c.name, c.report, got, c.want)
		}
	}
}

// A gitleaks finding as written with --no-git (without --redact, to prove the
// agent strips the fields itself). Secret, Match and Line hold the credential;
// nothing on the Wisec side reads them, so they must never leave the runner.
var gitleaksFinding = fmt.Sprintf(`[{
  "RuleID": "aws-access-token",
  "Description": "Identified a pattern that may indicate AWS credentials",
  "StartLine": 12, "EndLine": 12, "StartColumn": 15, "EndColumn": 34,
  "Match": "aws_key = \"%[1]s\"",
  "Secret": "%[1]s",
  "Line": "aws_key = \"%[1]s\"",
  "File": "config/settings.py",
  "Commit": "", "Entropy": 3.6, "Author": "Jane", "Email": "jane@example.com",
  "Date": "", "Message": "", "Tags": [], "Fingerprint": "config/settings.py:aws-access-token:12"
}]`, fakeKey)

func TestNormalizeGitleaksReportWithholdsTheSecret(t *testing.T) {
	got := normalizeGitleaksReport([]byte(gitleaksFinding))

	for _, leak := range []string{fakeKey, "jane@example.com", `"Secret"`, `"Match"`, `"Line"`, `"Author"`, `"Email"`} {
		if strings.Contains(got, leak) {
			t.Errorf("redacted report still contains %s: %s", leak, got)
		}
	}

	// What the platform does read must survive: the analysis keys a finding on
	// RuleID and File, and the gate on the report being non-empty.
	var findings []map[string]any
	if err := json.Unmarshal([]byte(got), &findings); err != nil || len(findings) != 1 {
		t.Fatalf("redacted report is not one finding: %v %s", err, got)
	}
	f := findings[0]
	if f["RuleID"] != "aws-access-token" || f["File"] != "config/settings.py" || f["StartLine"] != float64(12) {
		t.Errorf("redaction removed a field the platform needs: %v", f)
	}
	if f["Description"] == nil || f["Fingerprint"] == nil {
		t.Errorf("description and fingerprint must be kept: %v", f)
	}
}

func TestNormalizeGitleaksReportWithholdsNonObjectFindings(t *testing.T) {
	got := normalizeGitleaksReport([]byte(`["` + fakeKey + `"]`))
	if strings.Contains(got, fakeKey) {
		t.Errorf("a non-object finding was passed through: %s", got)
	}
	if got == "[]" {
		t.Error("a finding that cannot be read must still flag the build")
	}
}

// A pipeline that leaves its scanner reports in the working tree must not get
// gitleaks findings for them: the merged SARIF raised four CRITICAL
// generic-api-key on Wisec's own main branch (2026-11-11).
func TestDropFindingsInAgentInputs(t *testing.T) {
	report := []byte(`[
		{"RuleID":"generic-api-key","File":"wisec-scans.sarif"},
		{"RuleID":"generic-api-key","File":"./wisec-scans.sarif"},
		{"RuleID":"generic-api-key","File":"bom.json"},
		{"RuleID":"aws-access-token","File":"deploy/config.yaml"},
		{"RuleID":"generic-api-key","File":"sub/wisec-scans.sarif"}
	]`)
	got := dropFindingsInAgentInputs(report, []string{"./wisec-scans.sarif", "bom.json"})

	var findings []map[string]any
	if err := json.Unmarshal(got, &findings); err != nil {
		t.Fatalf("filtered report is not JSON: %v (%s)", err, got)
	}
	var files []string
	for _, f := range findings {
		files = append(files, f["File"].(string))
	}
	// A source file and a same-named report elsewhere in the tree are kept:
	// only the exact files the agent reads are skipped.
	want := []string{"deploy/config.yaml", "sub/wisec-scans.sarif"}
	if fmt.Sprint(files) != fmt.Sprint(want) {
		t.Fatalf("kept %v, want %v", files, want)
	}
}

func TestDropFindingsInAgentInputsLeavesOtherReportsAlone(t *testing.T) {
	cases := map[string]struct {
		report string
		files  []string
	}{
		"no input files":       {`[{"RuleID":"r","File":"a.sarif"}]`, nil},
		"nothing matches":      {`[{"RuleID":"r","File":"main.go"}]`, []string{"scans.sarif"}},
		"unreadable report":    {`not json`, []string{"scans.sarif"}},
		"finding without file": {`[{"RuleID":"r"}]`, []string{"scans.sarif"}},
	}
	for name, c := range cases {
		got := dropFindingsInAgentInputs([]byte(c.report), c.files)
		if string(got) != c.report {
			t.Errorf("%s: report changed to %s", name, got)
		}
	}
	// The unreadable case must still be withheld downstream, never read as clean.
	if normalizeGitleaksReport(dropFindingsInAgentInputs([]byte("not json"), []string{"x"})) != unreadableGitleaksReport {
		t.Error("an unreadable report must stay flagged after filtering")
	}
}

func TestAllFindingsInAgentInputsReadsAsClean(t *testing.T) {
	got := normalizeGitleaksReport(dropFindingsInAgentInputs(
		[]byte(`[{"RuleID":"generic-api-key","File":"scans.sarif","Secret":"x"}]`), []string{"scans.sarif"}))
	if got != "[]" {
		t.Fatalf("got %s, want []", got)
	}
}

func TestAgentInputFilesNeverListTheBinary(t *testing.T) {
	t.Setenv("WISEC_SCAN_REPORT_PATH", "scans.sarif")
	t.Setenv("WISEC_SBOM_PATH", "")
	t.Setenv("WISEC_BINARY_PATH", "myapp")
	if got := agentInputFiles(); fmt.Sprint(got) != "[scans.sarif]" {
		t.Fatalf("got %v: a secret compiled into the shipped binary is a real leak", got)
	}
}

// Without WISEC_SBOM_PATH the agent reads a bom.json it finds in the working
// directory; that file is an input too and must be skipped like the others.
func TestAgentInputFilesFollowTheSBOMTheAgentReads(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("WISEC_SCAN_REPORT_PATH", "")
	t.Setenv("WISEC_SBOM_PATH", "")
	if got := agentInputFiles(); len(got) != 0 {
		t.Fatalf("got %v with no input present", got)
	}
	if err := os.WriteFile("bom.json", []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := agentInputFiles(); fmt.Sprint(got) != "[bom.json]" {
		t.Fatalf("got %v, want [bom.json]", got)
	}
}
