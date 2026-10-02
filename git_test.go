package main

import (
	"encoding/json"
	"fmt"
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
