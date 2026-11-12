package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// emptyTreeHash is Git's well-known empty tree object, used to diff the very
// first commit (which has no parent) against nothing.
const emptyTreeHash = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"

func runGitCommand(args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("git %s: %w", strings.Join(args, " "), err)
	}
	return strings.TrimSpace(out.String()), nil
}

// gitCommitAuthorEmail resolves the commit author email, preferring CI-provided
// environment variables and falling back to the local git log.
func gitCommitAuthorEmail() (string, error) {
	if email := getEnv("CI_COMMIT_AUTHOR_EMAIL", "GIT_AUTHOR_EMAIL", "BUILD_REQUESTEDFOREMAIL"); email != "" {
		return email, nil
	}
	return runGitCommand("log", "-1", "--pretty=format:%ae")
}

// gitDiffChanges returns the files changed and deleted in the latest commit.
// On the initial commit (no parent) it diffs against the empty tree.
func gitDiffChanges() (changed, deleted []string, err error) {
	base := "HEAD~1"
	if _, err := runGitCommand("rev-parse", "--verify", "HEAD~1"); err != nil {
		base = emptyTreeHash
		logVerbose("no previous commit, diffing against the empty tree")
	}

	diff, err := runGitCommand("diff", "--name-status", base, "HEAD")
	if err != nil {
		return nil, nil, fmt.Errorf("git diff: %w", err)
	}

	scanner := bufio.NewScanner(strings.NewReader(diff))
	for scanner.Scan() {
		parts := strings.Split(scanner.Text(), "\t")
		if len(parts) != 2 {
			continue
		}
		switch parts[0] {
		case "D":
			deleted = append(deleted, parts[1])
		case "A", "M", "C", "R":
			changed = append(changed, parts[1])
		}
	}
	return changed, deleted, nil
}

// runGitleaks runs gitleaks over the working tree and returns its JSON report.
// It returns "[]" when no secrets are found and "" on an execution error.
func runGitleaks() string {
	const reportPath = "gitleaks-report.json"
	// --no-git scans the working tree directly: in CI the .git directory may be
	// shallow or absent. --redact keeps the secret out of gitleaks' own output
	// and report file, which stays on the runner; redactGitleaksFinding then
	// strips what is left before anything is signed or sent.
	cmd := exec.Command("gitleaks", "detect", "--source", ".", "--no-git", "--redact",
		"-v", "--report-format", "json", "--report-path", reportPath)
	output, err := cmd.CombinedOutput()

	// gitleaks exits 1 when leaks are found, 0 when none, and >1 on error.
	if err != nil && !strings.Contains(string(output), "leaks found") {
		logVerbose("gitleaks failed: %v", err)
		return ""
	}

	report, err := os.ReadFile(reportPath)
	if err != nil {
		return "[]"
	}
	return normalizeGitleaksReport(dropFindingsInAgentInputs(report, agentInputFiles()))
}

// agentInputFiles are the reports the agent reads as inputs: the scanner SARIF
// (WISEC_SCAN_REPORT_PATH) and the SBOM (WISEC_SBOM_PATH). When a pipeline
// leaves them in the working tree, gitleaks scans them like source code, and a
// SARIF report quotes CVE texts and code that it reads as keys: a merged Trivy
// report raised four CRITICAL generic-api-key findings on Wisec's own main
// branch (2026-11-11). A real secret quoted in such a report is still found
// in the source file it comes from, so nothing is lost by skipping the copy.
// The SBOM comes from locateSBOM, the same function that later reads it, so a
// bom.json picked up without WISEC_SBOM_PATH is skipped too: the list is
// exactly the files the agent ingests, never a guess.
// WISEC_BINARY_PATH is deliberately NOT listed: a secret compiled into the
// built binary is a real leak.
func agentInputFiles() []string {
	var files []string
	if p := os.Getenv("WISEC_SCAN_REPORT_PATH"); p != "" {
		files = append(files, p)
	}
	if p := locateSBOM(); p != "" {
		files = append(files, p)
	}
	return files
}

// dropFindingsInAgentInputs removes the findings located in one of the given
// files. Paths are compared absolute, so "./scans.sarif", "scans.sarif" and the
// full path all match. A report that is not a JSON array of objects is
// returned untouched: normalizeGitleaksReport decides what to do with it, and
// a filter must never be the reason an unreadable report reads as clean.
func dropFindingsInAgentInputs(report []byte, files []string) []byte {
	if len(files) == 0 {
		return report
	}
	excluded := map[string]string{}
	for _, f := range files {
		if abs, err := filepath.Abs(f); err == nil {
			excluded[abs] = f
		}
	}
	var findings []map[string]json.RawMessage
	if err := json.Unmarshal(bytes.TrimSpace(report), &findings); err != nil {
		return report
	}
	kept := make([]map[string]json.RawMessage, 0, len(findings))
	dropped := map[string]int{}
	for _, f := range findings {
		var file string
		if raw, ok := f["File"]; ok && json.Unmarshal(raw, &file) == nil && file != "" {
			if abs, err := filepath.Abs(file); err == nil {
				if name, hit := excluded[abs]; hit {
					dropped[name]++
					continue
				}
			}
		}
		kept = append(kept, f)
	}
	if len(dropped) == 0 {
		return report
	}
	for name, n := range dropped {
		logInfo("gitleaks: %d finding(s) in %s ignored: the agent reads this file as an input report, its sources are scanned on their own", n, name)
	}
	out, err := json.Marshal(kept)
	if err != nil {
		return report
	}
	return out
}

// gitleaksWithheldFields are the finding fields that carry the secret itself
// (Secret, Match, Line) or personal data about who committed it (Author, Email,
// Message). Wisec reads none of them: the analysis uses the rule, the file and
// the description, and the gate only needs to know a finding exists. Sending
// them made the platform hold customers' live credentials for no purpose.
var gitleaksWithheldFields = []string{"Secret", "Match", "Line", "Author", "Email", "Message"}

// unreadableGitleaksReport stands in for a report that is not a JSON array.
// The bytes cannot be sent as they are, since nothing guarantees what they
// contain, and dropping them would read as "no secrets" and let the gate pass:
// a placeholder finding keeps the build flagged without leaking anything.
const unreadableGitleaksReport = `[{"Description":"gitleaks report could not be parsed; its content was withheld","RuleID":"unreadable-gitleaks-report"}]`

// normalizeGitleaksReport returns a canonical, compact JSON array of gitleaks
// findings with the secret values removed. gitleaks writes the empty result as
// "[]\n", so a raw string compare against "[]" is fooled by the trailing
// newline and would report secrets that do not exist. Parsing the report makes
// the "no secrets" decision robust and guarantees the API receives valid JSON.
func normalizeGitleaksReport(report []byte) string {
	report = bytes.TrimSpace(report)
	if len(report) == 0 {
		return "[]"
	}
	var findings []json.RawMessage
	if err := json.Unmarshal(report, &findings); err != nil {
		logVerbose("gitleaks report is not a JSON array, withholding its content: %v", err)
		return unreadableGitleaksReport
	}
	if len(findings) == 0 {
		return "[]"
	}
	redacted := make([]json.RawMessage, 0, len(findings))
	for _, f := range findings {
		redacted = append(redacted, redactGitleaksFinding(f))
	}
	normalized, err := json.Marshal(redacted)
	if err != nil {
		return unreadableGitleaksReport
	}
	return string(normalized)
}

// redactGitleaksFinding drops the withheld fields from one finding. A finding
// that is not a JSON object is replaced rather than passed through, for the
// same reason as an unreadable report.
func redactGitleaksFinding(finding json.RawMessage) json.RawMessage {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(finding, &fields); err != nil || fields == nil {
		return json.RawMessage(`{"Description":"unreadable gitleaks finding; its content was withheld","RuleID":"unreadable-gitleaks-finding"}`)
	}
	for _, key := range gitleaksWithheldFields {
		delete(fields, key)
	}
	out, err := json.Marshal(fields)
	if err != nil {
		return json.RawMessage(`{"Description":"unreadable gitleaks finding; its content was withheld","RuleID":"unreadable-gitleaks-finding"}`)
	}
	return out
}
