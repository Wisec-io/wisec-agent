package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
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
	// shallow or absent.
	cmd := exec.Command("gitleaks", "detect", "--source", ".", "--no-git",
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
	return normalizeGitleaksReport(report)
}

// normalizeGitleaksReport returns a canonical, compact JSON array of gitleaks
// findings. gitleaks writes the empty result as "[]\n", so a raw string compare
// against "[]" is fooled by the trailing newline and would report secrets that
// do not exist. Parsing the report makes the "no secrets" decision robust and
// guarantees the API receives valid JSON. The raw bytes are kept only when the
// report is not a JSON array, so an unexpected format is still surfaced.
func normalizeGitleaksReport(report []byte) string {
	report = bytes.TrimSpace(report)
	if len(report) == 0 {
		return "[]"
	}
	var findings []json.RawMessage
	if err := json.Unmarshal(report, &findings); err != nil {
		logVerbose("gitleaks report is not a JSON array, sending as-is: %v", err)
		return string(report)
	}
	if len(findings) == 0 {
		return "[]"
	}
	normalized, err := json.Marshal(findings)
	if err != nil {
		return string(report)
	}
	return string(normalized)
}
