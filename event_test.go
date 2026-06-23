package main

import (
	"encoding/json"
	"sort"
	"strings"
	"testing"
)

func sampleParser() EventPayload {
	return EventPayload{
		Timestamp:    "2026-01-02T03:04:05Z",
		CommitHash:   "abc123",
		Branch:       "main",
		ProjectID:    7,
		Type:         "BuildSuccess",
		Details:      "ok",
		Dependencies: []string{"npm:b@2", "go:a@1"},
		ChangedFiles: []string{"z.go", "a.go"},
		DeletedFiles: []string{"old.go"},
		AuthorEmail:  "dev@example.com",
	}
}

// canonicalFields is the exact set of keys the canonical form must contain.
// It mirrors the contract with the Wisec API: changing it here without changing
// the API breaks signature verification, so this test is a deliberate tripwire.
var canonicalFields = []string{
	"AlertCount", "AuthorEmail", "Branch", "BuildDurationSeconds", "ChangedFiles",
	"CommitHash", "DeletedFiles", "Dependencies", "Details", "FilesChanged",
	"PreviousEventHash", "ProjectID", "SBOMContent", "SecurityScore", "SecretsFound",
	"Timestamp", "Type",
}

func TestCanonicalFieldSet(t *testing.T) {
	var got map[string]json.RawMessage
	if err := json.Unmarshal(getCanonicalEventData(sampleParser()), &got); err != nil {
		t.Fatalf("canonical data is not valid JSON: %v", err)
	}

	keys := make([]string, 0, len(got))
	for k := range got {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	want := append([]string{}, canonicalFields...)
	sort.Strings(want)

	if len(keys) != len(want) {
		t.Fatalf("field count = %d, want %d (%v)", len(keys), len(want), keys)
	}
	for i := range want {
		if keys[i] != want[i] {
			t.Errorf("field[%d] = %q, want %q", i, keys[i], want[i])
		}
	}
}

func TestCanonicalExcludesSARIF(t *testing.T) {
	p := sampleParser()
	p.SARIFReport = "should-not-appear"
	if got := string(getCanonicalEventData(p)); strings.Contains(got, "should-not-appear") {
		t.Error("canonical data must not include the SARIF report")
	}
}

func TestCanonicalIsOrderIndependent(t *testing.T) {
	a := sampleParser()
	b := sampleParser()
	b.Dependencies = []string{"go:a@1", "npm:b@2"} // same set, different order
	b.ChangedFiles = []string{"a.go", "z.go"}

	if string(getCanonicalEventData(a)) != string(getCanonicalEventData(b)) {
		t.Error("canonical data must not depend on slice ordering")
	}
}

func TestCanonicalManifestIncluded(t *testing.T) {
	p := sampleParser()
	p.Manifest = &Manifest{Version: "1.0"}
	var got map[string]json.RawMessage
	if err := json.Unmarshal(getCanonicalEventData(p), &got); err != nil {
		t.Fatal(err)
	}
	if _, ok := got["Manifest"]; !ok {
		t.Error("Manifest must be present when set")
	}
}
