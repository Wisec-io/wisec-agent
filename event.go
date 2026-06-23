package main

import (
	"encoding/json"
	"sort"
	"time"
)

// EventPayload holds the fields that contribute to the canonical event data.
// It is intentionally distinct from BuildEvent: only these fields are hashed
// and signed, and their canonical form must match the Wisec API exactly.
type EventPayload struct {
	Timestamp            string    `json:"timestamp"`
	CommitHash           string    `json:"commit_hash"`
	Branch               string    `json:"branch"`
	EventHash            string    `json:"event_hash"`
	ProjectID            uint      `json:"project_id"`
	Type                 string    `json:"type"`
	Details              string    `json:"details"`
	AlertCount           int       `json:"alert_count"`
	SecurityScore        float64   `json:"security_score"`
	BuildDurationSeconds float64   `json:"build_duration_seconds"`
	Dependencies         []string  `json:"dependencies"`
	AuthorEmail          string    `json:"author_email"`
	FilesChanged         int       `json:"files_changed"`
	DeletedFiles         []string  `json:"deleted_files"`
	ChangedFiles         []string  `json:"changed_files"`
	SecretsFound         string    `json:"secrets_found,omitempty"`
	SBOMContent          string    `json:"sbom_content,omitempty"`
	SARIFReport          string    `json:"sarif_report,omitempty"`
	Manifest             *Manifest `json:"manifest,omitempty"`
	PreviousEventHash    string    `json:"previous_event_hash,omitempty"`
}

// BuildEvent is the full event submitted to the Wisec API, including the
// signature and the canonical data used to produce it.
type BuildEvent struct {
	Timestamp            time.Time `json:"timestamp"`
	CommitHash           string    `json:"commit_hash"`
	Branch               string    `json:"branch"`
	EventHash            string    `json:"event_hash"`
	PreviousEventHash    string    `json:"previous_event_hash"`
	ProjectID            uint      `json:"project_id"`
	Type                 string    `json:"type"`
	Details              string    `json:"details"`
	AlertCount           int       `json:"alert_count"`
	SecurityScore        float64   `json:"security_score"`
	BuildDurationSeconds float64   `json:"build_duration_seconds"`
	Dependencies         []string  `json:"dependencies"`
	AuthorEmail          string    `json:"author_email"`
	FilesChanged         int       `json:"files_changed"`
	DeletedFiles         []string  `json:"deleted_files"`
	ChangedFiles         []string  `json:"changed_files"`
	SecretsFound         string    `json:"secrets_found,omitempty"`
	SBOMContent          string    `json:"sbom_content,omitempty"`
	SARIFReport          string    `json:"sarif_report,omitempty"`
	Manifest             *Manifest `json:"manifest,omitempty"`

	Signature          string `json:"signature"`
	SignerPublicKey    string `json:"signer_public_key"`
	VerificationStatus string `json:"verification_status"`
	CanonicalEventData string `json:"canonical_event_data"`
}

// getCanonicalEventData produces the canonical JSON representation of a build
// event. Keys are sorted by json.Marshal (Go sorts map[string]... keys), which
// makes the output deterministic. The dependency and file lists are sorted so
// the result is independent of collection order.
//
// This function MUST stay byte-for-byte identical to its counterpart in the
// Wisec API gateway: the signature is computed over the SHA-256 of this output,
// so any divergence breaks verification. Adding a field here requires the same
// change on the API side, simultaneously.
//
// SARIFReport is deliberately excluded: its integrity is committed through
// manifest.Payload.ScanReportHash instead.
func getCanonicalEventData(payload EventPayload) []byte {
	sort.Strings(payload.Dependencies)
	sort.Strings(payload.ChangedFiles)
	sort.Strings(payload.DeletedFiles)

	deps := payload.Dependencies
	if deps == nil {
		deps = []string{}
	}
	changed := payload.ChangedFiles
	if changed == nil {
		changed = []string{}
	}
	deleted := payload.DeletedFiles
	if deleted == nil {
		deleted = []string{}
	}

	fields := map[string]any{
		"AlertCount":           payload.AlertCount,
		"AuthorEmail":          payload.AuthorEmail,
		"Branch":               payload.Branch,
		"BuildDurationSeconds": payload.BuildDurationSeconds,
		"ChangedFiles":         changed,
		"CommitHash":           payload.CommitHash,
		"DeletedFiles":         deleted,
		"Dependencies":         deps,
		"Details":              payload.Details,
		"FilesChanged":         payload.FilesChanged,
		"PreviousEventHash":    payload.PreviousEventHash,
		"ProjectID":            payload.ProjectID,
		"SBOMContent":          payload.SBOMContent,
		"SecurityScore":        payload.SecurityScore,
		"SecretsFound":         payload.SecretsFound,
		"Timestamp":            payload.Timestamp,
		"Type":                 payload.Type,
	}

	if payload.Manifest != nil {
		// Round-trip through interface{} so nested manifest keys are sorted too.
		manifestBytes, _ := json.Marshal(payload.Manifest)
		var manifestMap any
		if err := json.Unmarshal(manifestBytes, &manifestMap); err == nil {
			fields["Manifest"] = manifestMap
		}
	}

	data, _ := json.Marshal(fields)
	return data
}

// canonicalizeJSON parses and re-marshals JSON into a canonical (sorted-key,
// compact) form so that hashes are stable across tool-specific formatting.
func canonicalizeJSON(data []byte) ([]byte, error) {
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		return nil, err
	}
	return json.Marshal(v)
}
