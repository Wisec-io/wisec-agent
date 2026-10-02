package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"time"
)

// Manifest is the signed integrity record anchored on IPFS. It commits to the
// hashes of the build artifacts (binary, SBOM, scan report) without carrying
// their content.
type Manifest struct {
	Version   string            `json:"version"`
	Metadata  ManifestMetadata  `json:"metadata"`
	Payload   ManifestPayload   `json:"payload"`
	Signature ManifestSignature `json:"signature"`
}

type ManifestMetadata struct {
	ProjectURL     string `json:"project_url"`
	CommitID       string `json:"commit_id"`
	Timestamp      string `json:"timestamp"`
	ScannerVersion string `json:"scanner_version"`
}

type ManifestPayload struct {
	BinaryHash     string `json:"binary_hash,omitempty"`
	SBOMHash       string `json:"sbom_hash,omitempty"`
	ScanReportHash string `json:"scan_report_hash,omitempty"`
	// ImageDigests are the container images the pipeline pushed, pinned by
	// digest ("registry/repo@sha256:<hex>"), read from WISEC_IMAGE_DIGESTS.
	// The manifest is part of the signed canonical form, which the API rebuilds
	// from its own struct: the API learned this field first (2026-10-02), and
	// omitempty keeps the canonical of a build without images unchanged.
	ImageDigests []string `json:"image_digests,omitempty"`
}

type ManifestSignature struct {
	PubKey         string `json:"pubkey"`
	SignatureValue string `json:"signature_value"`
}

// sbomCandidates are the file names probed when WISEC_SBOM_PATH is unset.
var sbomCandidates = []string{"bom.json", "cyclonedx.json", "sbom.json", "wisec-bom.json"}

// buildManifest assembles and signs the build manifest. It returns the manifest
// along with the SBOM and SARIF report contents to embed in the event.
func buildManifest(dependencies []string, pub ed25519.PublicKey, priv ed25519.PrivateKey) (*Manifest, string, string) {
	manifest := &Manifest{
		Version: "1.0",
		Metadata: ManifestMetadata{
			ProjectURL:     getEnv("CI_PROJECT_URL", "GITHUB_REPOSITORY", "BUILD_REPOSITORY_URI"),
			CommitID:       getEnv("CI_COMMIT_SHA", "GITHUB_SHA", "GIT_COMMIT", "BUILD_SOURCEVERSION"),
			Timestamp:      time.Now().UTC().Format(time.RFC3339),
			ScannerVersion: scannerVersion(),
		},
	}

	if binaryPath := os.Getenv("WISEC_BINARY_PATH"); binaryPath != "" {
		if hash, err := fileSHA256(binaryPath); err == nil {
			manifest.Payload.BinaryHash = "sha256:" + hash
			logVerbose("hashed binary %s", binaryPath)
		} else {
			logVerbose("could not hash binary %s: %v", binaryPath, err)
		}
	}

	manifest.Payload.ImageDigests = imageDigestsFromEnv()

	sbomContent := resolveSBOM(manifest, dependencies)
	sarifReport := resolveSARIF(manifest)

	manifest.Signature = signManifest(manifest, pub, priv)
	logInfo("  build artifacts sealed for verification")
	return manifest, sbomContent, sarifReport
}

// locateSBOM returns the path to an existing SBOM file: WISEC_SBOM_PATH when set,
// otherwise the first matching candidate in the working directory. It returns ""
// when none is present; no SBOM is generated here.
func locateSBOM() string {
	if sbomPath := os.Getenv("WISEC_SBOM_PATH"); sbomPath != "" {
		return sbomPath
	}
	for _, candidate := range sbomCandidates {
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	return ""
}

// resolveSBOM locates or generates an SBOM, records its hash in the manifest,
// and returns its content. An empty string means no SBOM was available.
func resolveSBOM(manifest *Manifest, dependencies []string) string {
	sbomPath := locateSBOM()

	if sbomPath == "" && len(dependencies) > 0 {
		logInfo("  no SBOM file found, generating one from dependencies")
		content, err := generateCycloneDXSBOM(dependencies)
		if err == nil {
			sbomPath = "wisec-bom.json"
			if err := os.WriteFile(sbomPath, content, 0o644); err != nil {
				logVerbose("could not write generated SBOM: %v", err)
				sbomPath = ""
			}
		}
	}

	if sbomPath == "" {
		logInfo("  no SBOM available, skipping SBOM anchoring")
		return ""
	}

	hash, err := fileSHA256(sbomPath)
	if err != nil {
		logVerbose("could not hash SBOM %s: %v", sbomPath, err)
		return ""
	}
	manifest.Payload.SBOMHash = "sha256:" + hash

	content, err := os.ReadFile(sbomPath)
	if err != nil {
		logVerbose("could not read SBOM %s: %v", sbomPath, err)
		return ""
	}
	logVerbose("hashed SBOM %s", sbomPath)
	return string(content)
}

// resolveSARIF loads the scanner report from WISEC_SCAN_REPORT_PATH, records its
// canonicalized hash in the manifest, and returns its content.
func resolveSARIF(manifest *Manifest) string {
	sarifPath := os.Getenv("WISEC_SCAN_REPORT_PATH")
	if sarifPath == "" {
		return ""
	}

	raw, err := os.ReadFile(sarifPath)
	if err != nil {
		logVerbose("could not read SARIF report %s: %v", sarifPath, err)
		return ""
	}

	canonical, err := stripSARIFCode(raw)
	if err != nil {
		// Not JSON, so not SARIF the analysis could read anyway. It used to be
		// sent as raw bytes, which could be anything the scanner wrote.
		logInfo("  SARIF report at %s is not valid JSON, not sent", sarifPath)
		return ""
	}
	sum := sha256.Sum256(canonical)
	manifest.Payload.ScanReportHash = "sha256:" + hex.EncodeToString(sum[:])
	logInfo("  SARIF report loaded from %s", sarifPath)
	return string(canonical)
}

// signManifest signs the manifest metadata and payload with the agent key.
func signManifest(manifest *Manifest, pub ed25519.PublicKey, priv ed25519.PrivateKey) ManifestSignature {
	signed, _ := json.Marshal(struct {
		Metadata ManifestMetadata `json:"metadata"`
		Payload  ManifestPayload  `json:"payload"`
	}{manifest.Metadata, manifest.Payload})

	return ManifestSignature{
		PubKey:         hex.EncodeToString(pub),
		SignatureValue: hex.EncodeToString(ed25519.Sign(priv, signed)),
	}
}

// sarifCodeFields are the SARIF properties that quote source code: the lines
// around a result (snippet, contextRegion), the code a tool proposes as a fix
// (fixes), and whole embedded files (contents). Wisec reads the rule, the
// location, the line and the message; none of these. Removing them wherever
// they appear means a scanner report can no longer carry code out of the CI.
var sarifCodeFields = map[string]bool{"snippet": true, "contextRegion": true, "fixes": true, "contents": true}

// stripSARIFCode returns the canonical JSON of a SARIF report without the
// fields that quote source code.
func stripSARIFCode(raw []byte) ([]byte, error) {
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	return json.Marshal(dropSARIFCode(doc))
}

func dropSARIFCode(v any) any {
	switch node := v.(type) {
	case map[string]any:
		for key, child := range node {
			if sarifCodeFields[key] {
				delete(node, key)
				continue
			}
			node[key] = dropSARIFCode(child)
		}
		return node
	case []any:
		for i, child := range node {
			node[i] = dropSARIFCode(child)
		}
		return node
	default:
		return v
	}
}

// imageDigestsFromEnv reads WISEC_IMAGE_DIGESTS: one or more image references
// pinned by digest, separated by commas, spaces or newlines, e.g.
// "rg.fr-par.scw.cloud/acme/api@sha256:<64 hex>". A reference that is not
// pinned by a well-formed sha256 digest is reported and left out: a tag can be
// moved to another image, so only a digest identifies what was built.
func imageDigestsFromEnv() []string {
	raw := os.Getenv("WISEC_IMAGE_DIGESTS")
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var refs []string
	seen := map[string]bool{}
	for _, field := range strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\n' || r == '\t' || r == '\r'
	}) {
		ref, ok := normalizeImageReference(field)
		if !ok {
			logInfo("  WISEC_IMAGE_DIGESTS: %q is not pinned by a sha256 digest, ignored", field)
			continue
		}
		if !seen[ref] {
			seen[ref] = true
			refs = append(refs, ref)
		}
	}
	if len(refs) > 0 {
		logInfo("  %d container image(s) declared for the provenance", len(refs))
	}
	return refs
}

// normalizeImageReference accepts "name@sha256:<64 hex>" (a tag before the
// digest is allowed) and lowercases the digest, so the same image always signs
// the same way.
func normalizeImageReference(ref string) (string, bool) {
	name, digest, ok := strings.Cut(strings.TrimSpace(ref), "@")
	if !ok || name == "" {
		return "", false
	}
	hexPart, ok := strings.CutPrefix(strings.ToLower(digest), "sha256:")
	if !ok || len(hexPart) != 64 {
		return "", false
	}
	if _, err := hex.DecodeString(hexPart); err != nil {
		return "", false
	}
	return name + "@sha256:" + hexPart, true
}
