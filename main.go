// Command wisec-agent collects build metadata in a CI/CD pipeline, signs it with
// an Ed25519 key, and submits it to the Wisec API for notarization and analysis.
//
// It runs in two modes:
//
//	wisec-agent          collect, sign and submit the build event (non-blocking)
//	wisec-agent --gate   poll the API until policies are evaluated, exit non-zero on block
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"slices"
	"strconv"
	"time"
)

func main() {
	log.SetFlags(0)

	publicKey, privateKey := loadOrGenerateKeys()

	if slices.Contains(os.Args[1:], "--gate") {
		runGateMode(publicKey, privateKey)
		return
	}

	logInfo("Wisec agent %s starting", version)

	logInfo("Collecting build metadata...")
	dependencies := scanDependencies()
	// In a monorepo or multi-language repo, no dependency manifest sits at the
	// repository root. Fall back to an SBOM (e.g. produced by syft) so CVE and
	// typosquatting analysis still see the dependency set.
	if len(dependencies) == 0 {
		if sbomPath := locateSBOM(); sbomPath != "" {
			if derived := dependenciesFromSBOM(sbomPath); len(derived) > 0 {
				dependencies = derived
				logInfo("  %d dependencies derived from SBOM %s", len(derived), sbomPath)
			}
		}
	}

	authorEmail, err := gitCommitAuthorEmail()
	if err != nil {
		logVerbose("could not resolve git author email: %v", err)
		authorEmail = getEnv("CI_COMMIT_AUTHOR", "GITHUB_ACTOR", "GIT_AUTHOR_EMAIL", "BUILD_REQUESTEDFOREMAIL")
	}

	changedFiles, deletedFiles, err := gitDiffChanges()
	if err != nil {
		log.Fatalf("could not read git diff: %v", err)
	}
	logInfo("  %d changed file(s), %d deleted file(s)", len(changedFiles), len(deletedFiles))

	logInfo("Scanning for secrets...")
	secretsFound := runGitleaks()
	if secretsFound != "[]" && secretsFound != "" {
		logInfo("  hardcoded secrets detected")
	} else {
		logInfo("  no hardcoded secrets detected")
	}

	logInfo("Preparing build artifacts...")
	manifest, sbomContent, sarifReport := buildManifest(dependencies, publicKey, privateKey)

	projectID := mustProjectID()

	logInfo("Fetching previous build hash for the notarization chain...")
	previousHash := fetchLatestBuildHash(projectID, publicKey, privateKey)
	if previousHash != "" {
		logInfo("  linked to previous build %s", shortHash(previousHash))
	} else {
		logInfo("  no previous build found, starting a new chain")
	}

	event := buildEvent(buildEventInput{
		projectID:    projectID,
		dependencies: dependencies,
		authorEmail:  authorEmail,
		changedFiles: changedFiles,
		deletedFiles: deletedFiles,
		secretsFound: secretsFound,
		sbomContent:  sbomContent,
		sarifReport:  sarifReport,
		manifest:     manifest,
		previousHash: previousHash,
	})

	canonical := getCanonicalEventData(eventPayload(event))
	hash := sha256.Sum256(canonical)
	event.EventHash = hex.EncodeToString(hash[:])
	event.Signature = hex.EncodeToString(ed25519.Sign(privateKey, []byte(event.EventHash)))
	event.SignerPublicKey = hex.EncodeToString(publicKey)
	event.VerificationStatus = "PENDING"
	event.CanonicalEventData = string(canonical)

	logInfo("Submitting build event...")
	sendToAPI(event)
}

// buildEventInput groups the collected data needed to assemble a BuildEvent.
type buildEventInput struct {
	projectID    uint
	dependencies []string
	authorEmail  string
	changedFiles []string
	deletedFiles []string
	secretsFound string
	sbomContent  string
	sarifReport  string
	manifest     *Manifest
	previousHash string
}

func buildEvent(in buildEventInput) BuildEvent {
	commitHash := getEnv("CI_COMMIT_SHA", "GITHUB_SHA", "GIT_COMMIT", "BUILD_SOURCEVERSION")
	if commitHash == "" {
		commitHash = "localdev"
	}
	branch := normalizeBranch(getEnv("CI_COMMIT_REF_NAME", "GITHUB_REF", "GIT_BRANCH", "BUILD_SOURCEBRANCH"))
	if branch == "" {
		branch = "main"
	}

	details := fmt.Sprintf("Build successful with %d dependencies, %d files changed, %d files deleted.",
		len(in.dependencies), len(in.changedFiles), len(in.deletedFiles))

	return BuildEvent{
		Timestamp:  time.Now(),
		CommitHash: commitHash,
		Branch:     branch,
		ProjectID:  in.projectID,
		Type:       "BuildSuccess",
		Details:    details,
		// AlertCount and SecurityScore are authoritatively computed server-side
		// after analysis; the agent does not assert them.
		AlertCount:           0,
		SecurityScore:        0,
		BuildDurationSeconds: buildDurationSeconds(),
		Dependencies:         in.dependencies,
		AuthorEmail:          in.authorEmail,
		FilesChanged:         len(in.changedFiles),
		DeletedFiles:         in.deletedFiles,
		ChangedFiles:         in.changedFiles,
		SecretsFound:         in.secretsFound,
		SBOMContent:          in.sbomContent,
		SARIFReport:          in.sarifReport,
		Manifest:             in.manifest,
		PreviousEventHash:    in.previousHash,
	}
}

func mustProjectID() uint {
	raw := os.Getenv("WISEC_PROJECT_ID")
	if raw == "" {
		log.Fatal("WISEC_PROJECT_ID is not set; configure it in your CI/CD pipeline")
	}
	id, err := strconv.ParseUint(raw, 10, 32)
	if err != nil {
		log.Fatalf("invalid WISEC_PROJECT_ID %q: must be an unsigned integer", raw)
	}
	return uint(id)
}

// buildDurationSeconds reports the build duration in seconds. The agent runs as a
// notification step and cannot measure the build itself, so the value is taken from
// WISEC_BUILD_DURATION_SECONDS when the pipeline provides it, and is 0 otherwise.
func buildDurationSeconds() float64 {
	if v := os.Getenv("WISEC_BUILD_DURATION_SECONDS"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil && f >= 0 {
			return f
		}
	}
	return 0
}

func shortHash(h string) string {
	if len(h) > 8 {
		return h[:8]
	}
	return h
}

// eventPayload projects a BuildEvent onto the fields that participate in the
// canonical representation. The canonical form is the single source of truth
// shared with the Wisec API and must stay byte-for-byte identical on both sides.
func eventPayload(e BuildEvent) EventPayload {
	return EventPayload{
		Timestamp:            e.Timestamp.In(time.UTC).Format(time.RFC3339Nano),
		CommitHash:           e.CommitHash,
		Branch:               e.Branch,
		ProjectID:            e.ProjectID,
		Type:                 e.Type,
		Details:              e.Details,
		AlertCount:           e.AlertCount,
		SecurityScore:        e.SecurityScore,
		BuildDurationSeconds: e.BuildDurationSeconds,
		Dependencies:         e.Dependencies,
		AuthorEmail:          e.AuthorEmail,
		FilesChanged:         e.FilesChanged,
		DeletedFiles:         e.DeletedFiles,
		ChangedFiles:         e.ChangedFiles,
		SecretsFound:         e.SecretsFound,
		SBOMContent:          e.SBOMContent,
		SARIFReport:          e.SARIFReport,
		Manifest:             e.Manifest,
		PreviousEventHash:    e.PreviousEventHash,
	}
}

// MarshalIndent is used in verbose mode to dump an event that is not sent.
func prettyJSON(v any) string {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return ""
	}
	return string(b)
}
