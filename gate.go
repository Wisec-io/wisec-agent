package main

import (
	"crypto/ed25519"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	defaultGateTimeout = 120 * time.Second
	gatePollInterval   = 3 * time.Second
)

// gateResponse is the API reply when polling for the policy decision.
type gateResponse struct {
	Status       string  `json:"status"`
	PolicyResult string  `json:"policy_result"`
	RiskScore    float64 `json:"risk_score"`
	Violations   []struct {
		PolicyName string `json:"policy_name"`
		Action     string `json:"action"`
		Message    string `json:"message"`
	} `json:"violations"`
}

// runGateMode polls the Wisec API until the post-analysis policies are
// evaluated, then exits non-zero if the merged result is "block". On timeout it
// passes unless WISEC_STRICT is set.
func runGateMode(pub ed25519.PublicKey, priv ed25519.PrivateKey) {
	logInfo("Wisec policy gate")

	endpoint := os.Getenv("WISEC_API_ENDPOINT")
	if endpoint == "" {
		log.Fatal("WISEC_API_ENDPOINT is not set")
	}
	projectID := os.Getenv("WISEC_PROJECT_ID")
	if projectID == "" {
		log.Fatal("WISEC_PROJECT_ID is not set")
	}

	commitHash := getEnv("CI_COMMIT_SHA", "GITHUB_SHA", "GIT_COMMIT", "BUILD_SOURCEVERSION")
	if commitHash == "" {
		var err error
		if commitHash, err = runGitCommand("rev-parse", "HEAD"); err != nil || commitHash == "" {
			log.Fatal("could not determine commit hash; set CI_COMMIT_SHA or GITHUB_SHA")
		}
	}

	timeout := gateTimeout()
	strict, _ := strconv.ParseBool(os.Getenv("WISEC_STRICT"))

	base := strings.TrimSuffix(endpoint, "/events") + "/events/gate"
	query := url.Values{"project_id": {projectID}, "commit_hash": {commitHash}}.Encode()
	gateURL := base + "?" + query

	logInfo("Waiting for analysis (timeout %s, strict %v)...", timeout, strict)
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		result, ok := pollGate(gateURL, pub, priv)
		if !ok {
			time.Sleep(gatePollInterval)
			continue
		}

		switch result.Status {
		case "pending", "not_found":
			logVerbose("analysis %s, retrying", result.Status)
			time.Sleep(gatePollInterval)
		case "completed", "failed":
			reportGate(result)
			return
		default:
			time.Sleep(gatePollInterval)
		}
	}

	if strict {
		log.Fatalf("Wisec gate timed out after %s (WISEC_STRICT=true)", timeout)
	}
	logInfo("Wisec gate timed out after %s; passing (set WISEC_STRICT=true to block on timeout)", timeout)
}

func pollGate(gateURL string, pub ed25519.PublicKey, priv ed25519.PrivateKey) (gateResponse, bool) {
	resp, err := signedGet(gateURL, "/api/v1/events/gate", pub, priv)
	if err != nil {
		logVerbose("gate poll error: %v", err)
		return gateResponse{}, false
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		logVerbose("gate returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
		return gateResponse{}, false
	}

	var result gateResponse
	if err := json.Unmarshal(body, &result); err != nil {
		logVerbose("could not parse gate response: %v", err)
		return gateResponse{}, false
	}
	return result, true
}

// reportGate prints the decision and exits non-zero when the build is blocked.
func reportGate(result gateResponse) {
	logInfo("Security score: %.0f/100", result.RiskScore)
	for _, v := range result.Violations {
		logInfo("  [%s] %s: %s", strings.ToUpper(v.Action), v.PolicyName, v.Message)
	}

	if result.PolicyResult == "block" {
		log.Fatal("Build blocked by Wisec policy; resolve the violations before merging")
	}
	if len(result.Violations) > 0 {
		logInfo("Warnings logged; build passes")
	} else {
		logInfo("Policy gate passed")
	}
}

func gateTimeout() time.Duration {
	if v := os.Getenv("WISEC_GATE_TIMEOUT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return time.Duration(n) * time.Second
		}
	}
	return defaultGateTimeout
}
