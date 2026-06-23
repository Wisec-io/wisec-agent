package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

const httpTimeout = 20 * time.Second

// sendToAPI submits the signed build event to the Wisec API. It never blocks the
// pipeline: policy enforcement happens later in the dedicated --gate step.
func sendToAPI(event BuildEvent) {
	endpoint := os.Getenv("WISEC_API_ENDPOINT")
	if endpoint == "" {
		logInfo("WISEC_API_ENDPOINT not set; skipping submission")
		logVerbose("event that was not sent:\n%s", prettyJSON(event))
		return
	}

	body, err := json.Marshal(event)
	if err != nil {
		log.Printf("could not encode event: %v", err)
		return
	}

	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		log.Printf("could not create request: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent())

	resp, err := (&http.Client{Timeout: httpTimeout}).Do(req)
	if err != nil {
		log.Printf("could not reach the Wisec API: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(resp.Body)
		log.Printf("Wisec API returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
		return
	}

	logInfo("Build event submitted")
	if url := dashboardURL(); url != "" {
		logInfo("Report: %s/projects/%d", url, event.ProjectID)
	}
}

// fetchLatestBuildHash returns the event hash of the project's previous build,
// used to chain-link builds. It returns "" when there is no previous build or
// the lookup cannot be completed.
func fetchLatestBuildHash(projectID uint, pub ed25519.PublicKey, priv ed25519.PrivateKey) string {
	endpoint := os.Getenv("WISEC_API_ENDPOINT")
	if endpoint == "" {
		return ""
	}
	base := strings.TrimSuffix(endpoint, "/events")
	url := fmt.Sprintf("%s/projects/%d/latest-hash", base, projectID)
	path := fmt.Sprintf("/api/v1/projects/%d/latest-hash", projectID)

	resp, err := signedGet(url, path, pub, priv)
	if err != nil {
		logVerbose("could not fetch latest build hash: %v", err)
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		logVerbose("latest-hash returned HTTP %d", resp.StatusCode)
		return ""
	}
	var result struct {
		LatestHash string `json:"latest_hash"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		logVerbose("could not decode latest-hash response: %v", err)
		return ""
	}
	return result.LatestHash
}

// signedGet performs a GET request authenticated with the agent key. The server
// verifies the signature over "GET:<path>:<timestamp>".
func signedGet(url, path string, pub ed25519.PublicKey, priv ed25519.PrivateKey) (*http.Response, error) {
	timestamp := time.Now().UTC().Format(time.RFC3339)
	message := fmt.Sprintf("GET:%s:%s", path, timestamp)
	signature := ed25519.Sign(priv, []byte(message))

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Wisec-Public-Key", hex.EncodeToString(pub))
	req.Header.Set("X-Wisec-Signature", hex.EncodeToString(signature))
	req.Header.Set("X-Wisec-Timestamp", timestamp)
	req.Header.Set("User-Agent", userAgent())

	return (&http.Client{Timeout: 10 * time.Second}).Do(req)
}

// dashboardURL derives the dashboard base URL. It honours WISEC_APP_URL, then
// falls back to deriving it from the API endpoint (api.* -> app.*). It returns
// "" when no URL can be determined.
func dashboardURL() string {
	if v := os.Getenv("WISEC_APP_URL"); v != "" {
		return strings.TrimRight(v, "/")
	}
	endpoint := os.Getenv("WISEC_API_ENDPOINT")
	if i := strings.Index(endpoint, "/api/"); i != -1 {
		endpoint = endpoint[:i]
	}
	if strings.Contains(endpoint, "api.") {
		return strings.Replace(endpoint, "api.", "app.", 1)
	}
	return endpoint
}
