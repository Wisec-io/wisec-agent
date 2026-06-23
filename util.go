package main

import (
	"log"
	"os"
	"strconv"
	"strings"
)

// version is overridden at build time with -ldflags "-X main.version=x.y.z".
var version = "dev"

// userAgent identifies the agent in outbound HTTP requests.
func userAgent() string { return "wisec-agent/" + version }

// scannerVersion is embedded in the signed build manifest.
func scannerVersion() string { return "wisec-agent-go/" + version }

// getEnv returns the value of the first non-empty environment variable among keys.
// The candidate lists cover GitLab CI, GitHub Actions, Jenkins and Azure DevOps.
func getEnv(keys ...string) string {
	for _, key := range keys {
		if val := os.Getenv(key); val != "" {
			return val
		}
	}
	return ""
}

// normalizeBranch strips ref prefixes added by some CI systems, e.g.
// "refs/heads/main" (Azure DevOps) or "origin/main" (Jenkins) become "main".
func normalizeBranch(branch string) string {
	branch = strings.TrimPrefix(branch, "refs/heads/")
	branch = strings.TrimPrefix(branch, "origin/")
	return branch
}

func isVerbose() bool {
	verbose, _ := strconv.ParseBool(os.Getenv("WISEC_VERBOSE"))
	return verbose
}

func logInfo(format string, v ...any) {
	log.Printf(format, v...)
}

func logVerbose(format string, v ...any) {
	if isVerbose() {
		log.Printf(format, v...)
	}
}
