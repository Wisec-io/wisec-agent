package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// CycloneDXBOM is a minimal CycloneDX 1.4 document, enough to anchor the set of
// dependencies when the build does not already produce an SBOM.
type CycloneDXBOM struct {
	BomFormat    string               `json:"bomFormat"`
	SpecVersion  string               `json:"specVersion"`
	SerialNumber string               `json:"serialNumber,omitempty"`
	Version      int                  `json:"version"`
	Metadata     CycloneDXMetadata    `json:"metadata"`
	Components   []CycloneDXComponent `json:"components"`
}

type CycloneDXMetadata struct {
	Timestamp string          `json:"timestamp"`
	Tools     []CycloneDXTool `json:"tools"`
}

type CycloneDXTool struct {
	Vendor  string `json:"vendor"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

type CycloneDXComponent struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Version string `json:"version"`
	Purl    string `json:"purl,omitempty"`
	BomRef  string `json:"bom-ref,omitempty"`
}

// generateCycloneDXSBOM builds a CycloneDX document from dependency coordinates
// in the agent's "ecosystem:name@version" form.
func generateCycloneDXSBOM(dependencies []string) ([]byte, error) {
	bom := CycloneDXBOM{
		BomFormat:   "CycloneDX",
		SpecVersion: "1.4",
		Version:     1,
		Metadata: CycloneDXMetadata{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Tools: []CycloneDXTool{
				{Vendor: "Wisec", Name: "Wisec Agent", Version: version},
			},
		},
		Components: []CycloneDXComponent{},
	}

	for _, dep := range dependencies {
		eco, name, ver, ok := splitDependency(dep)
		if !ok {
			continue
		}
		purl := dependencyPURL(eco, name, ver)
		bom.Components = append(bom.Components, CycloneDXComponent{
			Type:    "library",
			Name:    name,
			Version: ver,
			Purl:    purl,
			BomRef:  purl,
		})
	}

	return json.MarshalIndent(bom, "", "  ")
}

// splitDependency parses an "ecosystem:name@version" coordinate. The name part
// may itself contain colons (e.g. Maven "group:artifact"), so only the first
// colon separates the ecosystem.
func splitDependency(dep string) (ecosystem, name, version string, ok bool) {
	dep = stripComment(dep)
	eco, rest, found := strings.Cut(dep, ":")
	if !found || eco == "" || rest == "" {
		return "", "", "", false
	}
	name, version, found = strings.Cut(rest, "@")
	if !found || version == "" {
		version = "latest"
	}
	return eco, name, version, true
}

// dependencyPURL renders a Package URL. Maven names carry the group and artifact
// separated by a colon, which maps to a "/" in the purl namespace.
func dependencyPURL(ecosystem, name, version string) string {
	if ecosystem == "maven" {
		name = strings.Replace(name, ":", "/", 1)
	}
	return fmt.Sprintf("pkg:%s/%s@%s", ecosystem, name, version)
}

// stripComment trims an inline "# ..." comment and surrounding whitespace.
func stripComment(s string) string {
	if idx := strings.Index(s, "#"); idx != -1 {
		s = s[:idx]
	}
	return strings.TrimSpace(s)
}
