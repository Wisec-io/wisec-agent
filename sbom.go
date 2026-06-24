package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
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

// purlTypeToEcosystem maps Package URL types to the ecosystem tokens the Wisec
// analysis engine recognises for OSV lookups. syft and other SBOM tools emit
// "golang" where the engine expects "go", so the mapping is not a pass-through.
var purlTypeToEcosystem = map[string]string{
	"golang": "go",
	"go":     "go", // the agent's own generated SBOMs use "go"
	"npm":    "npm",
	"pypi":   "pypi",
	"maven":  "maven",
}

// dependenciesFromSBOM extracts dependency coordinates from a CycloneDX SBOM
// file. It lets the agent populate the dependency list from an SBOM produced by
// an external tool such as syft, which is the practical way to cover monorepos
// and multi-language repositories where no single manifest sits in the working
// directory. The returned coordinates feed CVE and typosquatting analysis.
func dependenciesFromSBOM(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		logVerbose("could not read SBOM %s for dependency extraction: %v", path, err)
		return nil
	}
	// Decode only the package URLs. Reusing the strict CycloneDXBOM type here is
	// wrong: it is tailored to the agent's own 1.4 output, whereas tools such as
	// syft emit CycloneDX 1.6 where metadata.tools is an object rather than an
	// array, which would make a full unmarshal fail. Reading just components
	// keeps extraction independent of the spec version and the producing tool.
	var bom struct {
		Components []struct {
			Purl string `json:"purl"`
		} `json:"components"`
	}
	if err := json.Unmarshal(data, &bom); err != nil {
		logVerbose("could not parse SBOM %s as CycloneDX: %v", path, err)
		return nil
	}

	seen := make(map[string]bool)
	var deps []string
	for _, c := range bom.Components {
		coord, ok := dependencyFromPURL(c.Purl)
		if !ok || seen[coord] {
			continue
		}
		seen[coord] = true
		deps = append(deps, coord)
	}
	return deps
}

// dependencyFromPURL converts a Package URL into the agent's
// "ecosystem:name@version" form. It returns ok=false for purl types the
// analysis engine cannot map to an OSV ecosystem, so unrelated components
// (OS packages, etc.) catalogued by syft are skipped rather than mislabelled.
func dependencyFromPURL(purl string) (string, bool) {
	rest, ok := strings.CutPrefix(purl, "pkg:")
	if !ok {
		return "", false
	}
	// Drop qualifiers (?k=v) and subpath (#...) which are not part of the coordinate.
	if i := strings.IndexAny(rest, "?#"); i != -1 {
		rest = rest[:i]
	}
	ptype, body, found := strings.Cut(rest, "/")
	if !found {
		return "", false
	}
	eco, known := purlTypeToEcosystem[strings.ToLower(ptype)]
	if !known {
		return "", false
	}

	coord, version, found := strings.Cut(body, "@")
	if !found || version == "" {
		version = "latest"
	}

	segments := strings.Split(coord, "/")
	for i, s := range segments {
		if decoded, err := url.PathUnescape(s); err == nil {
			segments[i] = decoded
		}
	}

	// Maven coordinates are "group:artifact"; every other ecosystem joins its
	// namespace and name with "/" (Go module paths, scoped npm packages).
	var name string
	if eco == "maven" && len(segments) >= 2 {
		group := strings.Join(segments[:len(segments)-1], ".")
		name = group + ":" + segments[len(segments)-1]
	} else {
		name = strings.Join(segments, "/")
	}
	if name == "" {
		return "", false
	}
	return fmt.Sprintf("%s:%s@%s", eco, name, version), true
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
