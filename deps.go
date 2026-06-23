package main

import (
	"bufio"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// depParser parses a dependency manifest into "ecosystem:name@version" entries.
type depParser struct {
	file  string
	parse func(string) ([]string, error)
}

// parsers maps each supported manifest to its parser. build.gradle and its
// Kotlin variant share one parser.
var parsers = []depParser{
	{"go.mod", parseGoMod},
	{"package.json", parsePackageJSON},
	{"requirements.txt", parseRequirementsTxt},
	{"pom.xml", parsePomXML},
	{"build.gradle", parseBuildGradle},
	{"build.gradle.kts", parseBuildGradle},
}

// scanDependencies parses every supported manifest present in the working
// directory and returns the combined dependency list.
func scanDependencies() []string {
	var all []string
	found := 0
	for _, p := range parsers {
		if _, err := os.Stat(p.file); err != nil {
			continue
		}
		logVerbose("parsing %s", p.file)
		deps, err := p.parse(p.file)
		if err != nil {
			logVerbose("could not parse %s: %v", p.file, err)
			continue
		}
		all = append(all, deps...)
		found++
	}

	if found == 0 {
		logInfo("  no dependency manifest found")
	} else {
		logInfo("  %d dependencies across %d manifest(s)", len(all), found)
	}
	return all
}

func parseGoMod(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var deps []string
	inRequireBlock := false
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		switch {
		case strings.HasPrefix(line, "require ("):
			inRequireBlock = true
			continue
		case inRequireBlock && strings.HasPrefix(line, ")"):
			inRequireBlock = false
			continue
		case !inRequireBlock && !strings.HasPrefix(line, "require"):
			continue
		}

		if idx := strings.Index(line, "//"); idx != -1 { // drop "// indirect" etc.
			line = strings.TrimSpace(line[:idx])
		}
		fields := strings.Fields(strings.TrimPrefix(line, "require"))
		if len(fields) >= 2 {
			deps = append(deps, fmt.Sprintf("go:%s@%s", fields[0], fields[1]))
		}
	}
	return deps, scanner.Err()
}

func parsePackageJSON(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var pkg struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil, err
	}

	var deps []string
	for _, set := range []map[string]string{pkg.Dependencies, pkg.DevDependencies} {
		for name, version := range set {
			deps = append(deps, fmt.Sprintf("npm:%s@%s", name, version))
		}
	}
	return deps, nil
}

// requirementSpecifiers are the version operators recognised in requirements.txt.
var requirementSpecifiers = []string{"==", ">=", "<=", "~=", ">"}

func parseRequirementsTxt(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var deps []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		name, version := line, "latest"
		for _, sep := range requirementSpecifiers {
			if before, after, found := strings.Cut(line, sep); found {
				name = strings.TrimSpace(before)
				version = strings.TrimSpace(after)
				break
			}
		}
		deps = append(deps, fmt.Sprintf("pypi:%s@%s", name, version))
	}
	return deps, scanner.Err()
}

func parsePomXML(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var project struct {
		Dependencies []struct {
			GroupID    string `xml:"groupId"`
			ArtifactID string `xml:"artifactId"`
			Version    string `xml:"version"`
		} `xml:"dependencies>dependency"`
	}
	if err := xml.Unmarshal(data, &project); err != nil {
		return nil, err
	}

	var deps []string
	for _, dep := range project.Dependencies {
		if dep.GroupID == "" || dep.ArtifactID == "" {
			continue
		}
		version := dep.Version
		if version == "" || strings.HasPrefix(version, "${") { // unresolved property
			version = "unknown"
		}
		deps = append(deps, fmt.Sprintf("maven:%s:%s@%s", dep.GroupID, dep.ArtifactID, version))
	}
	return deps, nil
}

// gradleDepRegex matches "implementation 'g:a:v'" and "api(\"g:a:v\")" style
// declarations in both the Groovy and Kotlin Gradle DSLs.
var gradleDepRegex = regexp.MustCompile(`(?m)^\s*\w+\s*\(?["']([\w.-]+:[\w.-]+:[\w.-]+)["')]`)

func parseBuildGradle(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var deps []string
	for _, match := range gradleDepRegex.FindAllSubmatch(data, -1) {
		parts := strings.Split(string(match[1]), ":") // group:artifact:version
		if len(parts) != 3 {
			continue
		}
		deps = append(deps, fmt.Sprintf("maven:%s:%s@%s", parts[0], parts[1], parts[2]))
	}
	return deps, nil
}
