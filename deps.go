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

// depParser parses a dependency file into "ecosystem:name@version" entries.
type depParser struct {
	file  string
	parse func(string) ([]string, error)
	// supersededBy lists lockfiles that, when present, replace this manifest.
	// A manifest declares what is acceptable (a range such as ^4.17.0 or
	// >=3.2), a lockfile records what was actually installed, and only an
	// installed version can be checked against a vulnerability database.
	supersededBy []string
}

// parsers maps each supported file to its parser. Lockfiles come first so the
// log reads in the order the files are used. build.gradle and its Kotlin
// variant share one parser.
var parsers = []depParser{
	{file: "package-lock.json", parse: parsePackageLock},
	{file: "poetry.lock", parse: parseTOMLPackageLock},
	{file: "uv.lock", parse: parseTOMLPackageLock},
	{file: "Pipfile.lock", parse: parsePipfileLock},
	{file: "Cargo.lock", parse: parseCargoLock},
	{file: "composer.lock", parse: parseComposerLock},
	{file: "packages.lock.json", parse: parseNuGetLock},
	{file: "Gemfile.lock", parse: parseGemfileLock},
	{file: "go.mod", parse: parseGoMod},
	{file: "package.json", parse: parsePackageJSON, supersededBy: []string{"package-lock.json"}},
	{file: "requirements.txt", parse: parseRequirementsTxt, supersededBy: []string{"poetry.lock", "uv.lock", "Pipfile.lock"}},
	{file: "pom.xml", parse: parsePomXML},
	{file: "build.gradle", parse: parseBuildGradle},
	{file: "build.gradle.kts", parse: parseBuildGradle},
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// scanDependencies parses every supported dependency file present in the
// working directory and returns the combined, de-duplicated dependency list.
func scanDependencies() []string {
	var all []string
	seen := make(map[string]bool)
	found := 0
	for _, p := range parsers {
		if !fileExists(p.file) {
			continue
		}
		if lock := firstExisting(p.supersededBy); lock != "" {
			logVerbose("skipping %s: %s records the installed versions", p.file, lock)
			continue
		}
		logVerbose("parsing %s", p.file)
		deps, err := p.parse(p.file)
		if err != nil {
			logVerbose("could not parse %s: %v", p.file, err)
			continue
		}
		for _, d := range deps {
			if !seen[d] {
				seen[d] = true
				all = append(all, d)
			}
		}
		found++
	}

	if found == 0 {
		logInfo("  no dependency manifest found")
	} else {
		logInfo("  %d dependencies across %d file(s)", len(all), found)
	}
	return all
}

func firstExisting(paths []string) string {
	for _, p := range paths {
		if fileExists(p) {
			return p
		}
	}
	return ""
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

// parsePackageJSON records the declared ranges as they are. They are not
// versions, so the analysis lists them as unchecked; package-lock.json, when
// present, replaces this file with the installed versions.
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

// requirementNameEnd finds where a requirement's project name stops: at its
// extras, its version specifier, its environment marker or a direct reference.
var requirementNameEnd = regexp.MustCompile(`[\[<>=!~;@\s]`)

// exactPin matches a specifier that names exactly one version: "==1.2.3" or
// "===1.2.3", with no second clause and no wildcard.
var exactPin = regexp.MustCompile(`^===?\s*([^,*\s]+)$`)

// parseRequirementsTxt reads a pip requirements file. Only an exact pin (==)
// is recorded as a version. Any other specifier (>=, ~=, several clauses) is
// recorded as written: it is not a version, so the analysis lists it as
// unchecked rather than checking a version that may not be the one installed.
// Until v1.4.0, "django>=3.2" was recorded as django@3.2 and drew the
// vulnerabilities of 3.2 whatever was actually installed.
func parseRequirementsTxt(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	// A trailing backslash continues the requirement on the next line.
	text := strings.ReplaceAll(strings.ReplaceAll(string(data), "\r\n", "\n"), "\\\n", " ")

	var deps []string
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		// pip only treats "#" as a comment at the start or after whitespace,
		// so a URL fragment (#egg=) is not cut.
		if strings.HasPrefix(line, "#") {
			continue
		}
		if i := strings.Index(line, " #"); i != -1 {
			line = strings.TrimSpace(line[:i])
		}
		// Options (-r, -c, -e, --index-url) and per-requirement options such as
		// --hash are not requirements.
		if line == "" || strings.HasPrefix(line, "-") {
			continue
		}
		if i := strings.Index(line, " --"); i != -1 {
			line = strings.TrimSpace(line[:i])
		}
		// A bare path or URL names no project.
		if strings.ContainsAny(line[:1], "./") || strings.Contains(strings.SplitN(line, " ", 2)[0], "://") {
			continue
		}
		if dep, ok := parseRequirement(line); ok {
			deps = append(deps, dep)
		}
	}
	return deps, nil
}

func parseRequirement(line string) (string, bool) {
	// The environment marker says where the requirement applies, not which
	// version: drop it.
	if i := strings.Index(line, ";"); i != -1 {
		line = strings.TrimSpace(line[:i])
	}
	nameEnd := len(line)
	if loc := requirementNameEnd.FindStringIndex(line); loc != nil {
		nameEnd = loc[0]
	}
	name := line[:nameEnd]
	if name == "" {
		return "", false
	}
	rest := strings.TrimSpace(line[nameEnd:])
	if strings.HasPrefix(rest, "[") { // extras: celery[redis]==5.3.0
		if i := strings.Index(rest, "]"); i != -1 {
			rest = strings.TrimSpace(rest[i+1:])
		}
	}

	switch {
	case rest == "":
		return fmt.Sprintf("pypi:%s@latest", name), true
	case strings.HasPrefix(rest, "@"):
		// A direct reference (name @ https://...) carries no version.
		return fmt.Sprintf("pypi:%s@unknown", name), true
	}
	spec := strings.Join(strings.Fields(rest), "")
	if m := exactPin.FindStringSubmatch(spec); m != nil {
		return fmt.Sprintf("pypi:%s@%s", name, m[1]), true
	}
	return fmt.Sprintf("pypi:%s@%s", name, spec), true
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
