package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// Lockfiles record the versions actually installed, transitive dependencies
// included: that is what ships, and a vulnerability in a dependency of a
// dependency is still a vulnerability. Every parser here uses the standard
// library only: the agent has no third-party dependency and keeps it that way.

// parsePackageLock reads an npm package-lock.json, lockfile v1, v2 or v3.
func parsePackageLock(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var lock struct {
		// v2 and v3: every installed package keyed by its node_modules path.
		Packages map[string]struct {
			Name    string `json:"name"`
			Version string `json:"version"`
			Link    bool   `json:"link"`
		} `json:"packages"`
		// v1: a nested tree keyed by package name.
		Dependencies map[string]packageLockV1Dep `json:"dependencies"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, err
	}

	var deps []string
	if len(lock.Packages) > 0 {
		for key, p := range lock.Packages {
			// "" is the project itself; keys outside node_modules are the
			// project's own workspace packages, and a link points at one.
			i := strings.LastIndex(key, "node_modules/")
			if i == -1 || p.Link || p.Version == "" {
				continue
			}
			name := key[i+len("node_modules/"):]
			// An aliased install ("x": "npm:real@1.0") is keyed by the alias
			// and names the real package.
			if p.Name != "" {
				name = p.Name
			}
			deps = append(deps, fmt.Sprintf("npm:%s@%s", name, p.Version))
		}
		return deps, nil
	}
	collectPackageLockV1(lock.Dependencies, &deps)
	return deps, nil
}

type packageLockV1Dep struct {
	Version      string                      `json:"version"`
	Dependencies map[string]packageLockV1Dep `json:"dependencies"`
}

func collectPackageLockV1(tree map[string]packageLockV1Dep, deps *[]string) {
	for name, d := range tree {
		version := d.Version
		// An alias records "npm:real@1.0" as its version.
		if real, ok := strings.CutPrefix(version, "npm:"); ok {
			if at := strings.LastIndex(real, "@"); at > 0 {
				name, version = real[:at], real[at+1:]
			}
		}
		if version != "" {
			*deps = append(*deps, fmt.Sprintf("npm:%s@%s", name, version))
		}
		collectPackageLockV1(d.Dependencies, deps)
	}
}

// parseTOMLPackageLock reads the [[package]] tables of a poetry.lock or a
// uv.lock, which share that layout:
//
//	[[package]]
//	name = "requests"
//	version = "2.31.0"
//
// Only the name, the version and the source of each table are read, line by
// line, which is all a dependency inventory needs and keeps the agent free of
// a TOML library. The project itself and local packages (a directory, an
// editable or virtual source) are not dependencies and are skipped.
func parseTOMLPackageLock(path string) ([]string, error) {
	return parseLockTables(path, "pypi", false)
}

// parseCargoLock reads a Rust Cargo.lock, which uses the same [[package]]
// layout. A crate from a registry or a git repository carries a source line;
// one without is a member of the project's own workspace, not a dependency.
func parseCargoLock(path string) ([]string, error) {
	return parseLockTables(path, "cargo", true)
}

// parseLockTables reads the [[package]] tables of a TOML lockfile. When
// needSource is set, a package with no source line is local and skipped.
func parseLockTables(path, ecosystem string, needSource bool) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var deps []string
	var name, version string
	inPackage, atTop, inSource, local, hasSource := false, false, false, false, false
	flush := func() {
		if inPackage && name != "" && !local && (hasSource || !needSource) {
			if version == "" {
				version = "unknown"
			}
			deps = append(deps, fmt.Sprintf("%s:%s@%s", ecosystem, name, version))
		}
		name, version, local, hasSource = "", "", false, false
	}

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "[") {
			switch {
			case line == "[[package]]":
				flush()
				inPackage, atTop, inSource = true, true, false
			case line == "[package.source]":
				atTop, inSource = false, true
			case strings.HasPrefix(line, "[package.") || strings.HasPrefix(line, "[[package."):
				atTop, inSource = false, false
			default: // [metadata] and anything else ends the package list
				flush()
				inPackage, atTop, inSource = false, false, false
			}
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || !inPackage {
			continue
		}
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		switch {
		case atTop && key == "name":
			name = unquoteTOML(value)
		case atTop && key == "version":
			version = unquoteTOML(value)
		case atTop && key == "source":
			hasSource = true
			// uv: source = { editable = "." } / { virtual = "." } / { directory = "..." }
			// Matched on the key, so a registry URL that happens to contain one
			// of these words is not mistaken for a local source.
			for _, kind := range []string{"editable =", "virtual =", "directory =", "path ="} {
				if strings.Contains(value, kind) {
					local = true
				}
			}
		case inSource && key == "type":
			// poetry: [package.source] type = "directory" / "file"
			if t := unquoteTOML(value); t == "directory" || t == "file" {
				local = true
			}
		}
	}
	flush()
	return deps, scanner.Err()
}

func unquoteTOML(v string) string {
	if i := strings.Index(v, " #"); i != -1 {
		v = strings.TrimSpace(v[:i])
	}
	return strings.Trim(v, `"'`)
}

// parsePipfileLock reads a pipenv Pipfile.lock: the default and develop
// sections map each package to its pinned "==version".
func parsePipfileLock(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	type entry struct {
		Version  string `json:"version"`
		Path     string `json:"path"`
		Editable bool   `json:"editable"`
	}
	var lock struct {
		Default map[string]entry `json:"default"`
		Develop map[string]entry `json:"develop"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, err
	}

	var deps []string
	for _, section := range []map[string]entry{lock.Default, lock.Develop} {
		for name, e := range section {
			if e.Path != "" || e.Editable {
				continue // a local package, not a dependency
			}
			version := strings.TrimPrefix(e.Version, "==")
			if version == "" {
				version = "unknown" // a VCS reference: no version to check
			}
			deps = append(deps, fmt.Sprintf("pypi:%s@%s", name, version))
		}
	}
	return deps, nil
}

// parseComposerLock reads a PHP composer.lock: the packages and packages-dev
// lists carry each installed package's name and version.
func parseComposerLock(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	type pkg struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	var lock struct {
		Packages    []pkg `json:"packages"`
		PackagesDev []pkg `json:"packages-dev"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, err
	}

	var deps []string
	for _, list := range [][]pkg{lock.Packages, lock.PackagesDev} {
		for _, p := range list {
			if p.Name == "" {
				continue
			}
			version := p.Version
			if version == "" {
				version = "unknown"
			}
			// A branch checkout ("dev-main") is kept as written: it is not a
			// version, so the analysis lists it as unchecked.
			deps = append(deps, fmt.Sprintf("composer:%s@%s", p.Name, version))
		}
	}
	return deps, nil
}

// parseNuGetLock reads a .NET packages.lock.json, which lists the resolved
// version of every package per target framework. The same package under two
// frameworks is recorded once per version; a reference to another project of
// the solution is not a package.
func parseNuGetLock(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var lock struct {
		Dependencies map[string]map[string]struct {
			Type     string `json:"type"`
			Resolved string `json:"resolved"`
		} `json:"dependencies"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, err
	}

	seen := make(map[string]bool)
	var deps []string
	for _, framework := range lock.Dependencies {
		for name, p := range framework {
			if strings.EqualFold(p.Type, "Project") || p.Resolved == "" {
				continue
			}
			d := fmt.Sprintf("nuget:%s@%s", name, p.Resolved)
			if !seen[d] {
				seen[d] = true
				deps = append(deps, d)
			}
		}
	}
	return deps, nil
}

// parseGemfileLock reads a Ruby Gemfile.lock. The gems installed from a
// registry are the "specs:" of the GEM section, indented by four spaces
// ("    rails (7.1.2)"); deeper lines are their own requirements, and the GIT and
// PATH sections hold gems built from a repository or the project itself.
func parseGemfileLock(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var deps []string
	inGem, inSpecs := false, false
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		raw := strings.TrimRight(scanner.Text(), " \r")
		if raw == "" {
			inGem, inSpecs = false, false
			continue
		}
		if !strings.HasPrefix(raw, " ") { // a section header: GEM, GIT, PATH, PLATFORMS...
			inGem, inSpecs = raw == "GEM", false
			continue
		}
		if !inGem {
			continue
		}
		if strings.TrimSpace(raw) == "specs:" {
			inSpecs = true
			continue
		}
		if !inSpecs || !strings.HasPrefix(raw, "    ") || strings.HasPrefix(raw, "     ") {
			continue
		}
		name, rest, ok := strings.Cut(strings.TrimSpace(raw), " (")
		if !ok {
			continue
		}
		version := strings.TrimSuffix(rest, ")")
		// A platform-specific gem appends its platform: nokogiri (1.15.4-x86_64-linux).
		// RubyGems versions never contain a dash otherwise.
		version, _, _ = strings.Cut(version, "-")
		deps = append(deps, fmt.Sprintf("gem:%s@%s", name, version))
	}
	return deps, scanner.Err()
}
