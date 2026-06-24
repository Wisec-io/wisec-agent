package main

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

func TestDependencyFromPURL(t *testing.T) {
	cases := []struct {
		purl string
		want string
		ok   bool
	}{
		// Go modules: syft emits "golang", the engine expects "go".
		{"pkg:golang/github.com/gin-gonic/gin@v1.9.1", "go:github.com/gin-gonic/gin@v1.9.1", true},
		// PyPI.
		{"pkg:pypi/flask@2.0.0", "pypi:flask@2.0.0", true},
		// Scoped npm package (the @scope is percent-encoded in the purl).
		{"pkg:npm/%40angular/core@17.0.0", "npm:@angular/core@17.0.0", true},
		{"pkg:npm/react@18.2.0", "npm:react@18.2.0", true},
		// Maven: group/artifact in the purl, group:artifact for the engine.
		{"pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.0", "maven:com.fasterxml.jackson.core:jackson-databind@2.13.0", true},
		// Qualifiers and subpaths are stripped.
		{"pkg:golang/github.com/foo/bar@v1.0.0?type=module", "go:github.com/foo/bar@v1.0.0", true},
		// Missing version falls back to "latest".
		{"pkg:pypi/requests", "pypi:requests@latest", true},
		// Unsupported ecosystems are skipped, not mislabelled.
		{"pkg:apk/alpine/musl@1.2.4", "", false},
		{"pkg:deb/debian/libc6@2.31", "", false},
		{"", "", false},
		{"not-a-purl", "", false},
	}

	for _, c := range cases {
		got, ok := dependencyFromPURL(c.purl)
		if ok != c.ok || got != c.want {
			t.Errorf("dependencyFromPURL(%q) = (%q, %v), want (%q, %v)", c.purl, got, ok, c.want, c.ok)
		}
	}
}

func TestDependenciesFromSBOM(t *testing.T) {
	// CycloneDX 1.6 as emitted by syft: metadata.tools is an OBJECT, not the
	// legacy array. Extraction must not choke on it (regression guard).
	sbom := `{
	  "bomFormat": "CycloneDX",
	  "specVersion": "1.6",
	  "version": 1,
	  "metadata": {
	    "tools": {"components": [{"type": "application", "author": "anchore", "name": "syft", "version": "1.18.0"}]}
	  },
	  "components": [
	    {"type": "library", "name": "gin", "version": "v1.9.1", "purl": "pkg:golang/github.com/gin-gonic/gin@v1.9.1"},
	    {"type": "library", "name": "flask", "version": "2.0.0", "purl": "pkg:pypi/flask@2.0.0"},
	    {"type": "library", "name": "gin", "version": "v1.9.1", "purl": "pkg:golang/github.com/gin-gonic/gin@v1.9.1"},
	    {"type": "operating-system", "name": "alpine", "version": "3.19", "purl": "pkg:apk/alpine/alpine-baselayout@3.4.3"}
	  ]
	}`
	dir := t.TempDir()
	path := filepath.Join(dir, "wisec-bom.json")
	if err := os.WriteFile(path, []byte(sbom), 0o644); err != nil {
		t.Fatal(err)
	}

	got := dependenciesFromSBOM(path)
	sort.Strings(got)
	want := []string{"go:github.com/gin-gonic/gin@v1.9.1", "pypi:flask@2.0.0"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("dependenciesFromSBOM() = %v, want %v (OS packages skipped, duplicates removed)", got, want)
	}
}

func TestDependenciesFromSBOMMissingFile(t *testing.T) {
	if got := dependenciesFromSBOM(filepath.Join(t.TempDir(), "absent.json")); got != nil {
		t.Errorf("dependenciesFromSBOM(missing) = %v, want nil", got)
	}
}
