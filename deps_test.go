package main

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func writeTemp(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func assertDeps(t *testing.T, got []string, want ...string) {
	t.Helper()
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("deps = %v, want %v", got, want)
	}
}

func TestParseGoMod(t *testing.T) {
	path := writeTemp(t, "go.mod", `module example.com/x

go 1.22

require (
	github.com/a/b v1.2.3
	github.com/c/d v0.4.0 // indirect
)

require github.com/e/f v2.0.0
`)
	deps, err := parseGoMod(path)
	if err != nil {
		t.Fatal(err)
	}
	assertDeps(t, deps,
		"go:github.com/a/b@v1.2.3",
		"go:github.com/c/d@v0.4.0",
		"go:github.com/e/f@v2.0.0",
	)
}

func TestParseRequirementsTxt(t *testing.T) {
	path := writeTemp(t, "requirements.txt", `# comment
flask==2.0.1
requests>=2.25.0

django
`)
	deps, err := parseRequirementsTxt(path)
	if err != nil {
		t.Fatal(err)
	}
	assertDeps(t, deps,
		"pypi:flask@2.0.1",
		"pypi:requests@2.25.0",
		"pypi:django@latest",
	)
}

func TestParsePackageJSON(t *testing.T) {
	path := writeTemp(t, "package.json", `{
		"dependencies": {"react": "18.2.0"},
		"devDependencies": {"jest": "29.0.0"}
	}`)
	deps, err := parsePackageJSON(path)
	if err != nil {
		t.Fatal(err)
	}
	assertDeps(t, deps, "npm:react@18.2.0", "npm:jest@29.0.0")
}

func TestParsePomXML(t *testing.T) {
	path := writeTemp(t, "pom.xml", `<project>
	<dependencies>
		<dependency>
			<groupId>org.springframework</groupId>
			<artifactId>spring-core</artifactId>
			<version>6.1.0</version>
		</dependency>
		<dependency>
			<groupId>com.example</groupId>
			<artifactId>lib</artifactId>
			<version>${lib.version}</version>
		</dependency>
	</dependencies>
</project>`)
	deps, err := parsePomXML(path)
	if err != nil {
		t.Fatal(err)
	}
	assertDeps(t, deps,
		"maven:org.springframework:spring-core@6.1.0",
		"maven:com.example:lib@unknown",
	)
}

func TestParseBuildGradle(t *testing.T) {
	path := writeTemp(t, "build.gradle", `dependencies {
	implementation 'com.google.guava:guava:32.1.0'
	api("org.apache.commons:commons-lang3:3.12.0")
}`)
	deps, err := parseBuildGradle(path)
	if err != nil {
		t.Fatal(err)
	}
	assertDeps(t, deps,
		"maven:com.google.guava:guava@32.1.0",
		"maven:org.apache.commons:commons-lang3@3.12.0",
	)
}

func TestDependencyPURL(t *testing.T) {
	cases := map[string]string{
		"go:github.com/a/b@v1.0.0":             "pkg:go/github.com/a/b@v1.0.0",
		"npm:react@18.2.0":                     "pkg:npm/react@18.2.0",
		"maven:org.springframework:core@6.1.0": "pkg:maven/org.springframework/core@6.1.0",
	}
	for dep, want := range cases {
		eco, name, ver, ok := splitDependency(dep)
		if !ok {
			t.Fatalf("splitDependency(%q) failed", dep)
		}
		if got := dependencyPURL(eco, name, ver); got != want {
			t.Errorf("purl(%q) = %q, want %q", dep, got, want)
		}
	}
}
