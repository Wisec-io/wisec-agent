package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// A SARIF result as Semgrep writes it, with the quoted lines, a proposed fix and
// an embedded artifact. Only ruleId, location, line and message are read by Wisec.
const sarifWithCode = `{
  "version": "2.1.0",
  "runs": [{
    "tool": {"driver": {"name": "semgrep", "version": "1.90.0"}},
    "artifacts": [{"location": {"uri": "app.py"}, "contents": {"text": "password = 'hunter2-full-file'"}}],
    "results": [{
      "ruleId": "python.lang.security.hardcoded-password",
      "message": {"text": "Hardcoded password"},
      "locations": [{"physicalLocation": {
        "artifactLocation": {"uri": "app.py"},
        "region": {"startLine": 3, "snippet": {"text": "password = 'hunter2-snippet'"}},
        "contextRegion": {"startLine": 1, "endLine": 5, "snippet": {"text": "def f():\n  password = 'hunter2-context'"}}
      }}],
      "fixes": [{"artifactChanges": [{"artifactLocation": {"uri": "app.py"},
        "replacements": [{"deletedRegion": {"startLine": 3}, "insertedContent": {"text": "password = os.environ['hunter2-fix']"}}]}]}]
    }]
  }]
}`

func TestStripSARIFCodeRemovesQuotedSource(t *testing.T) {
	out, err := stripSARIFCode([]byte(sarifWithCode))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "hunter2") {
		t.Errorf("source code left the CI: %s", out)
	}

	// What the analysis reads must survive.
	var doc struct {
		Runs []struct {
			Tool struct {
				Driver struct{ Name, Version string }
			} `json:"tool"`
			Results []struct {
				RuleID    string                `json:"ruleId"`
				Message   struct{ Text string } `json:"message"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct{ URI string } `json:"artifactLocation"`
						Region           struct {
							StartLine int `json:"startLine"`
						} `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	r := doc.Runs[0].Results[0]
	loc := r.Locations[0].PhysicalLocation
	if r.RuleID != "python.lang.security.hardcoded-password" || r.Message.Text == "" ||
		loc.ArtifactLocation.URI != "app.py" || loc.Region.StartLine != 3 ||
		doc.Runs[0].Tool.Driver.Name != "semgrep" {
		t.Errorf("stripping removed a field the analysis needs: %s", out)
	}
}

func TestStripSARIFCodeRejectsNonJSON(t *testing.T) {
	if _, err := stripSARIFCode([]byte("password = 'hunter2'")); err == nil {
		t.Error("a non-JSON report must be refused, not passed through")
	}
}

const testImageHex = "1111111111111111111111111111111111111111111111111111111111111111"

func TestImageDigestsFromEnv(t *testing.T) {
	cases := []struct {
		name string
		env  string
		want []string
	}{
		{"unset", "", nil},
		{"one image", "rg.fr-par.scw.cloud/acme/api@sha256:" + testImageHex,
			[]string{"rg.fr-par.scw.cloud/acme/api@sha256:" + testImageHex}},
		{"several, any separator, digest lowercased, duplicates merged",
			"a/api@sha256:" + strings.ToUpper(testImageHex) + ", b/web:1.2@sha256:" + testImageHex + "\n a/api@sha256:" + testImageHex,
			[]string{"a/api@sha256:" + testImageHex, "b/web:1.2@sha256:" + testImageHex}},
		{"a tag alone is not a digest", "a/api:latest", nil},
		{"wrong algorithm", "a/api@sha512:" + testImageHex, nil},
		{"not hex", "a/api@sha256:" + strings.Repeat("z", 64), nil},
		{"no name", "@sha256:" + testImageHex, nil},
		{"invalid ones are dropped, valid ones kept", "a/api:latest b/web@sha256:" + testImageHex,
			[]string{"b/web@sha256:" + testImageHex}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("WISEC_IMAGE_DIGESTS", c.env)
			got := imageDigestsFromEnv()
			if strings.Join(got, "|") != strings.Join(c.want, "|") {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
}
