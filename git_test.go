package main

import "testing"

func TestNormalizeGitleaksReport(t *testing.T) {
	cases := []struct {
		name   string
		report string
		want   string
	}{
		// gitleaks writes the empty result with a trailing newline; it must not
		// be mistaken for findings.
		{"empty array with newline", "[]\n", "[]"},
		{"empty array with whitespace", "  [ ]  ", "[]"},
		{"empty file", "", "[]"},
		{"real findings are kept", `[{"Description":"AWS key","File":"a.go"}]`,
			`[{"Description":"AWS key","File":"a.go"}]`},
		// A non-array payload is surfaced as-is rather than silently dropped.
		{"non-array payload preserved", `{"unexpected":true}`, `{"unexpected":true}`},
	}

	for _, c := range cases {
		if got := normalizeGitleaksReport([]byte(c.report)); got != c.want {
			t.Errorf("%s: normalizeGitleaksReport(%q) = %q, want %q", c.name, c.report, got, c.want)
		}
	}
}
