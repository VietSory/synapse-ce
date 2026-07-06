package sbom

import (
	"reflect"
	"testing"
)

func TestCoverageByEcosystem(t *testing.T) {
	s := SBOM{Components: []Component{
		{Name: "django", Version: "3.2", PURL: "pkg:pypi/django@3.2"},
		{Name: "flask", Version: "", PURL: "pkg:pypi/flask"},           // unresolved (no version)
		{Name: "requests", Version: "^2.0", PURL: "pkg:pypi/requests"}, // unresolved (floating range, not a pinned version)
		{Name: "left-pad", Version: "1.0.0", PURL: "pkg:npm/left-pad@1.0.0"},
		{Name: "github.com/foo/bar", Version: "v1.2.0", PURL: "pkg:golang/github.com/foo/bar@v1.2.0"}, // v+digit resolves
		{Name: "self", Version: "", PURL: ""},                                                         // first-party/local, no PURL
	}}
	got := CoverageByEcosystem(s)
	want := []EcosystemCoverage{
		{Ecosystem: "(no purl)", Components: 1, Resolved: 0},
		{Ecosystem: "golang", Components: 1, Resolved: 1},
		{Ecosystem: "npm", Components: 1, Resolved: 1},
		{Ecosystem: "pypi", Components: 3, Resolved: 1}, // django resolved; flask (empty) + requests (^2.0 floating) not
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("coverage mismatch:\n got %+v\nwant %+v", got, want)
	}
	// The tally must account for every component (no silent drop).
	total := 0
	for _, c := range got {
		total += c.Components
	}
	if total != len(s.Components) {
		t.Errorf("coverage must count every component: summed %d, have %d", total, len(s.Components))
	}
}

func TestCoverageByEcosystemEmpty(t *testing.T) {
	if got := CoverageByEcosystem(SBOM{}); len(got) != 0 {
		t.Errorf("an empty SBOM must yield no coverage rows, got %+v", got)
	}
}

func TestEcosystemFromPURL(t *testing.T) {
	cases := map[string]string{
		"pkg:pypi/django@3.2":              "pypi",
		"pkg:npm/%40scope/pkg@1.0":         "npm",
		"pkg:golang/github.com/foo/bar@v1": "golang",
		"pkg:Maven/org.x/y@1":              "maven", // type lower-cased
		"":                                 noPURL,
		"not-a-purl":                       noPURL,
		"pkg:pypi":                         noPURL, // no '/' → malformed
	}
	for in, want := range cases {
		if got := ecosystemFromPURL(in); got != want {
			t.Errorf("ecosystemFromPURL(%q) = %q, want %q", in, got, want)
		}
	}
}
