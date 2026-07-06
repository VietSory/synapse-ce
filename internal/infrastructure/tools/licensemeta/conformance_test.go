package licensemeta

import (
	"context"
	"fmt"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

type trivyLicensePair struct{ pkg, license string }

// TestPURLSpecConformance locks PURL-spec parsing across the ecosystems Synapse
// supports: a canonical package-URL maps to the expected (system, name, version), with qualifiers (?…)
// and subpath (#…) stripped, percent-encoding decoded (npm scope @), maven group:artifact joined, and
// an unmapped type / non-PURL rejected (fail-closed). Proves conformance to the standard, not a one-off.
func TestPURLSpecConformance(t *testing.T) {
	cases := []struct {
		purl                  string
		system, name, version string
		ok                    bool
	}{
		{"pkg:npm/lodash@4.17.21", "npm", "lodash", "4.17.21", true},
		{"pkg:npm/%40angular/core@17.0.0", "npm", "@angular/core", "17.0.0", true}, // scoped, percent-encoded @
		{"pkg:pypi/requests@2.31.0", "pypi", "requests", "2.31.0", true},
		{"pkg:golang/github.com/sirupsen/logrus@1.9.3", "go", "github.com/sirupsen/logrus", "1.9.3", true},
		{"pkg:maven/org.apache.commons/commons-lang3@3.14.0", "maven", "org.apache.commons:commons-lang3", "3.14.0", true}, // group:artifact
		{"pkg:cargo/serde@1.0.197", "cargo", "serde", "1.0.197", true},
		{"pkg:gem/rails@7.1.3", "rubygems", "rails", "7.1.3", true},
		{"pkg:npm/lodash@4.17.21?arch=amd64#subpath", "npm", "lodash", "4.17.21", true}, // qualifiers + subpath stripped
		{"pkg:deb/debian/curl@7.88", "", "", "", false},                                 // unmapped ecosystem -> fail-closed
		{"lodash@4.17.21", "", "", "", false},                                           // not a PURL -> fail-closed
	}
	for _, tc := range cases {
		sys, name, ver, ok := parsePURL(tc.purl)
		if ok != tc.ok || sys != tc.system || name != tc.name || ver != tc.version {
			t.Errorf("parsePURL(%q) = (%q,%q,%q,%v), want (%q,%q,%q,%v)",
				tc.purl, sys, name, ver, ok, tc.system, tc.name, tc.version, tc.ok)
		}
	}
}

func TestOSMetadataTrivyDebian9LicenseParityFixture(t *testing.T) {
	fixture := []trivyLicensePair{
		{"adduser", "GPL-2.0-only"}, {"adduser", "GPL-2.0-or-later"},
		{"apt", "GPL-2.0-or-later"}, {"apt", "GPL-2.0-only"},
		{"bash", "GPL-3.0-only"}, {"bash", "GPL-3.0-or-later"},
		{"bsdutils", "BSD-4-Clause"}, {"bsdutils", "MIT"}, {"bsdutils", "GPL-2.0-only"}, {"bsdutils", "LGPL-2.1-or-later"},
		{"curl", "curl"}, {"curl", "BSD-3-Clause"}, {"curl", "ISC"}, {"curl", "CC0-1.0"},
		{"git", "GPL-2.0-only"}, {"git", "LGPL-2.1-or-later"},
		{"git-man", "GPL-2.0-or-later"}, {"git-man", "LGPL-2.0-only"},
		{"libc-bin", "LGPL-2.1-only"}, {"libc-bin", "GPL-2.0-only"},
		{"libc6", "LGPL-2.1-only"}, {"libc6", "GPL-2.0-only"},
		{"libgnutls30", "LGPL-2.1-only"}, {"libgnutls30", "LGPL-2.0-or-later"}, {"libgnutls30", "LGPL-3.0-only"}, {"libgnutls30", "GPL-2.0-or-later"}, {"libgnutls30", "GPL-3.0-only"},
		{"libpython2.7-minimal", "GPL-2.0-only"}, {"libpython2.7-minimal", "LGPL-2.1-or-later"},
		{"libunistring0", "LGPL-3.0-or-later"}, {"libunistring0", "GPL-3.0-or-later"}, {"libunistring0", "GPL-2.0-or-later"}, {"libunistring0", "LGPL-3.0-only"}, {"libunistring0", "GPL-3.0-only"}, {"libunistring0", "GPL-2.0-only"},
		{"openssh-client", "BSD-2-Clause"}, {"openssh-client", "MIT"}, {"openssh-client", "public-domain"},
		{"perl", "Artistic-2.0"}, {"perl", "BSD-3-Clause"}, {"perl", "GPL-2.0-only"}, {"perl", "LGPL-2.1-only"},
		{"perl-modules-5.24", "Artistic-2.0"}, {"perl-modules-5.24", "GPL-1.0-or-later"}, {"perl-modules-5.24", "Zlib"},
	}

	byPkg := map[string]bool{}
	for _, p := range fixture {
		byPkg[p.pkg] = true
	}
	comps := make([]sbom.Component, 0, len(byPkg))
	for pkg := range byPkg {
		comps = append(comps, sbom.Component{Name: pkg, Version: "1", PURL: "pkg:deb/debian/" + pkg + "@1"})
	}
	out := NewOSMetadata().Enrich(context.Background(), comps)
	got := map[trivyLicensePair]bool{}
	for _, comp := range out {
		for _, lic := range comp.Licenses {
			got[trivyLicensePair{pkg: comp.Name, license: lic.SPDXID}] = true
		}
	}
	missing := []trivyLicensePair{}
	for _, want := range fixture {
		if !got[want] {
			missing = append(missing, want)
		}
	}
	coverage := float64(len(fixture)-len(missing)) / float64(len(fixture))
	if coverage < 0.95 {
		t.Fatalf("Trivy Debian 9 license fixture coverage = %.1f%%, missing %d/%d: %s", coverage*100, len(missing), len(fixture), formatMissingPairs(missing))
	}
}

func formatMissingPairs(missing []trivyLicensePair) string {
	if len(missing) == 0 {
		return ""
	}
	limit := len(missing)
	if limit > 8 {
		limit = 8
	}
	out := ""
	for i := 0; i < limit; i++ {
		if i > 0 {
			out += ", "
		}
		out += fmt.Sprintf("%s/%s", missing[i].pkg, missing[i].license)
	}
	if len(missing) > limit {
		out += fmt.Sprintf(", ... +%d", len(missing)-limit)
	}
	return out
}
