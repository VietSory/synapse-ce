package licensemeta

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

func TestParsePURL(t *testing.T) {
	cases := []struct {
		purl           string
		sys, name, ver string
		ok             bool
	}{
		{"pkg:npm/lodash@4.17.21", "npm", "lodash", "4.17.21", true},
		{"pkg:npm/%40babel/core@7.0.0", "npm", "@babel/core", "7.0.0", true},
		{"pkg:pypi/django@4.2", "pypi", "django", "4.2", true},
		{"pkg:maven/org.apache.commons/commons-lang3@3.12", "maven", "org.apache.commons:commons-lang3", "3.12", true},
		{"pkg:golang/github.com/gin-gonic/gin@1.9.1", "go", "github.com/gin-gonic/gin", "1.9.1", true},
		{"pkg:gem/rails@7.0?x=y", "rubygems", "rails", "7.0", true},
		{"pkg:cocoapods/AFNetworking@4.0", "", "", "", false}, // unsupported eco
		{"not-a-purl", "", "", "", false},
		{"pkg:npm/noversion", "", "", "", false},
	}
	for _, c := range cases {
		sys, name, ver, ok := parsePURL(c.purl)
		if ok != c.ok || (ok && (sys != c.sys || name != c.name || ver != c.ver)) {
			t.Errorf("parsePURL(%q) = (%q,%q,%q,%v), want (%q,%q,%q,%v)",
				c.purl, sys, name, ver, ok, c.sys, c.name, c.ver, c.ok)
		}
	}
}

func TestEnrichResolvesAndClassifiesReasons(t *testing.T) {
	mux := http.NewServeMux()
	// lodash -> MIT
	mux.HandleFunc("/v3/systems/npm/packages/lodash/versions/4.17.21", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"licenses":["MIT"]}`))
	})
	// no-license -> empty licenses (no_license_declared)
	mux.HandleFunc("/v3/systems/npm/packages/no-license/versions/1.0.0", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"licenses":[]}`))
	})
	// everything else -> 404 (metadata_missing)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	e := New(srv.URL, srv.Client())
	comps := []sbom.Component{
		{Name: "already", Version: "1", PURL: "pkg:npm/already@1", Licenses: []sbom.License{{SPDXID: "Apache-2.0"}}},
		{Name: "lodash", Version: "4.17.21", PURL: "pkg:npm/lodash@4.17.21"},
		{Name: "no-license", Version: "1.0.0", PURL: "pkg:npm/no-license@1.0.0"},
		{Name: "missing", Version: "9.9.9", PURL: "pkg:npm/missing@9.9.9"},
		{Name: "weird", Version: "1", PURL: "pkg:cocoapods/weird@1"},
	}
	out := e.Enrich(context.Background(), comps)

	if out[0].LicenseSource != "sbom" || out[0].LicenseConfidence != "declared" {
		t.Errorf("pre-declared license: source/conf = %q/%q", out[0].LicenseSource, out[0].LicenseConfidence)
	}
	if len(out[1].Licenses) != 1 || out[1].Licenses[0].SPDXID != "MIT" || out[1].LicenseSource != "registry" {
		t.Errorf("lodash not resolved from registry: %+v", out[1])
	}
	if out[2].UnknownReason != sbom.ReasonNoLicenseDeclared {
		t.Errorf("no-license reason = %q, want no_license_declared", out[2].UnknownReason)
	}
	if out[3].UnknownReason != sbom.ReasonMetadataMissing {
		t.Errorf("missing reason = %q, want metadata_missing", out[3].UnknownReason)
	}
	if out[4].UnknownReason != sbom.ReasonUnsupportedEco {
		t.Errorf("unsupported eco reason = %q, want unsupported_ecosystem", out[4].UnknownReason)
	}
}

func TestEnrichRegistryOutageDegrades(t *testing.T) {
	// Server immediately closed -> connection error -> registry_unavailable, no crash.
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	srv.Close()
	e := New(srv.URL, srv.Client())
	comps := []sbom.Component{{Name: "lodash", Version: "4.17.21", PURL: "pkg:npm/lodash@4.17.21"}}
	out := e.Enrich(context.Background(), comps)
	if out[0].UnknownReason != sbom.ReasonRegistryUnavailable {
		t.Errorf("outage reason = %q, want registry_unavailable", out[0].UnknownReason)
	}
}

func TestComputeLicenseCoverage(t *testing.T) {
	comps := []sbom.Component{
		{Licenses: []sbom.License{{SPDXID: "MIT"}}},
		{Licenses: []sbom.License{{SPDXID: "Apache-2.0"}}},
		{},
	}
	c := sbom.ComputeLicenseCoverage(comps)
	if c.Total != 3 || c.Detected != 2 || c.Unknown != 1 {
		t.Errorf("coverage = %+v", c)
	}
	if c.Pct < 66 || c.Pct > 67 {
		t.Errorf("pct = %.2f, want ~66.7", c.Pct)
	}
}

func TestChainResolvesOSBeforeRegistry(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v3/systems/debian/packages/apt/versions/2.6.1", func(w http.ResponseWriter, _ *http.Request) {
		t.Fatalf("registry should not be called for OS metadata resolved package")
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	out := NewChain(NewOSMetadata(), New(srv.URL, srv.Client())).Enrich(context.Background(), []sbom.Component{{
		Name:    "apt",
		Version: "2.6.1",
		PURL:    "pkg:deb/debian/apt@2.6.1",
	}})
	want := map[string]bool{"GPL-2.0-or-later": true, "GPL-2.0-only": true}
	for _, lic := range out[0].Licenses {
		delete(want, lic.SPDXID)
	}
	if len(want) > 0 {
		t.Fatalf("apt license = %+v, missing Trivy parity licenses %+v", out[0].Licenses, want)
	}
	if out[0].LicenseSource != sbom.LicenseSourceOSMetadata || out[0].LicenseConfidence != "metadata" {
		t.Fatalf("apt provenance = %q/%q, want os-metadata/metadata", out[0].LicenseSource, out[0].LicenseConfidence)
	}
}

func TestOSMetadataMatchesTrivyRestrictedLicensePairs(t *testing.T) {
	cases := map[string][]string{
		"adduser":              {"GPL-2.0-only", "GPL-2.0-or-later"},
		"bash":                 {"GPL-3.0-only", "GPL-3.0-or-later"},
		"coreutils":            {"GPL-3.0-only", "GPL-3.0-or-later"},
		"libc-bin":             {"LGPL-2.1-only", "GPL-2.0-only"},
		"libc6":                {"LGPL-2.1-only", "GPL-2.0-only"},
		"libgnutls30":          {"LGPL-2.1-only", "LGPL-2.0-or-later", "LGPL-3.0-only", "GPL-2.0-or-later", "GPL-3.0-only"},
		"libunistring0":        {"LGPL-3.0-or-later", "GPL-3.0-or-later", "GPL-2.0-or-later", "LGPL-3.0-only", "GPL-3.0-only", "GPL-2.0-only"},
		"libpython2.7-minimal": {"GPL-2.0-only", "LGPL-2.1-or-later"},
		"perl":                 {"GPL-1.0-only", "GPL-1.0-or-later", "GPL-2.0-only", "GPL-2.0-or-later", "Artistic-2.0"},
		"libperl5.24":          {"GPL-1.0-only", "GPL-1.0-or-later", "GPL-2.0-only", "GPL-2.0-or-later", "Artistic-2.0"},
		"perl-modules-5.24":    {"GPL-1.0-only", "GPL-1.0-or-later", "GPL-2.0-only", "GPL-2.0-or-later", "Artistic-2.0"},
		"git":                  {"GPL-2.0-only", "GPL-2.0-or-later", "LGPL-2.0-only", "LGPL-2.0-or-later", "LGPL-2.1-only", "LGPL-2.1-or-later"},
	}

	comps := make([]sbom.Component, 0, len(cases))
	for name := range cases {
		comps = append(comps, sbom.Component{Name: name, Version: "1", PURL: "pkg:deb/debian/" + name + "@1", Licenses: []sbom.License{{SPDXID: "sha256:deadbeef"}}})
	}
	out := NewOSMetadata().Enrich(context.Background(), comps)
	for _, comp := range out {
		got := map[string]bool{}
		for _, lic := range comp.Licenses {
			if strings.HasPrefix(lic.SPDXID, "sha256:") {
				t.Fatalf("%s kept unresolved license evidence: %+v", comp.Name, comp.Licenses)
			}
			got[lic.SPDXID] = true
		}
		for _, want := range cases[comp.Name] {
			if !got[want] {
				t.Fatalf("%s licenses = %+v, missing %s", comp.Name, comp.Licenses, want)
			}
		}
	}
}

func TestEnrichTreatsPlaceholderEvidenceAsUnresolved(t *testing.T) {
	// A component carrying only placeholder evidence (sha256:/LicenseRef-) must NOT be
	// stamped as a declared SBOM license; with no PURL it resolves to a local-component
	// reason and the placeholder is dropped (no network call is made).
	out := New("", nil).Enrich(context.Background(), []sbom.Component{
		{Name: "x", Version: "1.0.0", Licenses: []sbom.License{{SPDXID: "sha256:deadbeef"}}},
	})
	c := out[0]
	if c.LicenseSource == sbom.LicenseSourceSBOM || c.LicenseConfidence == "declared" {
		t.Fatalf("placeholder mislabeled as declared: source=%q confidence=%q", c.LicenseSource, c.LicenseConfidence)
	}
	if len(c.Licenses) != 0 {
		t.Fatalf("placeholder license should be dropped, got %+v", c.Licenses)
	}
	if c.UnknownReason != sbom.ReasonLocalComponent {
		t.Fatalf("UnknownReason = %q, want %q", c.UnknownReason, sbom.ReasonLocalComponent)
	}
}
