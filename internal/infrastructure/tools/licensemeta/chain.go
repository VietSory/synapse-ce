package licensemeta

import (
	"context"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Chain runs multiple license enrichers in order. Later enrichers only see the
// components as mutated by earlier ones, so metadata with stronger local
// provenance can resolve first and registry lookups fill the remaining gaps.
type Chain struct{ enrichers []ports.LicenseEnricher }

// NewChain returns a best-effort chain. Nil enrichers are ignored.
func NewChain(enrichers ...ports.LicenseEnricher) *Chain {
	out := make([]ports.LicenseEnricher, 0, len(enrichers))
	for _, e := range enrichers {
		if e != nil {
			out = append(out, e)
		}
	}
	return &Chain{enrichers: out}
}

var _ ports.LicenseEnricher = (*Chain)(nil)

func (c *Chain) Enrich(ctx context.Context, comps []sbom.Component) []sbom.Component {
	for _, e := range c.enrichers {
		comps = e.Enrich(ctx, comps)
	}
	return comps
}

// OSMetadata resolves common licenses for OS packages when the SBOM did not
// include license choices. It uses deterministic package metadata aliases only;
// it never shells out or reads host package databases.
type OSMetadata struct{}

func NewOSMetadata() *OSMetadata { return &OSMetadata{} }

var _ ports.LicenseEnricher = (*OSMetadata)(nil)

func (OSMetadata) Enrich(_ context.Context, comps []sbom.Component) []sbom.Component {
	for i := range comps {
		c := &comps[i]
		if len(c.Licenses) > 0 && !onlyUnresolvedLicenseEvidence(c.Licenses) {
			continue
		}
		if !isOSPackagePURL(c.PURL) {
			continue
		}
		lics := osPackageLicenses(c.Name)
		if len(lics) == 0 {
			c.UnknownReason = sbom.ReasonMetadataMissing
			c.LicenseConfidence = "unknown"
			continue
		}
		if onlyUnresolvedLicenseEvidence(c.Licenses) {
			c.Licenses = nil
		}
		c.Licenses = append(c.Licenses, lics...)
		c.LicenseSource = sbom.LicenseSourceOSMetadata
		c.LicenseConfidence = "metadata"
		c.UnknownReason = ""
	}
	return comps
}

func onlyUnresolvedLicenseEvidence(licenses []sbom.License) bool {
	if len(licenses) == 0 {
		return false
	}
	for _, lic := range licenses {
		id := strings.ToLower(strings.TrimSpace(lic.SPDXID))
		if id == "" {
			id = strings.ToLower(strings.TrimSpace(lic.Name))
		}
		if id == "" {
			continue
		}
		if !strings.HasPrefix(id, "sha256:") && !strings.HasPrefix(id, "licenseref-") && id != "unknown" && id != "other" {
			return false
		}
	}
	return true
}

func isOSPackagePURL(purl string) bool {
	return strings.HasPrefix(purl, "pkg:deb/") || strings.HasPrefix(purl, "pkg:apk/") || strings.HasPrefix(purl, "pkg:rpm/")
}

func osPackageLicenses(name string) []sbom.License {
	ids, ok := osLicenseByPackage[strings.ToLower(strings.TrimSpace(name))]
	if !ok {
		return nil
	}
	out := make([]sbom.License, 0, len(ids))
	for _, id := range ids {
		out = append(out, sbom.License{SPDXID: id, Name: id})
	}
	return out
}

var osLicenseByPackage = map[string][]string{
	"adduser":                {"GPL-2.0-only", "GPL-2.0-or-later"},
	"apt":                    {"GPL-2.0-or-later", "GPL-2.0-only"},
	"base-files":             {"GPL-2.0-or-later"},
	"base-passwd":            {"GPL-2.0-only", "PD"},
	"bash":                   {"GPL-3.0-only", "GPL-3.0-or-later"},
	"bsdutils":               {"BSD-4-Clause", "GPL-2.0-only", "GPL-2.0-or-later", "GPL-3.0-only", "GPL-3.0-or-later", "LGPL-2.0-only", "LGPL-2.0-or-later", "LGPL-2.1-only", "LGPL-2.1-or-later", "LGPL-3.0-only", "LGPL-3.0-or-later"},
	"busybox":                {"GPL-2.0-only"},
	"bzip2":                  {"bzip2-1.0.6", "GPL-2.0-only"},
	"ca-certificates":        {"GPL-2.0-only", "GPL-2.0-or-later", "MPL-2.0"},
	"coreutils":              {"GPL-3.0-only", "GPL-3.0-or-later"},
	"curl":                   {"curl", "BSD-3-Clause", "ISC", "CC0-1.0"},
	"dash":                   {"GPL-2.0-or-later"},
	"debian-archive-keyring": {"GPL-2.0-or-later"},
	"dpkg":                   {"GPL-2.0-or-later"},
	"e2fslibs":               {"GPL-2.0-only", "LGPL-2.0-only"},
	"e2fsprogs":              {"GPL-2.0-only", "LGPL-2.0-only"},
	"findutils":              {"GPL-3.0-only"},
	"gcc-6-base":             {"GPL-2.0-or-later", "GPL-3.0-only", "GPL-2.0-only"},
	"git":                    {"GPL-2.0-only", "GPL-2.0-or-later", "LGPL-2.0-only", "LGPL-2.0-or-later", "LGPL-2.1-only", "LGPL-2.1-or-later"},
	"git-man":                {"GPL-2.0-only", "GPL-2.0-or-later", "LGPL-2.0-only", "LGPL-2.0-or-later", "LGPL-2.1-only", "LGPL-2.1-or-later"},
	"grep":                   {"GPL-3.0-or-later"},
	"gzip":                   {"GPL-2.0-or-later"},
	"hostname":               {"GPL-2.0-only"},
	"iputils-ping":           {"GPL-2.0-or-later"},
	"libacl1":                {"LGPL-2.1-only", "GPL-2.0-or-later"},
	"libapt-pkg5.0":          {"GPL-2.0-only", "GPL-2.0-or-later"},
	"libattr1":               {"GPL-2.0-only"},
	"libblkid1":              {"BSD-4-Clause", "GPL-2.0-only", "GPL-2.0-or-later", "GPL-3.0-only", "GPL-3.0-or-later", "LGPL-2.0-only", "LGPL-2.0-or-later", "LGPL-2.1-only", "LGPL-2.1-or-later", "LGPL-3.0-only", "LGPL-3.0-or-later"},
	"libbsd0":                {"BSD-2-Clause", "BSD-3-Clause", "BSD-4-Clause", "ISC", "MIT", "public-domain"},
	"libbz2-1.0":             {"bzip2-1.0.6", "GPL-2.0-only"},
	"libc-bin":               {"LGPL-2.1-only", "GPL-2.0-only"},
	"libc6":                  {"LGPL-2.1-only", "GPL-2.0-only"},
	"libcap-ng0":             {"LGPL-2.1-only", "GPL-2.0-only", "GPL-3.0-only"},
	"libcurl3":               {"curl", "BSD-3-Clause", "ISC", "CC0-1.0"},
	"libcurl3-gnutls":        {"curl", "BSD-3-Clause", "ISC", "CC0-1.0"},
	"libelf1":                {"GPL-2.0-only", "GPL-3.0-only", "LGPL-2.0-or-later"},
	"libffi6":                {"GPL-2.0-or-later"},
	"libfdisk1":              {"BSD-4-Clause", "GPL-2.0-only", "GPL-2.0-or-later", "GPL-3.0-only", "GPL-3.0-or-later", "LGPL-2.0-only", "LGPL-2.0-or-later", "LGPL-2.1-only", "LGPL-2.1-or-later", "LGPL-3.0-only", "LGPL-3.0-or-later"},
	"libgcrypt20":            {"LGPL-2.0-or-later", "GPL-2.0-only"},
	"libgmp10":               {"LGPL-3.0-only", "GPL-2.0-only", "GPL-3.0-only", "GPL-2.0-or-later"},
	"libgnutls30":            {"LGPL-2.1-only", "LGPL-2.0-or-later", "LGPL-3.0-only", "GPL-2.0-or-later", "GPL-3.0-only"},
	"libgssapi-krb5-2":       {"GPL-2.0-only"},
	"libidn11":               {"GPL-2.0-or-later"},
	"libidn2-0":              {"GPL-2.0-or-later"},
	"libk5crypto3":           {"GPL-2.0-only"},
	"libkrb5-3":              {"GPL-2.0-only"},
	"libksba8":               {"GPL-3.0-only"},
	"libmount1":              {"BSD-4-Clause", "GPL-2.0-only", "GPL-2.0-or-later", "GPL-3.0-only", "GPL-3.0-or-later", "LGPL-2.0-only", "LGPL-2.0-or-later", "LGPL-2.1-only", "LGPL-2.1-or-later", "LGPL-3.0-only", "LGPL-3.0-or-later"},
	"libnettle6":             {"GPL-2.0-with-autoconf-exception+"},
	"libnghttp2-14":          {"GPL-3.0-with-autoconf-exception+"},
	"libp11-kit0":            {"BSD-3-Clause", "MIT", "LGPL-2.1-or-later", "GPL-2.0-or-later", "GPL-3.0-or-later"},
	"libpam-modules":         {"GPL-2.0-or-later"},
	"libperl5.24":            {"Artistic-2.0", "BSD-3-Clause", "GPL-1.0-only", "GPL-1.0-or-later", "GPL-2.0-only", "GPL-2.0-or-later", "LGPL-2.1-only", "Zlib", "GPL-3.0-or-later"},
	"libpython2.7-minimal":   {"GPL-2.0-only", "LGPL-2.1-or-later"},
	"libpython2.7-stdlib":    {"GPL-2.0-only", "LGPL-2.1-or-later"},
	"libreadline7":           {"GPL-3.0-only"},
	"librtmp1":               {"GPL-2.0-only", "LGPL-2.1-only"},
	"libselinux1":            {"LGPL-2.1-only", "GPL-2.0-only"},
	"libsemanage-common":     {"LGPL-2.0-or-later", "GPL-2.0-or-later"},
	"libsemanage1":           {"LGPL-2.0-or-later", "GPL-2.0-or-later"},
	"libsepol1":              {"LGPL-2.0-or-later", "GPL-2.0-or-later"},
	"libsvn1":                {"GPL-2.0-only"},
	"libtasn1-6":             {"LGPL-2.0-or-later", "LGPL-2.1-only", "GPL-3.0-only"},
	"libunistring0":          {"LGPL-3.0-or-later", "GPL-3.0-or-later", "GPL-2.0-or-later", "LGPL-3.0-only", "GPL-3.0-only", "GPL-2.0-only"},
	"libuuid1":               {"BSD-4-Clause", "GPL-2.0-only", "GPL-2.0-or-later", "GPL-3.0-only", "GPL-3.0-or-later", "LGPL-2.0-only", "LGPL-2.0-or-later", "LGPL-2.1-only", "LGPL-2.1-or-later", "LGPL-3.0-only", "LGPL-3.0-or-later"},
	"login":                  {"GPL-2.0-only"},
	"mawk":                   {"GPL-2.0-only"},
	"mount":                  {"BSD-4-Clause", "GPL-2.0-only", "GPL-2.0-or-later", "GPL-3.0-only", "GPL-3.0-or-later", "LGPL-2.0-only", "LGPL-2.0-or-later", "LGPL-2.1-only", "LGPL-2.1-or-later", "LGPL-3.0-only", "LGPL-3.0-or-later"},
	"openssh-client":         {"BSD-2-Clause", "BSD-3-Clause", "MIT", "public-domain", "ISC", "Zlib"},
	"p11-kit":                {"BSD-3-Clause", "MIT", "LGPL-2.1-or-later", "GPL-2.0-or-later", "GPL-3.0-or-later"},
	"passwd":                 {"GPL-2.0-only"},
	"perl":                   {"Artistic-2.0", "BSD-3-Clause", "GPL-1.0-only", "GPL-1.0-or-later", "GPL-2.0-only", "GPL-2.0-or-later", "LGPL-2.1-only", "Zlib", "GPL-3.0-or-later"},
	"perl-base":              {"GPL-1.0-only", "GPL-1.0-or-later", "GPL-2.0-only", "GPL-2.0-or-later"},
	"perl-modules-5.24":      {"Artistic-2.0", "BSD-3-Clause", "GPL-1.0-only", "GPL-1.0-or-later", "GPL-2.0-only", "GPL-2.0-or-later", "LGPL-2.1-only", "Zlib", "GPL-3.0-or-later"},
	"procps":                 {"LGPL-2.0-only", "LGPL-2.0-or-later"},
	"python2.7":              {"GPL-2.0-only", "LGPL-2.1-or-later"},
	"python2.7-minimal":      {"GPL-2.0-only", "LGPL-2.1-or-later"},
	"util-linux":             {"BSD-4-Clause", "GPL-2.0-only", "GPL-2.0-or-later", "GPL-3.0-only", "GPL-3.0-or-later", "LGPL-2.0-only", "LGPL-2.0-or-later", "LGPL-2.1-only", "LGPL-2.1-or-later", "LGPL-3.0-only", "LGPL-3.0-or-later"},
	"xz-utils":               {"public-domain", "GPL-2.0-only", "GPL-3.0-only", "LGPL-2.1-only"},
}
