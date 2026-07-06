package license

import (
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

// licenseFamily is a coarse license bucket inferred from an SPDX id's NAMING FAMILY. It is
// used only as a deterministic FALLBACK when an id is absent from the curated spdxCategory /
// riskByLicense tables — so the long tail of the SPDX License List (≈700 ids) and any future
// id still gets a category + risk instead of "unknown". It is intentionally CONSERVATIVE:
// an ambiguous id returns famUnknown (→ unknown → warn) rather than risk a permissive verdict
// on a copyleft license (never under-state an obligation by false attribution).
//
// Family→bucket rules are DERIVED (cross-checked, not copied) from the SPDX License List
// naming conventions (https://spdx.org/licenses) and the FSF/OSI + google/licenseclassifier
// categorizations (https://github.com/google/licenseclassifier, license_type.go) — the same
// canonical sources other scanners (e.g. Trivy) port from. Where Synapse's curated tables
// already take a stance on a specific id, that curated entry wins (this is a fallback only),
// so these rules only ever decide ids no scanner table mentions.
type licenseFamily int

const (
	famUnknown        licenseFamily = iota
	famPermissive                   // notice / permissive (MIT, BSD, Apache, AFL, ISC, …)
	famUnencumbered                 // public-domain-equivalent (CC0, Unlicense, 0BSD, …)
	famWeakCopyleft                 // weak / file-level copyleft (MPL, EPL, CDDL, APSL, …)
	famStrongCopyleft               // strong copyleft (GPL, AGPL, OSL, QPL, share-alike CC, …)
	famNonCommercial                // non-commercial / source-available bans (CC *-NC*, Commons-Clause)
)

func (f licenseFamily) category() sbom.LicenseCategory {
	switch f {
	case famPermissive, famUnencumbered:
		return sbom.LicensePermissive
	case famWeakCopyleft:
		return sbom.LicenseWeakCopyleft
	case famStrongCopyleft:
		return sbom.LicenseCopyleft
	case famNonCommercial:
		return sbom.LicenseProprietary
	}
	return sbom.LicenseUnknown
}

func (f licenseFamily) risk() RiskCategory {
	switch f {
	case famPermissive:
		return RiskNotice
	case famUnencumbered:
		return RiskUnencumbered
	case famWeakCopyleft:
		return RiskReciprocal
	case famStrongCopyleft:
		return RiskRestricted
	case famNonCommercial:
		return RiskForbidden
	}
	return RiskUnknown
}

// familyOf infers a license family from a NORMALIZED SPDX id (lowercase, suffix-stripped —
// the form produced by normalizeSPDX, e.g. "gpl-3.0", "cc-by-nc-sa-4.0", "osl-3.0"). It
// returns famUnknown when no family is a confident match.
func familyOf(norm string) licenseFamily {
	norm = strings.TrimSpace(norm)
	// Only a SINGLE SPDX id — never an expression/list ("A OR B", "A AND B", "a, b", "(x)").
	// Those must be split by classify()/classifyRisk() first; a family prefix would otherwise
	// match the leading operand of the whole string (e.g. "mit and gpl-3.0" → permissive,
	// dropping the GPL). SPDX ids contain no spaces, commas, semicolons, or parentheses.
	if norm == "" || strings.ContainsAny(norm, " \t\n,;()") {
		return famUnknown
	}

	// Authoritative ScanCode-derived table first — it covers the full SPDX License List with
	// verified per-id categories, so the heuristic naming rules below only ever decide non-SPDX
	// / future id strings the table doesn't list.
	if f, ok := spdxFamily[norm]; ok {
		return f
	}

	// Public-domain-equivalent (checked first — some share an mit-/bsd- prefix shape).
	switch norm {
	case "unlicense", "0bsd", "mit-0", "blessing", "public-domain", "pd", "sax-pd", "cc-pddc", "cc0-1.0":
		return famUnencumbered
	}
	if hasAnyPrefix(norm, "cc0", "pddl-") {
		return famUnencumbered
	}

	// Creative Commons — the flavor drives the bucket (matches licenseclassifier exactly):
	// *-NC* = non-commercial (forbidden); *-SA / *-ND = share-alike or no-derivatives
	// (restricted); plain CC-BY-<n> = attribution-only (notice).
	if strings.HasPrefix(norm, "cc-by") {
		switch {
		case strings.Contains(norm, "-nc"):
			return famNonCommercial
		case strings.Contains(norm, "-sa"), strings.Contains(norm, "-nd"):
			return famStrongCopyleft
		default:
			return famPermissive
		}
	}

	// CeCILL / CERN-OHL have per-variant flavors (B/P = permissive, C/W = weak, base/S = strong).
	if strings.HasPrefix(norm, "cecill") {
		switch {
		case strings.HasPrefix(norm, "cecill-b"):
			return famPermissive
		case strings.HasPrefix(norm, "cecill-c"):
			return famWeakCopyleft
		default:
			return famStrongCopyleft
		}
	}
	if strings.HasPrefix(norm, "cern-ohl") {
		switch {
		case strings.HasPrefix(norm, "cern-ohl-s"):
			return famStrongCopyleft
		case strings.HasPrefix(norm, "cern-ohl-w"):
			return famWeakCopyleft
		default: // cern-ohl-p (permissive) and the 1.x hardware licenses
			return famPermissive
		}
	}
	// Community Data License Agreement: Sharing is share-alike (strong); Permissive is notice.
	if strings.HasPrefix(norm, "cdla-sharing") {
		return famStrongCopyleft
	}
	if strings.HasPrefix(norm, "cdla-permissive") {
		return famPermissive
	}
	// Artistic-1.x is weak/vague copyleft (FSF); Artistic-2.0 is permissive.
	if strings.HasPrefix(norm, "artistic-1") {
		return famWeakCopyleft
	}
	if strings.HasPrefix(norm, "artistic-2") || norm == "artistic" {
		return famPermissive
	}

	// Strong copyleft families (whole-work reciprocal).
	if hasAnyPrefix(norm,
		"gpl-", "agpl-", "osl-", "nposl-", "npl-", "qpl-", "rpl-", "rpsl-",
		"eupl-", "cpal-", "cal-", "parity-", "simpl-", "gfdl-") {
		return famStrongCopyleft
	}
	switch norm {
	// "bsd-protection" carries a GPL-style same-license requirement on derivatives → strong
	// copyleft (licenseclassifier RESTRICTED), so it must be caught BEFORE the broad "bsd-"
	// permissive prefix below, which would otherwise wrongly allow it.
	case "gpl", "agpl", "ngpl", "sleepycat", "bsd-protection":
		return famStrongCopyleft
	}

	// Weak / file-level copyleft families. (MS-PL / MS-RL are weak copyleft per FSF + Synapse's
	// curated table — kept here, NOT in the permissive block, so the family table can't downgrade.)
	if hasAnyPrefix(norm,
		"lgpl-", "mpl-", "epl-", "cddl-", "cpl-", "ipl-", "apsl-", "ms-rl", "ms-pl",
		"spl-", "sissl", "vsl-", "watcom", "lpl-", "lppl-", "motosoto", "nokia",
		"ypl-", "qhull", "ruby", "freeimage", "rscpl") {
		return famWeakCopyleft
	}

	// Permissive / notice families (the big bucket — anchored to licenseclassifier's NOTICE
	// set plus well-established SPDX permissive families). Kept to families with broad
	// consensus; genuinely obscure one-offs are deliberately left famUnknown. Prefixes are
	// intentionally broad (not "-"-anchored) so merged-word ids like MITNFA / MulanPSL-2.0
	// still resolve; this only ever runs for ids ABSENT from the curated tables, and every
	// REAL SPDX id matching these prefixes is permissive (the lone copyleft collision,
	// BSD-Protection, is caught as strong copyleft above before "bsd-").
	if hasAnyPrefix(norm,
		"mit", "bsd-", "apache-", "afl-", "isc", "zlib", "zpl-", "bsl-", "ncsa",
		"postgresql", "python-", "cnri-", "php-", "w3c", "x11", "unicode", "upl-",
		"openssl", "ofl-", "ecl-", "efl-", "ntp", "icu", "vim",
		"libpng", "blueoak-", "zend-", "miros", "mulanps", "mulan", "curl", "ftl",
		"sgi-b-", "lil-", "linux-openib", "oldap-", "imagemagick", "egenix",
		"gust-font", "pil", "tcl", "spencer-", "hpnd", "beerware", "wtfpl",
		"json", "xnet", "intel", "naumen", "entessa", "fair", "saxpath", "w3m") {
		return famPermissive
	}
	switch norm {
	case "apache", "bsd", "isc", "mit":
		return famPermissive
	}

	// Non-commercial / source-available bans (kept narrow + explicit).
	if hasAnyPrefix(norm, "commons-clause", "aladdin", "elastic-", "busl", "polyform-", "sspl") {
		return famNonCommercial
	}
	if strings.Contains(norm, "-nc-") || strings.HasSuffix(norm, "-nc") {
		return famNonCommercial
	}

	return famUnknown
}

func hasAnyPrefix(s string, prefixes ...string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}
