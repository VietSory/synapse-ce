package license

import "testing"

func TestRiskOf(t *testing.T) {
	cases := map[string]struct {
		cat RiskCategory
		sev string
	}{
		// The correctness fixes: AGPL/LGPL were under-rated by the policy taxonomy.
		"AGPL-3.0":          {RiskForbidden, "critical"},
		"AGPL-3.0-or-later": {RiskForbidden, "critical"}, // suffix normalized
		"GPL-3.0-only":      {RiskRestricted, "high"},
		"GPL-2.0":           {RiskRestricted, "high"},
		"LGPL-2.1":          {RiskRestricted, "high"},
		"CC-BY-NC-4.0":      {RiskForbidden, "critical"},
		"Commons-Clause":    {RiskForbidden, "critical"},
		"SSPL-1.0":          {RiskForbidden, "critical"}, // modern source-available
		"MPL-2.0":           {RiskReciprocal, "medium"},
		"EPL-2.0":           {RiskReciprocal, "medium"},
		"MIT":               {RiskNotice, "low"},
		"Apache-2.0":        {RiskNotice, "low"},
		"BSD-3-Clause":      {RiskNotice, "low"},
		"Unlicense":         {RiskUnencumbered, "low"},
		"CC0-1.0":           {RiskUnencumbered, "low"},
		"0BSD":              {RiskUnencumbered, "low"},
		"Totally-Made-Up":   {RiskUnknown, "unknown"},
		// Free-text name (reuses the alias table) + expressions.
		"Apache License 2.0":               {RiskNotice, "low"},
		"MIT OR GPL-3.0-only":              {RiskNotice, "low"},      // OR → least-risky electable operand
		"MIT AND GPL-3.0-only":             {RiskRestricted, "high"}, // AND → most-risky
		"Apache-2.0 OR AGPL-3.0":           {RiskNotice, "low"},      // can elect Apache
		"GPL-2.0-with-classpath-exception": {RiskRestricted, "high"}, // WITH → base
	}
	for in, want := range cases {
		gotCat, gotSev := RiskOf(in)
		if gotCat != want.cat || gotSev != want.sev {
			t.Errorf("RiskOf(%q) = (%q, %q), want (%q, %q)", in, gotCat, gotSev, want.cat, want.sev)
		}
	}
}
