package sbom

import "testing"

func TestClassifyScope(t *testing.T) {
	cases := []struct {
		loc, cdx, want string
	}{
		{"examples/with-redux/package.json", "", ScopeExample},
		{"packages/next/src/index.ts", "", ScopeProduction},
		{"integration/fixtures/foo/package.json", "", ScopeFixture},
		{"benchmarks/bench/package.json", "", ScopeBenchmark},
		{"docs/api/package.json", "", ScopeDocumentation},
		{"src/tests/package.json", "", ScopeTest},
		{"requirements-dev.txt", "", ScopeDevelopment},
		{"package.json", "excluded", ScopeDevelopment},
		{"package.json", "required", ScopeProduction},
		{"usr/share/doc/bash/copyright", "", ScopeDocumentation},
		{"", "", ScopeUnknown},
		{"", "required", ScopeProduction},
	}
	for _, c := range cases {
		if got := ClassifyScope(c.loc, c.cdx); got != c.want {
			t.Errorf("ClassifyScope(%q,%q) = %q, want %q", c.loc, c.cdx, got, c.want)
		}
	}
}

func TestClassifyFirstPartyGatesOnUnversioned(t *testing.T) {
	comps := []Component{
		{Name: "vue", Version: "2.7.16"},               // real 3rd-party, versioned
		{Name: "k8s.io/api", Version: "UNKNOWN"},       // 1st-party module, unversioned
		{Name: "k8s.io/apimachinery/pkg", Version: ""}, // 1st-party sub-path, unversioned
		{Name: "lodash", Version: "4.17.21"},           // 3rd-party, versioned
	}
	// The repo declares local modules named "vue" (collateral) + the k8s modules.
	ClassifyFirstParty(comps, []string{"vue", "k8s.io/api", "k8s.io/apimachinery"})

	if comps[0].FirstParty {
		t.Error("versioned third-party vue must NOT be first-party despite a same-named local module")
	}
	if !comps[1].FirstParty {
		t.Error("unversioned local module k8s.io/api must be first-party")
	}
	if !comps[2].FirstParty {
		t.Error("unversioned sub-path of a local module must be first-party")
	}
	if comps[3].FirstParty {
		t.Error("versioned third-party lodash must not be first-party")
	}
}
