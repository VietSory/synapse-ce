package sca

import (
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerability"
)

func TestClassifyVulnsUsesGraphPropagatedScope(t *testing.T) {
	devRoot := "pkg:npm/dev-root@1.0.0"
	leaf := "pkg:npm/leaf@1.0.0"
	doc := &sbom.SBOM{
		Components: []sbom.Component{
			{Name: "dev-root", Version: "1.0.0", PURL: devRoot, Scope: sbom.ScopeDevelopment},
			{Name: "leaf", Version: "1.0.0", PURL: leaf, Scope: sbom.ScopeProduction},
		},
		Dependencies: []sbom.Dependency{
			{Ref: devRoot, DependsOn: []string{leaf}, Scope: sbom.ScopeDevelopment},
		},
	}
	vulns := []vulnerability.Vulnerability{
		{ID: "CVE-TEST-0001", Component: "leaf", Version: "1.0.0", PackagePURL: leaf, Severity: shared.SeverityHigh},
	}

	classifyVulns(doc, vulns)

	if got := vulns[0].Scope; got != sbom.ScopeDevelopment {
		t.Fatalf("graph-propagated vulnerability scope = %q, want %q", got, sbom.ScopeDevelopment)
	}
}
