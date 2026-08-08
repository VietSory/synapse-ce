package jsresolve

import (
	"context"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/jsresolution"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

func TestResolverR2CFirstPartySBOMComponentIsNotThirdPartyEvidence(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeJSON(t, r2bJoin(root, "package.json"), map[string]any{"name": "root"})
	doc := &sbom.SBOM{Components: []sbom.Component{{
		Name: "lodash", Version: "4.17.21", PURL: "pkg:npm/lodash@4.17.21", FirstParty: true,
	}}}

	got, err := NewResolver().Resolve(context.Background(), root, graphWithExternal("src/index.ts", "lodash"), doc)
	if err != nil {
		t.Fatal(err)
	}
	if got.Imports[0].Status == jsresolution.StatusComponent {
		t.Fatalf("first-party SBOM component became third-party evidence: %#v", got.Imports[0])
	}
	if !hasCoverageKind(got.Coverage, jsresolution.CoverageMissingSBOMComponent) {
		t.Fatalf("first-party-only SBOM lacks missing-component coverage: %#v", got.Coverage)
	}
}

func TestResolverR2CSBOMNameOrVersionDisagreementFailsClosed(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name      string
		component sbom.Component
	}{
		{name: "name", component: sbom.Component{Name: "underscore", Version: "4.17.21", PURL: "pkg:npm/lodash@4.17.21"}},
		{name: "version", component: sbom.Component{Name: "lodash", Version: "4.17.20", PURL: "pkg:npm/lodash@4.17.21"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			writeJSON(t, r2bJoin(root, "package.json"), map[string]any{"name": "root"})
			got, err := NewResolver().Resolve(context.Background(), root, graphWithExternal("src/index.ts", "lodash"), &sbom.SBOM{Components: []sbom.Component{tc.component}})
			if err != nil {
				t.Fatal(err)
			}
			if got.Imports[0].Status == jsresolution.StatusComponent || got.Complete {
				t.Fatalf("SBOM disagreement produced confidence: %#v coverage=%#v", got.Imports[0], got.Coverage)
			}
			if !hasCoverageKind(got.Coverage, jsresolution.CoverageUnsupportedMetadata) {
				t.Fatalf("SBOM disagreement has no coverage: %#v", got.Coverage)
			}
		})
	}
}

func TestResolverR2CDuplicateExactVersionPURLsRemainAmbiguous(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeJSON(t, r2bJoin(root, "package.json"), map[string]any{
		"name": "root", "packageManager": "npm@11.6.0", "dependencies": map[string]string{"lodash": "4.17.21"},
	})
	writeNPMResolvedLock(t, r2bJoin(root, "package-lock.json"), "lodash", "4.17.21")
	doc := &sbom.SBOM{Components: []sbom.Component{
		{Name: "lodash", Version: "4.17.21", PURL: "pkg:npm/lodash@4.17.21"},
		{Name: "lodash", Version: "4.17.21", PURL: "pkg:npm/lodash@4.17.21?repository_url=https%3A%2F%2Fregistry.example"},
	}}

	got, err := NewResolver().Resolve(context.Background(), root, graphWithExternal("src/index.ts", "lodash"), doc)
	if err != nil {
		t.Fatal(err)
	}
	if got.Imports[0].Status != jsresolution.StatusAmbiguous || len(got.Imports[0].Candidates) != 2 {
		t.Fatalf("same version with two exact PURLs did not remain ambiguous: %#v coverage=%#v", got.Imports[0], got.Coverage)
	}
}

func TestResolverR2CNilSBOMKeepsExternalPackageUnresolved(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeJSON(t, r2bJoin(root, "package.json"), map[string]any{"name": "root"})
	got, err := NewResolver().Resolve(context.Background(), root, graphWithExternal("src/index.ts", "lodash"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.Imports[0].Status != jsresolution.StatusUnresolved || got.Complete {
		t.Fatalf("nil SBOM did not preserve unresolved external identity: %#v coverage=%#v", got.Imports[0], got.Coverage)
	}
	if !hasCoverageKind(got.Coverage, jsresolution.CoverageMissingSBOMComponent) {
		t.Fatalf("nil SBOM lacks missing-component coverage: %#v", got.Coverage)
	}
}
