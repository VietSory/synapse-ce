from pathlib import Path


def replace_once(text: str, old: str, new: str, label: str) -> str:
    if old not in text:
        raise SystemExit(f"{label} changed unexpectedly")
    return text.replace(old, new, 1)


conan = Path("internal/infrastructure/tools/ownsbom/conan_test.go")
text = conan.read_text()

old = """\tif len(deps) != 2 {
\t\tt.Fatalf(\"want 2 dependencies, got %d: %+v\", len(deps), deps)
\t}

\tif deps[0].Ref != \"pkg:conan/app@1.0\" {
\t\tt.Errorf(\"dep 0 ref want pkg:conan/app@1.0, got %s\", deps[0].Ref)
\t}
\tif len(deps[0].DependsOn) != 3 || deps[0].DependsOn[0] != \"pkg:conan/cmake@3.29.0\" || deps[0].DependsOn[1] != \"pkg:conan/lib-a@2.0\" || deps[0].DependsOn[2] != \"pkg:conan/lib-b@3.0\" {
\t\tt.Errorf(\"dep 0 DependsOn wrong: %v\", deps[0].DependsOn)
\t}

\tif deps[1].Ref != \"pkg:conan/lib-a@2.0\" {
\t\tt.Errorf(\"dep 1 ref want pkg:conan/lib-a@2.0, got %s\", deps[1].Ref)
\t}
\tif len(deps[1].DependsOn) != 1 || deps[1].DependsOn[0] != \"pkg:conan/openssl@3.0.0\" {
\t\tt.Errorf(\"dep 1 DependsOn wrong: %v\", deps[1].DependsOn)
\t}
"""
new = """\twantDeps := []sbom.Dependency{
\t\t{Ref: \"pkg:conan/app@1.0\", DependsOn: []string{\"pkg:conan/cmake@3.29.0\"}, Scope: sbom.ScopeDevelopment},
\t\t{Ref: \"pkg:conan/app@1.0\", DependsOn: []string{\"pkg:conan/lib-a@2.0\", \"pkg:conan/lib-b@3.0\"}, Scope: sbom.ScopeProduction},
\t\t{Ref: \"pkg:conan/lib-a@2.0\", DependsOn: []string{\"pkg:conan/openssl@3.0.0\"}, Scope: sbom.ScopeProduction},
\t}
\tif !reflect.DeepEqual(deps, wantDeps) {
\t\tt.Fatalf(\"dependencies = %+v, want %+v\", deps, wantDeps)
\t}
"""
if old in text:
    text = text.replace(old, new, 1)
elif 'pkg:conan/cmake@3.29.0"}, Scope: sbom.ScopeDevelopment' not in text:
    raise SystemExit("Conan graph expectation changed unexpectedly")

old = """\tif len(doc.Dependencies) != 2 {
\t\tt.Fatalf(\"want 2 dependencies, got %d: %+v\", len(doc.Dependencies), doc.Dependencies)
\t}
"""
new = """\tif len(doc.Dependencies) != 3 {
\t\tt.Fatalf(\"want 3 dependencies, got %d: %+v\", len(doc.Dependencies), doc.Dependencies)
\t}
"""
if old in text:
    text = text.replace(old, new, 1)
elif 'want 3 dependencies, got %d: %+v' not in text:
    raise SystemExit("Conan registry expectation changed unexpectedly")

old = """\tif len(deps) != 1 || len(deps[0].DependsOn) != 2 {
\t\tt.Fatalf(\"want 1 dep with 2 edges, got %+v\", deps)
\t}
\tif deps[0].DependsOn[0] != \"pkg:conan/cmake@2.0\" || deps[0].DependsOn[1] != \"pkg:conan/runtime@1.0\" {
\t\tt.Errorf(\"DependsOn wrong: %v\", deps[0].DependsOn)
\t}
"""
new = """\twantDeps := []sbom.Dependency{
\t\t{Ref: \"pkg:conan/app@1.0\", DependsOn: []string{\"pkg:conan/cmake@2.0\"}, Scope: sbom.ScopeDevelopment},
\t\t{Ref: \"pkg:conan/app@1.0\", DependsOn: []string{\"pkg:conan/runtime@1.0\"}, Scope: sbom.ScopeProduction},
\t}
\tif !reflect.DeepEqual(deps, wantDeps) {
\t\tt.Fatalf(\"dependencies = %+v, want %+v\", deps, wantDeps)
\t}
"""
if old in text:
    text = text.replace(old, new, 1)
elif 'pkg:conan/cmake@2.0"}, Scope: sbom.ScopeDevelopment' not in text:
    raise SystemExit("Conan mixed-edge expectation changed unexpectedly")

conan.write_text(text)

service = Path("internal/usecase/sca/service.go")
text = service.read_text()
marker = "\treachableScopes := sbom.ReachableScopes(doc.Components, doc.Dependencies)\n"
if marker not in text:
    old = (
        "\tscopeByCV := make(map[string]string, len(doc.Components))\n"
        "\treachByCV := make(map[string]string, len(doc.Components))\n"
    )
    new = (
        "\tscopeByCV := make(map[string]string, len(doc.Components))\n"
        "\treachableScopes := sbom.ReachableScopes(doc.Components, doc.Dependencies)\n"
        "\treachByCV := make(map[string]string, len(doc.Components))\n"
    )
    text = replace_once(text, old, new, "classifyVulns map setup")

    old = (
        "\t\tif c.Scope != \"\" {\n"
        "\t\t\tscopeByCV[c.Name+\"\\x00\"+c.Version] = c.Scope\n"
        "\t\t}\n"
    )
    new = (
        "\t\teffectiveScope := c.Scope\n"
        "\t\tid := sbom.ComponentID(c.Name, c.Version, c.PURL)\n"
        "\t\tif graphScope := reachableScopes[id]; graphScope != \"\" && graphScope != sbom.ScopeUnknown {\n"
        "\t\t\teffectiveScope = graphScope\n"
        "\t\t}\n"
        "\t\tif effectiveScope != \"\" {\n"
        "\t\t\tscopeByCV[c.Name+\"\\x00\"+c.Version] = effectiveScope\n"
        "\t\t}\n"
    )
    text = replace_once(text, old, new, "classifyVulns scope block")
    service.write_text(text)

sca_test = Path("internal/usecase/sca/dependency_scope_test.go")
if not sca_test.exists():
    sca_test.write_text('''package sca

import (
\t"testing"

\t"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
\t"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
\t"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerability"
)

func TestClassifyVulnsUsesGraphPropagatedScope(t *testing.T) {
\tdevRoot := "pkg:npm/dev-root@1.0.0"
\tleaf := "pkg:npm/leaf@1.0.0"
\tdoc := &sbom.SBOM{
\t\tComponents: []sbom.Component{
\t\t\t{Name: "dev-root", Version: "1.0.0", PURL: devRoot, Scope: sbom.ScopeDevelopment},
\t\t\t{Name: "leaf", Version: "1.0.0", PURL: leaf, Scope: sbom.ScopeProduction},
\t\t},
\t\tDependencies: []sbom.Dependency{
\t\t\t{Ref: devRoot, DependsOn: []string{leaf}, Scope: sbom.ScopeDevelopment},
\t\t},
\t}
\tvulns := []vulnerability.Vulnerability{
\t\t{ID: "CVE-TEST-0001", Component: "leaf", Version: "1.0.0", PackagePURL: leaf, Severity: shared.SeverityHigh},
\t}

\tclassifyVulns(doc, vulns)

\tif got := vulns[0].Scope; got != sbom.ScopeDevelopment {
\t\tt.Fatalf("graph-propagated vulnerability scope = %q, want %q", got, sbom.ScopeDevelopment)
\t}
}
''')
