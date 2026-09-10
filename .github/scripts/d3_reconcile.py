from pathlib import Path
import subprocess

OLD = "0453b02f75a9eead8454128bac282564a541ab58"
CARRY = [
    "internal/infrastructure/tools/ownsbom/cargo.go",
    "internal/infrastructure/tools/ownsbom/conan.go",
    "internal/infrastructure/tools/ownsbom/conan_test.go",
    "internal/infrastructure/tools/ownsbom/npm.go",
    "internal/infrastructure/tools/ownsbom/nuget.go",
    "internal/infrastructure/tools/ownsbom/pnpm.go",
    "internal/infrastructure/tools/ownsbom/pnpm_test.go",
    "internal/infrastructure/tools/ownsbom/poetry.go",
    "internal/infrastructure/tools/ownsbom/yarn.go",
]
subprocess.run(["git", "fetch", "origin", "feat/scanner-edge-scope"], check=True)
subprocess.run(["git", "checkout", OLD, "--", *CARRY], check=True)


def replace_once(path, old, new):
    p = Path(path)
    text = p.read_text()
    if old not in text:
        raise SystemExit(f"expected snippet missing in {path}: {old[:100]!r}")
    p.write_text(text.replace(old, new, 1))

# #918 seeds graph roots at production. Encode a known dev root on its outgoing edge so the existing
# scopeRank/scopeLabel propagation carries that restriction transitively without a second scope model.
replace_once(
    "internal/infrastructure/tools/ownsbom/cargo.go",
    "deps = append(deps, sbom.Dependency{Ref: ref, DependsOn: on, Scope: baseScope})",
    "deps = append(deps, sbom.Dependency{Ref: ref, DependsOn: on, Scope: scope})",
)
replace_once(
    "internal/infrastructure/tools/ownsbom/poetry.go",
    "deps = append(deps, sbom.Dependency{Ref: ref, DependsOn: required, Scope: baseScope})",
    "deps = append(deps, sbom.Dependency{Ref: ref, DependsOn: required, Scope: scope})",
)
replace_once(
    "internal/infrastructure/tools/ownsbom/poetry.go",
    "deps = append(deps, sbom.Dependency{Ref: ref, DependsOn: optional, Scope: baseScope, Optional: true})",
    "deps = append(deps, sbom.Dependency{Ref: ref, DependsOn: optional, Scope: scope, Optional: true})",
)
replace_once(
    "internal/infrastructure/tools/ownsbom/npm.go",
    "\t\t\ttargetMeta := make(map[string]npmEdgeMeta)\n\t\t\tfor _, dep := range npmEdgeSpecs(lock.Packages[path], prodScope) {",
    "\t\t\tsourceScope := prodScope\n\t\t\tif lock.Packages[path].Dev {\n\t\t\t\tsourceScope = sbom.ScopeDevelopment\n\t\t\t}\n\t\t\ttargetMeta := make(map[string]npmEdgeMeta)\n\t\t\tfor _, dep := range npmEdgeSpecs(lock.Packages[path], sourceScope) {",
)

# Keep uv.go on current main; only add the edge field from the old PR (its old blob had comment-only churn).
replace_once(
    "internal/infrastructure/tools/ownsbom/uv.go",
    "deps = append(deps, sbom.Dependency{Ref: ref, DependsOn: on})",
    "deps = append(deps, sbom.Dependency{Ref: ref, DependsOn: on, Scope: scope})",
)

# Project projection consumes the same #918 production-reachability fact as SCA. This is downgrade-only:
# graph evidence may refine prod/unknown to development, but never turns a shipping component into a
# background/gate-exempt scope. Preserve per-edge metadata when exporting/cloning dependency subtrees.
replace_once(
    "internal/usecase/projectuc/dependency_graph.go",
    "\tsort.Slice(components, func(i, j int) bool { return components[i].id < components[j].id })\n\n\tedgeSeen := make(map[string]bool)",
    "\tsort.Slice(components, func(i, j int) bool { return components[i].id < components[j].id })\n\tprodReach := sbom.ProductionReachable(scan.SBOM.Dependencies)\n\n\tedgeSeen := make(map[string]bool)",
)
replace_once(
    "internal/usecase/projectuc/dependency_graph.go",
    "\t\tlicenseRisk := verdict == string(ports.LicenseWarn) || verdict == string(ports.LicenseDeny) || verdict == \"\" && riskyCategory\n\t\tnode := DependencyGraphNode{\n\t\t\tID: ref.id, Name: ref.component.Name, Version: ref.component.Version, PURL: ref.component.PURL,\n\t\t\tScope: ref.component.Scope, Reachability: ref.component.Reachability,",
    "\t\tlicenseRisk := verdict == string(ports.LicenseWarn) || verdict == string(ports.LicenseDeny) || verdict == \"\" && riskyCategory\n\t\teffectiveScope := ref.component.Scope\n\t\tif reachable, ok := prodReach[ref.id]; ok && !reachable &&\n\t\t\t(effectiveScope == \"\" || effectiveScope == sbom.ScopeProduction || effectiveScope == sbom.ScopeUnknown) {\n\t\t\teffectiveScope = sbom.ScopeDevelopment\n\t\t}\n\t\tnode := DependencyGraphNode{\n\t\t\tID: ref.id, Name: ref.component.Name, Version: ref.component.Version, PURL: ref.component.PURL,\n\t\t\tScope: effectiveScope, Reachability: ref.component.Reachability,",
)
replace_once(
    "internal/usecase/projectuc/dependency_graph.go",
    "\t\tnext := sbom.Dependency{Ref: dependency.Ref}",
    "\t\tnext := sbom.Dependency{Ref: dependency.Ref, Scope: dependency.Scope, Optional: dependency.Optional}",
)
replace_once(
    "internal/usecase/projectuc/dependency_graph.go",
    "\t\tout[i] = sbom.Dependency{Ref: dependency.Ref, DependsOn: append([]string(nil), dependency.DependsOn...)}",
    "\t\tout[i] = sbom.Dependency{\n\t\t\tRef: dependency.Ref, DependsOn: append([]string(nil), dependency.DependsOn...),\n\t\t\tScope: dependency.Scope, Optional: dependency.Optional,\n\t\t}",
)

Path("internal/usecase/sca/dependency_scope_test.go").write_text(r'''package sca

import (
    "testing"

    "github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
    "github.com/KKloudTarus/synapse-ce/internal/domain/shared"
    "github.com/KKloudTarus/synapse-ce/internal/domain/vulnerability"
)

func TestClassifyVulnsGraphScopeRefinement(t *testing.T) {
    component := func(name string, scope string) sbom.Component {
        return sbom.Component{Name: name, Version: "1.0.0", PURL: "pkg:generic/" + name + "@1.0.0", Scope: scope}
    }
    dep := func(from string, scope string, to ...string) sbom.Dependency {
        targets := make([]string, len(to))
        for i, name := range to {
            targets[i] = "pkg:generic/" + name + "@1.0.0"
        }
        return sbom.Dependency{Ref: "pkg:generic/" + from + "@1.0.0", DependsOn: targets, Scope: scope}
    }

    tests := []struct {
        name       string
        components []sbom.Component
        deps       []sbom.Dependency
        target     string
        want       string
    }{
        {
            name: "dev-only transitive is downgraded",
            components: []sbom.Component{component("root", sbom.ScopeProduction), component("leaf", sbom.ScopeProduction)},
            deps: []sbom.Dependency{dep("root", sbom.ScopeDevelopment, "leaf")}, target: "leaf", want: sbom.ScopeDevelopment,
        },
        {
            name: "production path wins a mixed diamond",
            components: []sbom.Component{component("root", sbom.ScopeProduction), component("prod", sbom.ScopeProduction), component("dev", sbom.ScopeProduction), component("leaf", sbom.ScopeProduction)},
            deps: []sbom.Dependency{
                dep("root", sbom.ScopeProduction, "prod"), dep("root", sbom.ScopeDevelopment, "dev"),
                dep("prod", sbom.ScopeProduction, "leaf"), dep("dev", sbom.ScopeProduction, "leaf"),
            }, target: "leaf", want: sbom.ScopeProduction,
        },
        {
            name: "provided-only Maven-style path is actionable development",
            components: []sbom.Component{component("root", sbom.ScopeProduction), component("leaf", sbom.ScopeProduction)},
            deps: []sbom.Dependency{dep("root", "provided", "leaf")}, target: "leaf", want: sbom.ScopeDevelopment,
        },
        {
            name: "background graph evidence is monotonically clamped",
            components: []sbom.Component{component("root", sbom.ScopeProduction), component("leaf", sbom.ScopeProduction)},
            deps: []sbom.Dependency{dep("root", sbom.ScopeTest, "leaf")}, target: "leaf", want: sbom.ScopeDevelopment,
        },
        {
            name: "rootless cycle remains conservative production",
            components: []sbom.Component{component("a", sbom.ScopeProduction), component("b", sbom.ScopeProduction)},
            deps: []sbom.Dependency{dep("a", sbom.ScopeDevelopment, "b"), dep("b", sbom.ScopeDevelopment, "a")}, target: "b", want: sbom.ScopeProduction,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            doc := &sbom.SBOM{Components: tt.components, Dependencies: tt.deps}
            vulns := []vulnerability.Vulnerability{{ID: "CVE-TEST-0001", Component: tt.target, Version: "1.0.0", Severity: shared.SeverityHigh}}
            classifyVulns(doc, vulns)
            if got := vulns[0].Scope; got != tt.want {
                t.Fatalf("scope = %q, want %q", got, tt.want)
            }
            if tt.name == "background graph evidence is monotonically clamped" && sbom.IsBackgroundScope(vulns[0].Scope) {
                t.Fatalf("graph refinement moved shipping vuln into background scope %q", vulns[0].Scope)
            }
        })
    }
}
''')

Path("internal/infrastructure/tools/ownsbom/npm_edge_scope_test.go").write_text(r'''package ownsbom

import (
    "context"
    "testing"

    "github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

type npmTestEdgeMeta struct {
    scope string
    optional bool
}

func TestNPMEdgeScopeAndOptional(t *testing.T) {
    tests := []struct {
        name string
        lock string
        want map[string]npmTestEdgeMeta
    }{
        {
            name: "mixed runtime dev optional and shared runtime wins",
            lock: `{"lockfileVersion":3,"packages":{"":{"name":"app","version":"1.0.0"},"node_modules/parent":{"version":"1.0.0","dependencies":{"runtime":"1.0.0","shared":"1.0.0"},"devDependencies":{"dev-only":"1.0.0","shared":"1.0.0"},"optionalDependencies":{"optional":"1.0.0"}},"node_modules/runtime":{"version":"1.0.0"},"node_modules/dev-only":{"version":"1.0.0"},"node_modules/shared":{"version":"1.0.0"},"node_modules/optional":{"version":"1.0.0"}}}`,
            want: map[string]npmTestEdgeMeta{
                "pkg:npm/parent@1.0.0->pkg:npm/runtime@1.0.0": {sbom.ScopeProduction, false},
                "pkg:npm/parent@1.0.0->pkg:npm/dev-only@1.0.0": {sbom.ScopeDevelopment, false},
                "pkg:npm/parent@1.0.0->pkg:npm/shared@1.0.0": {sbom.ScopeProduction, false},
                "pkg:npm/parent@1.0.0->pkg:npm/optional@1.0.0": {sbom.ScopeProduction, true},
            },
        },
        {
            name: "dev package carries restriction to normal child edge",
            lock: `{"lockfileVersion":3,"packages":{"":{"name":"app","version":"1.0.0"},"node_modules/dev-parent":{"version":"1.0.0","dev":true,"dependencies":{"child":"1.0.0"}},"node_modules/child":{"version":"1.0.0","dev":true}}}`,
            want: map[string]npmTestEdgeMeta{
                "pkg:npm/dev-parent@1.0.0->pkg:npm/child@1.0.0": {sbom.ScopeDevelopment, false},
            },
        },
        {
            name: "cycle keeps deterministic production edge metadata",
            lock: `{"lockfileVersion":3,"packages":{"":{"name":"app","version":"1.0.0"},"node_modules/a":{"version":"1.0.0","dependencies":{"b":"1.0.0"}},"node_modules/b":{"version":"1.0.0","dependencies":{"a":"1.0.0"}}}}`,
            want: map[string]npmTestEdgeMeta{
                "pkg:npm/a@1.0.0->pkg:npm/b@1.0.0": {sbom.ScopeProduction, false},
                "pkg:npm/b@1.0.0->pkg:npm/a@1.0.0": {sbom.ScopeProduction, false},
            },
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            _, deps, err := NPM{}.Parse(context.Background(), ParseInput{Path: "package-lock.json", Content: []byte(tt.lock)})
            if err != nil { t.Fatalf("parse: %v", err) }
            got := map[string]npmTestEdgeMeta{}
            for _, d := range deps {
                for _, target := range d.DependsOn {
                    got[d.Ref+"->"+target] = npmTestEdgeMeta{d.Scope, d.Optional}
                }
            }
            if len(got) != len(tt.want) { t.Fatalf("got %d edges, want %d: %#v", len(got), len(tt.want), got) }
            for edge, want := range tt.want {
                if got[edge] != want { t.Errorf("%s = %#v, want %#v", edge, got[edge], want) }
            }
        })
    }
}
''')

Path("internal/infrastructure/tools/ownsbom/source_scope_test.go").write_text(r'''package ownsbom

import (
    "context"
    "os"
    "path/filepath"
    "testing"

    "github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

func TestDevPackageScopeIsEncodedOnOutgoingEdges(t *testing.T) {
    t.Run("cargo direct dev root", func(t *testing.T) {
        dir := t.TempDir()
        if err := os.WriteFile(filepath.Join(dir, "Cargo.toml"), []byte("[dev-dependencies]\ndevroot = \"1\"\n"), 0o600); err != nil { t.Fatal(err) }
        lock := []byte(`version = 3

[[package]]
name = "devroot"
version = "1.0.0"
dependencies = ["leaf 1.0.0"]

[[package]]
name = "leaf"
version = "1.0.0"
`)
        _, deps, err := Cargo{}.Parse(context.Background(), ParseInput{Dir: dir, Path: filepath.Join(dir, "Cargo.lock"), Content: lock})
        if err != nil { t.Fatal(err) }
        leaf := "pkg:cargo/leaf@1.0.0"
        if sbom.ProductionReachable(deps)[leaf] { t.Fatalf("dev-root transitive leaf must not be production-reachable: %+v", deps) }
    })

    t.Run("poetry dev category", func(t *testing.T) {
        lock := []byte(`[[package]]
name = "devroot"
version = "1.0.0"
category = "dev"
[package.dependencies]
leaf = "1.0.0"

[[package]]
name = "leaf"
version = "1.0.0"
category = "main"
`)
        _, deps, err := Poetry{}.Parse(context.Background(), ParseInput{Path: "poetry.lock", Content: lock})
        if err != nil { t.Fatal(err) }
        leaf := "pkg:pypi/leaf@1.0.0"
        if sbom.ProductionReachable(deps)[leaf] { t.Fatalf("dev-category transitive leaf must not be production-reachable: %+v", deps) }
    })
}
''')

Path("internal/usecase/projectuc/dependency_scope_test.go").write_text(r'''package projectuc

import (
    "testing"

    "github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
    scauc "github.com/KKloudTarus/synapse-ce/internal/usecase/sca"
)

func TestBuildProjectDependencyGraphUsesProductionReachability(t *testing.T) {
    c := func(name, scope string) sbom.Component { return component(name, "1", "pkg:generic/"+name+"@1", scope) }
    d := func(from, scope string, to ...string) sbom.Dependency {
        targets := make([]string, len(to))
        for i, name := range to { targets[i] = "pkg:generic/"+name+"@1" }
        return sbom.Dependency{Ref: "pkg:generic/"+from+"@1", DependsOn: targets, Scope: scope}
    }
    tests := []struct {
        name string
        components []sbom.Component
        deps []sbom.Dependency
        target string
        want string
    }{
        {"dev-only transitive", []sbom.Component{c("root", sbom.ScopeProduction), c("leaf", sbom.ScopeProduction)}, []sbom.Dependency{d("root", sbom.ScopeDevelopment, "leaf")}, "leaf", sbom.ScopeDevelopment},
        {"production path wins diamond", []sbom.Component{c("root", sbom.ScopeProduction), c("p", sbom.ScopeProduction), c("d", sbom.ScopeProduction), c("leaf", sbom.ScopeProduction)}, []sbom.Dependency{d("root", sbom.ScopeProduction, "p"), d("root", sbom.ScopeDevelopment, "d"), d("p", sbom.ScopeProduction, "leaf"), d("d", sbom.ScopeProduction, "leaf")}, "leaf", sbom.ScopeProduction},
        {"rootless cycle conservative", []sbom.Component{c("a", sbom.ScopeProduction), c("b", sbom.ScopeProduction)}, []sbom.Dependency{d("a", sbom.ScopeDevelopment, "b"), d("b", sbom.ScopeDevelopment, "a")}, "b", sbom.ScopeProduction},
    }
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            graph, err := buildProjectDependencyGraph("analysis", scauc.ScanResult{SBOM: &sbom.SBOM{Components: tt.components, Dependencies: tt.deps}})
            if err != nil { t.Fatal(err) }
            got := graphNodesByID(graph.Nodes)["pkg:generic/"+tt.target+"@1"].Scope
            if got != tt.want { t.Fatalf("scope = %q, want %q", got, tt.want) }
        })
    }
}

func TestDependencySubtreePreservesEdgeMetadata(t *testing.T) {
    a := component("a", "1", "pkg:generic/a@1", sbom.ScopeProduction)
    b := component("b", "1", "pkg:generic/b@1", sbom.ScopeDevelopment)
    doc := &sbom.SBOM{Components: []sbom.Component{a, b}, Dependencies: []sbom.Dependency{{Ref: a.PURL, DependsOn: []string{b.PURL}, Scope: sbom.ScopeDevelopment, Optional: true}}}
    got, err := dependencySubtree(doc, a.PURL)
    if err != nil { t.Fatal(err) }
    if len(got.Dependencies) != 1 || got.Dependencies[0].Scope != sbom.ScopeDevelopment || !got.Dependencies[0].Optional {
        t.Fatalf("edge metadata lost from subtree: %+v", got.Dependencies)
    }
    cloned := cloneDependencies(doc.Dependencies)
    if cloned[0].Scope != sbom.ScopeDevelopment || !cloned[0].Optional { t.Fatalf("edge metadata lost from clone: %+v", cloned) }
}
''')

# Update Unreleased without claiming fields/functions that #918 already landed.
changelog = Path("CHANGELOG.md")
text = changelog.read_text()
entry = "- **Non-Maven dependency graphs now preserve relationship scope and optionality end to end.** The owned npm, pnpm, Poetry, Yarn, Cargo, Conan, NuGet, and uv parsers now emit `sbom.Dependency` edge metadata instead of leaving those relationships scope-less; mixed required/optional or runtime/dev children are split deterministically, and known dev package roots encode their restriction on outgoing edges so the existing `ReachableScopes`/`ProductionReachable` model from the Maven graph work propagates it transitively. SCA keeps the existing downgrade-only actionable clamp, while the Project dependency projection now consumes the same production-reachability fact and subtree exports retain `Scope`/`Optional`. This completes the remaining EPIC #860 D3.3 coverage without introducing a second scope model.\n"
marker = "### Added\n\n"
if entry not in text:
    if marker not in text: raise SystemExit("CHANGELOG Added marker missing")
    changelog.write_text(text.replace(marker, marker + entry, 1))
