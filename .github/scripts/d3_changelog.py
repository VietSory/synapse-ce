from pathlib import Path

path = Path("CHANGELOG.md")
text = path.read_text()
entry = "- **Dependency scope now follows the relationship that introduced a package.** The owned lockfile parsers preserve production/development and optional metadata on `sbom.Dependency` edge groups instead of flattening that context onto the component itself. Mixed-metadata children are split deterministically, and `sbom.ReachableScopes` propagates non-shipping scope through transitive paths while production wins when any production path reaches the same package. SCA vulnerability classification and the project dependency graph consume that effective scope, so a package reached only through a dev/test path is no longer ranked as production just because its component record is production-shaped, while a package also reachable from production stays production.\n"

if entry not in text:
    marker = "### Added\n\n"
    if marker not in text:
        raise SystemExit("CHANGELOG Added section changed unexpectedly")
    text = text.replace(marker, marker + entry, 1)
    path.write_text(text)
