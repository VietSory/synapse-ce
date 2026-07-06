# Features

> Screenshots live in [`assets/screenshots/`](assets/screenshots/). Drop your images there and
> they will render below.

## Overview

Synapse runs the security-assessment lifecycle — software composition analysis, recon,
evidence capture, findings, and reporting — behind a single governed control plane. It is
deterministic-first: scanning, matching, license classification, and reporting are pure,
reproducible Go.

<!-- ![Dashboard](assets/screenshots/dashboard.png) -->

## Software composition analysis

- **SBOM generation** across many ecosystems (npm, PyPI, Maven, Gradle, Go, Cargo, RubyGems,
  Composer, NuGet, Hex, Dart/Pub, and more) with owned per-ecosystem lockfile parsers.
- **Vulnerability detection** from a live advisory source plus an offline database,
  cross-correlated and de-duplicated. An owned advisory store can ingest OSV, GHSA, and CSAF
  feeds for detection independence.
- **Risk-based prioritization** — findings are ordered by exploitability (known-exploited
  catalog → exploit-prediction score → CVSS), never by raw CVSS alone.
- **Reachability** — a deterministic call-graph engine decides whether a vulnerable symbol is
  actually reachable from application code.

<!-- ![SCA scan](assets/screenshots/sca-scan.png) -->

## License compliance

- Declared-license resolution and SPDX expression parsing (AND / OR / WITH).
- A curated SPDX category and risk model.
- Coordinate recovery for shaded / renamed / metadata-less JARs, so their licenses and
  vulnerabilities are attributed correctly.

## Findings & evidence

- One finding per issue, de-duplicated and updated in place across re-scans.
- Every artifact is hash-chained into a tamper-evident custody record; a broken chain blocks
  the report.
- Append-only audit and evidence logs.

<!-- ![Finding detail](assets/screenshots/finding.png) -->

## Reporting

- Deterministic, templated reports assembled from stored data — no model in the path.
- Compliance mapping (CWE → OWASP / PCI / ISO) from a curated, source-cited table.
- Export formats suitable for client deliverables.

<!-- ![Report](assets/screenshots/report.png) -->

## Governance & safety

- **Scope + authorization window** enforced server-side before any tool runs.
- **Hardened execution** — tools are shelled out via `argv` arrays inside a Linux sandbox with
  egress scoping; execution **fails closed** without the required kernel features.
- **Secrets stay server-side** in a credential vault with placeholder substitution.
- **Per-action RBAC + tenant isolation** through a single authorization chokepoint.

## Standards

CycloneDX + SPDX (PURL) · SARIF · OpenVEX / CSAF · KEV + EPSS.
