<div align="center">

<img src="assets/logo-full.png#gh-light-mode-only" alt="Synapse" width="420">
<img src="assets/logo-full-dark.png#gh-dark-mode-only" alt="Synapse" width="420">

### Verify Everything. Trust Nothing.

**A governed control plane for software composition analysis, recon, evidence, and reporting.**

Turn a fragmented, manual security process into a controlled, auditable workflow — with
server-side scope enforcement, hardened tool execution, tamper-evident evidence, and
deterministic reports.

`Go 1.26` · `Clean Architecture` · `PostgreSQL` · `Vite + React + Tailwind`

[Quickstart](#quickstart) · [Features](#features) · [Architecture](#architecture) · [Deployment](docs/) · [Security](SECURITY.md)

</div>

---

> [!IMPORTANT]
> **Authorized use only.** Synapse is built for authorized security testing, pentest
> engagements, and defensive security work. Every engagement enforces an explicit
> **scope** and **legal authorization window**, server-side, before any tool runs. You are
> responsible for holding written permission to test any target.

## What is Synapse

Synapse runs the security-assessment lifecycle — software composition analysis, recon,
evidence capture, findings, and reporting — behind a single governed control plane.

It is **deterministic-first**: scanning, matching, license classification, and reporting
are pure, reproducible Go with nothing else in the path. Where automated analysis is
offered it is strictly bounded — a proposal is only ever *proposed*; a typed Go state
machine validates and executes, scope and authorization are checked in the execution
layer, secrets never leave the server, every artifact is hash-chained into a
tamper-evident custody record, and a human approves anything intrusive.

The result is a scanner you can put in front of a client engagement: fast, but provable.

## Features

### Software composition analysis
- **SBOM generation** across many ecosystems (npm, PyPI, Maven, Gradle, Go, Cargo, RubyGems,
  Composer, NuGet, Hex, Dart/Pub, and more), with owned per-ecosystem lockfile parsers and a
  pluggable producer.
- **Vulnerability detection** from multiple sources — a live advisory API and an offline
  database — cross-correlated and de-duplicated, with an owned advisory store that can ingest
  OSV, GHSA, and CSAF feeds for detection independence.
- **Risk-based prioritization**: findings are ordered by exploitability (known-exploited
  catalog → exploit-prediction score → CVSS), never by raw CVSS alone.
- **License compliance**: declared-license resolution, SPDX expression parsing (AND/OR/WITH),
  a curated SPDX category + risk model, and coordinate recovery for shaded/metadata-less JARs.
- **Reachability**: a deterministic call-graph engine decides whether a vulnerable symbol is
  actually reachable from application code, so a finding on unused code can be de-prioritized.

### Evidence & governance
- **Tamper-evident custody**: every artifact is hash-chained (`previous_hash`); a broken chain
  blocks the report. Audit and evidence logs are append-only.
- **Hardened execution**: heavy or capability-sensitive tools are shelled out to pinned
  binaries via `argv` arrays (never a shell string) inside a Linux sandbox with egress
  scoping. Scope + the authorization window are enforced server-side before any tool runs.
- **Secrets stay server-side**: a credential vault with placeholder substitution keeps tokens
  out of logs, transcripts, and source.
- **Per-action RBAC + tenant isolation** through a single authorization chokepoint.

### Standards & reporting
- **Standards**: CycloneDX + SPDX (PURL) · SARIF · OpenVEX / CSAF · KEV + EPSS.
- **Deterministic reports**: templated from stored data. Compliance mapping
  (CWE → OWASP / PCI / ISO) is a curated, source-cited table.

## Architecture

Clean architecture with a strict, inward-only dependency rule:

```
domain  ←  usecase  ←  adapter / infrastructure
```

| Layer          | Path                        | May import                |
| -------------- | --------------------------- | ------------------------- |
| domain         | `internal/domain/*`         | only `domain` + stdlib    |
| usecase        | `internal/usecase/*`        | domain, `usecase/ports`   |
| adapter        | `internal/adapter/*`        | usecase, domain           |
| infrastructure | `internal/infrastructure/*` | `usecase/ports`, domain   |
| platform       | `internal/platform/*`       | stdlib, domain/ports      |

All external I/O (database, tools, storage, sandbox) goes through **ports** — interfaces in
`internal/usecase/ports`. `cmd/*` is the composition root (manual dependency injection in
`main`, no business logic).

## Binaries

| Binary              | Role                                                        |
| ------------------- | ----------------------------------------------------------- |
| `synapse-api`       | HTTP API server (the primary service)                       |
| `synapse-cli`       | Run an SCA scan from the command line (CI-friendly)         |
| `synapse-worker`    | Durable job runner (recon + background jobs), lease-based   |
| `synapse-callgraph` | Sandboxed call-graph builder for reachability analysis      |
| `synapse-mcp`       | Read-only, propose-only integration server (never executes) |

Each `cmd/*` is a composition root only.

## Quickstart

### Prerequisites

- **Go 1.26** (pinned in `go.mod`), **Node + pnpm** (web dashboard — use pnpm, not npm/yarn).
- **External scan binaries** — Synapse shells out to pinned tools:
  - **Syft** (SBOM generation) — required for any SCA scan.
  - **Grype** (offline vulnerability database) — optional; missing ⇒ degrades to the live
    source only.
  - `make tools` installs both (pinned, checksum-verified) into `./bin`. The container image
    bundles them.
- **Docker** (optional) — the easiest way to run the dev Postgres + object-store stack, and
  the simplest path to a full run on any OS.
- The hardened execution sandbox and live recon require a **Linux host** (bubblewrap, seccomp,
  cgroups, netns). Without them the API still runs (SCA, findings, reports); sandboxed
  execution **fails closed** rather than running unsandboxed.

### Development

```bash
# 0. Dependencies (Go modules + web) and the external scan tools (syft + grype)
make install
make tools                      # into ./bin  (add RECON=1 on Linux for recon tools)
export PATH="$PWD/bin:$PATH"

# 1. Dev dependencies — Postgres + object store
make docker-up

# 2. Minimum configuration — Synapse reads the process environment directly
export SYNAPSE_API_TOKEN=$(openssl rand -hex 32)     # REQUIRED — no anonymous access

# Point at Postgres. The dev stack (make docker-up) uses user, password, and database
# all set to "synapse"; put the user + password into the userinfo slot of the URL.
export SYNAPSE_DB_DSN="postgres://localhost:5432/synapse?sslmode=disable"

# 3. Run the API (:8080) and the web dashboard (:5173) together
make dev
```

Open <http://localhost:5173>. A blank `SYNAPSE_DB_DSN` runs an in-memory dev store (nothing
is persisted). Database migrations are embedded and applied automatically at startup.

### Scan from the command line

```bash
make build
./bin/synapse-cli scan ./path/to/project --fail-on high
```

### Run the full stack with Docker

```bash
docker compose -f deploy/docker-compose.full.yml up --build
```

See **[docs/](docs/)** for full deployment, configuration, and operations guides.

## Configuration

Synapse reads its configuration from the **process environment**. Copy `.env.example` and
adjust. The only required variable is `SYNAPSE_API_TOKEN` (the server refuses to start
without it — there is no anonymous access). See
[docs/configuration.md](docs/configuration.md) for the complete reference.

## Project structure

```
cmd/                    Composition roots (one per binary)
internal/
  domain/               Pure business types + rules (no I/O)
  usecase/              Application services + ports (interfaces)
  adapter/              HTTP API + presenters
  infrastructure/       Tool, DB, storage, sandbox implementations of ports
  platform/             Cross-cutting helpers (config, ids, logging)
migrations/             Numbered SQL, embedded + auto-applied at startup
web/                    Vite + React + Tailwind dashboard
deploy/                 Dockerfiles + compose stacks
docs/                   Deployment & operations documentation
```

## Common Make targets

```bash
make dev          # API on :8080 + web on :5173
make build        # build all Go binaries into ./bin
make test         # run Go tests
make vet lint     # static analysis
make typecheck    # go vet + web tsc --noEmit
make docker-up    # dev Postgres + object store
make smoke        # build then probe /healthz
```

## Contributing

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). Please also read the
[Code of Conduct](CODE_OF_CONDUCT.md) and report vulnerabilities per the
[Security Policy](SECURITY.md).

## License

Licensed under the [Apache License 2.0](LICENSE).
