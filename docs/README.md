<div align="center">

<img src="assets/logo-full.png#gh-light-mode-only" alt="Synapse" width="360">
<img src="assets/logo-full-dark.png#gh-dark-mode-only" alt="Synapse" width="360">

# Synapse Documentation

</div>

Welcome to the Synapse documentation. These guides cover installing, configuring, deploying,
and operating Synapse.

## Guides

| Guide | What's inside |
| ----- | ------------- |
| [Features](features.md) | What Synapse does, with screenshots |
| [Deployment](deployment.md) | Docker, Compose, and production deployment |
| [Configuration](configuration.md) | Full environment-variable reference |
| [CLI](cli.md) | Using `synapse-cli` for scans in CI |

## Quick links

- **Run the full stack locally:**
  ```bash
  docker compose -f deploy/docker-compose.full.yml up --build
  ```
  Then open <http://localhost:8080>.

- **Scan a project from the command line:**
  ```bash
  ./bin/synapse-cli scan ./path/to/project --fail-on high
  ```

- **Minimum configuration:** set `SYNAPSE_API_TOKEN` (required — no anonymous access). A blank
  `SYNAPSE_DB_DSN` runs an in-memory dev store. See [Configuration](configuration.md).

## Platform note

The runtime target is a **Linux server**. The execution sandbox, live recon, and egress
scoping use Linux-kernel features (bubblewrap, seccomp, cgroups, network namespaces) with no
Windows equivalent. The code builds and the SCA scan runs on macOS and Windows for
development; the Linux-only features stay disabled and **fail closed** rather than running
unsandboxed. The simplest way to get full parity on any OS is to run the container — it is
Linux inside.
