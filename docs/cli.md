# Command-line scanning (`synapse-cli`)

`synapse-cli` runs the same SCA pipeline as the server, from the command line — ideal for CI
gating. It creates an ephemeral, scope-checked engagement covering the target path, so scope
enforcement is exercised, not bypassed. Nothing is persisted.

Build it with `make build`; the binary lands in `./bin/synapse-cli`.

## Scan

```
synapse-cli scan <path|image-ref> [flags]
```

| Flag | Description |
| ---- | ----------- |
| `--mode full\|vulnerabilities\|licenses` | What to scan (default `full`). |
| `--fail-on critical\|high\|medium\|low\|info` | Exit non-zero if a finding at or above this severity is present (default `high`). |
| `--image` | Treat the argument as a container image reference (pulled via crane) instead of a local path. |
| `--offline` | Skip the live advisory source; detect with the offline database only (air-gapped / fast). |
| `--ignore-unfixed` | Ignore vulnerabilities that have no fix available. |

### Examples

```bash
# Fail a CI build on any high-or-critical vulnerability
synapse-cli scan . --fail-on high

# Licenses only
synapse-cli scan . --mode licenses

# Scan a container image, offline
synapse-cli scan alpine:3.19 --image --offline
```

Exit code is `0` when no finding meets the `--fail-on` threshold, non-zero otherwise — wire it
straight into a pipeline step.

## Advisory sync (optional owned store)

For detection independence you can maintain an owned advisory store (requires a database via
`SYNAPSE_DB_DSN`) and ingest feeds into it:

```bash
# Ingest a local OSV dump directory
synapse-cli sync-advisories <dir>

# Fetch + ingest application ecosystems from the OSV bulk source
synapse-cli sync-advisories --remote

# Fetch + ingest OS-package advisories (large)
synapse-cli sync-advisories --remote-distros

# Ingest a local CSAF 2.0 advisory dump
synapse-cli sync-advisories --csaf <dir>
```

## CI example (GitHub Actions)

```yaml
- name: SCA scan
  run: |
    make tools
    make build
    ./bin/synapse-cli scan . --fail-on high
```
