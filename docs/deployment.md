# Deployment

Synapse ships as a set of Go binaries plus a web dashboard. The recommended way to run it is
with the provided container images and Compose stack.

## Option 1 — full stack with Docker Compose (recommended)

The `deploy/docker-compose.full.yml` stack runs everything: PostgreSQL, an S3-compatible
object store (MinIO), the API server (with syft + grype bundled), and the web dashboard.

```bash
docker compose -f deploy/docker-compose.full.yml up --build
```

Services and ports:

| Service        | Port   | Purpose                          |
| -------------- | ------ | -------------------------------- |
| `synapse-api`  | `8080` | HTTP API                         |
| `web`          | `5173` | Web dashboard (proxies to API)   |
| `postgres`     | `5432` | Database                         |
| `minio`        | `9000` / `9001` | Object store + console  |

The stack reads its settings from environment variables with sensible dev defaults
(`DB_USER`, `DB_PASSWORD`, `BLOB_USER`, `BLOB_PASSWORD`, `SYNAPSE_API_TOKEN`, …). **Change
them for anything but local development** — put real values in a `.env` file next to the
Compose file, or export them in your shell.

Open the dashboard at <http://localhost:5173> and the API at <http://localhost:8080>.

## Option 2 — API container only

The `deploy/Dockerfile` builds two images:

- **`api`** — a minimal distroless image (`gcr.io/distroless/static-debian12:nonroot`) with
  just the `synapse-api` binary. Smallest and most locked-down; SCA runs against an SBOM you
  provide, and syft/grype are expected on `PATH` if you scan source directly.
- **`full`** — a Debian-based image that bundles pinned **syft** and **grype** so it can run a
  full SCA scan end-to-end.

```bash
# API-only (distroless)
docker build -t synapse-api:latest --target api -f deploy/Dockerfile .

# Full image with bundled scan tools
docker build -t synapse:full --target full -f deploy/Dockerfile .
```

Run the API with a database and a token. Point `SYNAPSE_DB_DSN` at your PostgreSQL — a
standard `postgres://` connection URL with your user and password in the userinfo slot (see
[Configuration](configuration.md)):

```bash
docker run --rm -p 8080:8080 \
  -e SYNAPSE_API_TOKEN=$(openssl rand -hex 32) \
  -e SYNAPSE_DB_DSN="$DATABASE_URL" \
  synapse:full
```

## Option 3 — build and run natively

```bash
make install        # Go modules + web deps
make tools          # syft + grype into ./bin (add RECON=1 on Linux for recon tools)
make build          # all binaries into ./bin
export PATH="$PWD/bin:$PATH"

export SYNAPSE_API_TOKEN=$(openssl rand -hex 32)
export SYNAPSE_DB_DSN="$DATABASE_URL"    # your postgres:// connection URL
./bin/synapse-api
```

Build the dashboard separately and serve `web/dist` behind your reverse proxy:

```bash
cd web && pnpm install && pnpm build
```

## Production checklist

- [ ] `SYNAPSE_ENV` is left at its production value (any value other than
      `development`/`dev`/`local`/`test`/`ci` enables the strict, fail-closed gates).
- [ ] `SYNAPSE_API_TOKEN` is set to a strong random value.
- [ ] `SYNAPSE_DB_DSN` points at a managed PostgreSQL with TLS.
- [ ] The credential-vault master key and signing seed are set (required in production).
- [ ] The object store (S3/MinIO) is configured for evidence artifacts.
- [ ] Run on a **Linux host** so the execution sandbox and egress scoping are available.
- [ ] Terminate TLS at your load balancer / reverse proxy in front of the API.
- [ ] Back up the database and the evidence object store.

## Migrations

Database migrations are **embedded** in the binary and applied automatically at startup — no
separate migrate step. They are numbered SQL files under `migrations/`.

## Health check

The API exposes an unauthenticated `GET /healthz` for liveness/readiness probes:

```bash
curl -s http://localhost:8080/healthz
```
