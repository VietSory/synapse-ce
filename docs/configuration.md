# Configuration

Synapse reads its configuration from the **process environment** — it does not auto-load a
file. Load your settings into the environment first, for example:

```bash
set -a; source .env; set +a
```

or pass them via `docker run --env-file`, Compose `env_file`, or your process manager. A fully
documented template with every option lives in [`.env.example`](../.env.example) — copy it to
`.env` and adjust.

Conventions: an empty value means "unset" (the built-in default applies); booleans accept
`1/0/true/false`; durations use Go syntax (`30s`, `10m`, `1h`); sizes are byte counts.

## Required

| Variable | Description |
| -------- | ----------- |
| `SYNAPSE_API_TOKEN` | Bootstrap-admin bearer token. **The API exits if this is empty** — there is no anonymous access. Generate one with `openssl rand -hex 32`. |

## Core / server

| Variable | Default | Description |
| -------- | ------- | ----------- |
| `SYNAPSE_HTTP_ADDR` | `:8080` | Listen address. |
| `SYNAPSE_ENV` | `development` | Deployment environment. Non-prod values: `development`, `dev`, `local`, `test`, `ci`. **Any other value** (including typos and `production`) is treated as production and enables the strict, fail-closed gates. |
| `SYNAPSE_LOG_LEVEL` | `info` | Log verbosity. |
| `SYNAPSE_AUP_VERSION` | `1.0` | Acceptable-Use Policy version operators must accept on first run. |

## Persistence

| Variable | Description |
| -------- | ----------- |
| `SYNAPSE_DB_DSN` | PostgreSQL connection URL. **Empty ⇒ in-memory dev store** (nothing is persisted). |

Connection-pool sizing (`SYNAPSE_DB_MAX_CONNS`, `SYNAPSE_DB_MIN_CONNS`,
`SYNAPSE_DB_MAX_CONN_LIFETIME`, `SYNAPSE_DB_MAX_CONN_IDLE`) is documented in `.env.example`.

## Evidence object store (S3 / MinIO)

| Variable | Description |
| -------- | ----------- |
| `SYNAPSE_BLOB_ENDPOINT` | `host:port` without a scheme. Empty ⇒ in-memory dev store. |
| `SYNAPSE_BLOB_ACCESS_KEY` / `SYNAPSE_BLOB_SECRET_KEY` | Object-store credentials. |
| `SYNAPSE_BLOB_BUCKET` | Bucket for evidence artifacts. |
| `SYNAPSE_BLOB_USE_SSL` | `true` for HTTPS endpoints. |

## Custody, signing & anchoring

The credential-vault master key and the signing seed are **required in production** (the
server fails closed without them). See `.env.example` for the exact variable names and formats.

## Scanning

Optional switches control SBOM producers, the owned advisory store, cross-checking,
reachability, and JAR hash-identity recovery — all documented inline in `.env.example`. The
defaults are safe: detection runs with a live advisory source plus the offline database when
present, and the optional analyses stay off until you enable them.

---

For the authoritative, exhaustive list of every environment variable with inline notes, read
[`.env.example`](../.env.example).
