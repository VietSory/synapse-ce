# A3 fleet telemetry transport (#624)

This document records the runtime and persistence contract implemented by the A3 telemetry transport. It is intentionally scoped to the fleet-agent transport boundary; downstream telemetry materialization remains a separate concern.

## Trust and identity boundary

The authenticated fleet credential is authoritative for `agent_id` and tenant. The canonical `asset_id` is resolved from the server-side `telemetry_asset_bindings` row established by inventory reconciliation. A request body cannot create or change that binding. `agent_session_id` is derived from the authenticated agent identity and the delivery `stream_id` is derived from `(agent_id, agent_session_id, priority)`.

Agents keep an Ed25519 telemetry signing key in their state directory with mode `0600`. A usable key is reused across process restarts and rotated after its bounded validity window. Registration sends only the public lifecycle record plus proof of possession. Telemetry batches are rejected if the key is unknown, expired/not-yet-valid, belongs to a different agent or purpose, or if the committed manifest/payload signature does not verify.

## Durable delivery and ACK semantics

The agent writes normalized telemetry to the local spool before transport. Each priority lane is shipped as a contiguous `(epoch, sequence)` prefix. The HTTP client gzip-compresses the signed batch. A local spool record is acknowledged/deleted only after the server returns an ACK whose priority and epoch match the batch and whose `through` sequence covers the sent record. HTTP 429/5xx failures retain the WAL record and honor `Retry-After`; terminal 4xx rejections also retain the record for diagnosis/recovery rather than silently discarding evidence.

The server persists transport provenance transactionally in `telemetry_delivery_streams`, `telemetry_delivery_sequences`, `telemetry_delivery_batches`, `telemetry_gaps`, and the A3 columns of `telemetry_events`. ACK progress is derived from durable contiguous sequence rows, never from receipt of an HTTP request. Re-delivery of the same delivery key is idempotent. A higher epoch is a new incarnation and may reset sequence to 1; stale epochs cannot advance the stream. Forward holes stay explicit in `telemetry_gaps` until late delivery resolves them.

All A3 persistence tables are tenant-scoped and have PostgreSQL RLS enabled through `synapse_enable_tenant_rls`. Foreign keys also carry tenant identity so referential integrity cannot cross tenants even though PostgreSQL FK checks bypass RLS.

## Schema compatibility

A3 accepts supported telemetry envelope schema versions concurrently (currently v1 and v2). Each signed batch commits one schema version and the server validates every decoded event against that commitment. Unknown versions fail closed; mixed-schema spool records are split at the schema boundary before signing.

## Validation expectations

Release evidence for #624 should include Linux and Windows build/vet/test, the PostgreSQL integration suite with migrations applied to a real database, Go lint, race-sensitive transport/spool tests where supported, and OpenAPI route coverage for the two fleet transport endpoints. Branch-specific failures must be fixed; unrelated failures already present on the base branch should be kept out of #624.
