# A3 fleet telemetry transport (#624)

This document records the runtime and persistence contract implemented by the A3 telemetry transport. It is intentionally scoped to the fleet-agent transport boundary; downstream telemetry materialization remains a separate concern.

## Trust and identity boundary

The authenticated fleet credential is authoritative for `agent_id` and tenant. The canonical `asset_id` is resolved from the server-side `telemetry_asset_bindings` row established by inventory reconciliation. A request body cannot create or change that binding. `agent_session_id` is derived from the authenticated agent identity and the delivery `stream_id` is derived from `(agent_id, agent_session_id, priority)`.

Agents keep an Ed25519 telemetry signing key in their state directory with mode `0600`. A usable key is reused across process restarts and rotated before its bounded validity window expires. Registration sends only the public lifecycle record plus proof of possession. Registration retries transient network/429/5xx failures and honors `Retry-After`; terminal rejections fail closed. Telemetry batches and agent-origin gap reports are rejected if the key is unknown, expired/not-yet-valid, belongs to a different agent or purpose, or if the signed commitment does not verify.

## Durable delivery and ACK semantics

The agent writes normalized telemetry to the local spool before transport. Each raw telemetry priority lane is shipped as a contiguous `(epoch, sequence)` prefix. The HTTP client gzip-compresses signed telemetry batches. A local WAL record is acknowledged/deleted only after the server returns an ACK whose priority and epoch match the batch and whose `through` sequence covers the sent record. HTTP 429/5xx failures retain the WAL record and honor `Retry-After`; terminal 4xx rejections also retain it for diagnosis/recovery rather than silently discarding evidence.

The server persists transport provenance transactionally in `telemetry_delivery_streams`, `telemetry_delivery_sequences`, `telemetry_delivery_batches`, `telemetry_gaps`, and the A3 columns of `telemetry_events`. ACK progress is derived from durable contiguous sequence rows, never from receipt of an HTTP request. Re-delivery of the same delivery key is idempotent. A higher epoch is a new incarnation and may reset sequence to 1; stale epochs cannot advance the stream. Forward holes stay explicit in `telemetry_gaps` until late delivery resolves them. Gap time windows are anchored by persisted neighboring event times so a retro hunt that crosses a missing interval cannot be reported complete merely because the hole was discovered or partially filled later.

## Agent-origin spool loss

Local spool loss is a different provenance class from a server-inferred delivery hole. Quota eviction, quota backpressure, corrupt/torn frames, I/O failure, unsynced tails, and state recovery are retained in the durable local `gaps.log`. Some of these records have a trustworthy sequence range; others deliberately carry `known_sequence=false` rather than inventing coordinates.

A3 ships each local loss record as a purpose-bound Ed25519-signed gap report over `POST /api/v1/fleet/telemetry` using media type `application/vnd.synapse.telemetry-gap+json`. The signed manifest commits the stable `gap_id`, canonical agent/host/session/asset/stream identity, lane/epoch, known or unknown sequence shape, reason, count, and occurrence time. The server re-derives all server-authoritative identity before persistence and stores the evidence separately in `telemetry_agent_gaps`; delivery late-fill reconciliation never resolves or rewrites agent-origin loss.

Agent-origin gap persistence is idempotent by `(tenant_id, agent_id, gap_id)`. A stable local gap may grow while it is being coalesced, so the server accepts only monotonic extensions of the same signed evidence and rejects shrink/re-point attempts. On the agent, a server `gap_id` ACK removes local evidence only if the current durable gap still exactly matches the snapshot that was sent. If the gap grew while the HTTP request was in flight, the older ACK cannot delete the newer evidence; the updated snapshot is sent again and only the current ACK may rewrite/sync the local gap journal.

Retro-hunt completeness consumes both unresolved delivery holes and durable agent-origin loss through separate readers. Unknown-coordinate agent loss can therefore make an intersecting hunt incomplete without fabricating a fake sequence gap. Priority/class filtering remains intact so loss in one lane does not poison unrelated class-only hunts.

All A3 persistence tables are tenant-scoped and have PostgreSQL RLS enabled through `synapse_enable_tenant_rls`. Foreign keys also carry tenant identity so referential integrity cannot cross tenants even though PostgreSQL FK checks bypass RLS. `telemetry_agent_gaps` is added by migration `0110` and has the same tenant/RLS boundary.

## Schema compatibility

A3 accepts supported telemetry envelope schema versions concurrently (currently v1 and v2). Each signed batch commits one schema version and the server validates every decoded event against that commitment. Unknown versions fail closed; mixed-schema spool records are split at the schema boundary before signing. Agent-origin gap reports use their own protocol-v1 signed manifest and are not telemetry-envelope schema values.

## Validation expectations

Release evidence for #624 should include Linux and Windows build/vet/test, the PostgreSQL integration suite with migrations applied to a real database, Go lint, race-sensitive transport/spool tests where supported, Agent Package Matrix, OpenAPI route/content coverage for the fleet transport endpoints, and regression coverage for in-flight gap coalescing. Branch-specific failures must be fixed; unrelated failures already present on the base branch should be kept out of #624.
