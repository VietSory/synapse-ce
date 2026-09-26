# Ticketing foundation

Issue #1423 introduces the storage and domain contracts for external tickets without
enabling any provider, new route, UI, or outbound write.

Mappings attach an existing integration to either one project or one engagement. Links
may attach an HTTPS ticket URL to a finding even when no integration is configured.
Write intents are idempotent by (tenant, integration, request key), while the immutable
correlation marker derives from the intent ID. A replay with different command content
is a conflict, not a second outbound operation.

The pure `internal/domain/writeintent` state machine is shared with future
documentation publishing. In-flight lease expiry leads to `uncertain`; this state
must never be submitted again without remote reconciliation. Exactly zero marker
matches permits `reconcile_absent` to return to pending, and exactly one match permits
`reconcile_found` to finalize. Multiple matches require human intervention.
An explicit, definitive provider rejection becomes `failed`.

All three tables use tenant-scoped composite foreign keys and
`synapse_enable_tenant_rls`. No provider credentials, outbound URLs with query
parameters, raw transport errors or API changes are stored here. The existing
integration connection and credential core remains the only reused framework part.
