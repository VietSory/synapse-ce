package fleetdesired_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	desireddom "github.com/KKloudTarus/synapse-ce/internal/domain/fleetdesired"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	desireduc "github.com/KKloudTarus/synapse-ce/internal/usecase/fleetdesired"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type testClock struct{ now time.Time }
func (c *testClock) Now() time.Time { return c.now }

type testAudit struct{ entries []ports.AuditEntry }
func (a *testAudit) Record(_ context.Context, entry ports.AuditEntry) error {
	a.entries = append(a.entries, entry)
	return nil
}

func createAgent(t *testing.T, store *memory.FleetAgentStore, id string, caps []string, at time.Time) {
	t.Helper()
	agent, err := fleetagent.NewAgent(shared.ID(id), shared.ID("tenant-1"), id, "linux", "", "1.0.0", caps, "not-a-real-secret-hash", at)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CreateAgent(context.Background(), agent); err != nil {
		t.Fatal(err)
	}
}

func TestSetDesiredCapabilitiesNormalizesAuditsAndPreservesCreatedAt(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 8, 19, 1, 0, 0, 0, time.UTC)
	clock := &testClock{now: now}
	agents := memory.NewFleetAgentStore()
	createAgent(t, agents, "agent-1", []string{"telemetry.process"}, now)
	store := memory.NewFleetDesiredStore()
	audit := &testAudit{}
	svc, err := desireduc.NewService(store, agents, audit, clock, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	first, err := svc.SetDesiredCapabilities(ctx, desireduc.SetInput{
		TenantID: shared.ID("tenant-1"), AgentID: shared.ID("agent-1"), Actor: shared.ID("operator-1"),
		Capabilities: []string{" telemetry.process ", "inventory.host", "telemetry.process"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Capabilities) != 2 || first.Capabilities[0] != "inventory.host" || first.Capabilities[1] != "telemetry.process" {
		t.Fatalf("capabilities not canonical: %v", first.Capabilities)
	}
	clock.now = now.Add(time.Minute)
	second, err := svc.SetDesiredCapabilities(ctx, desireduc.SetInput{
		TenantID: shared.ID("tenant-1"), AgentID: shared.ID("agent-1"), Actor: shared.ID("operator-2"),
		Capabilities: []string{"telemetry.network"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !second.Audit.CreatedAt.Equal(first.Audit.CreatedAt) || !second.Audit.UpdatedAt.Equal(clock.now) {
		t.Fatalf("audit timestamps not preserved/moved: first=%v second=%v", first.Audit, second.Audit)
	}
	if len(audit.entries) != 2 || audit.entries[1].Action != "fleet.desired_capabilities.set" || audit.entries[1].Actor != "operator-2" {
		t.Fatalf("unexpected audit entries: %#v", audit.entries)
	}
}

func TestSetDesiredCapabilitiesRejectsUnknownAgent(t *testing.T) {
	ctx := context.Background()
	clock := &testClock{now: time.Now().UTC()}
	store := memory.NewFleetDesiredStore()
	svc, err := desireduc.NewService(store, memory.NewFleetAgentStore(), &testAudit{}, clock, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	_, err = svc.SetDesiredCapabilities(ctx, desireduc.SetInput{
		TenantID: shared.ID("tenant-1"), AgentID: shared.ID("missing"), Actor: shared.ID("operator"), Capabilities: []string{"x"},
	})
	if !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("got %v want ErrNotFound", err)
	}
	if _, getErr := store.Get(ctx, shared.ID("tenant-1"), shared.ID("missing")); !errors.Is(getErr, shared.ErrNotFound) {
		t.Fatalf("unknown agent wrote desired state: %v", getErr)
	}
}

func TestReconcileSurfacesEveryDesiredGapWithoutWrites(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 8, 19, 2, 0, 0, 0, time.UTC)
	clock := &testClock{now: now}
	agents := memory.NewFleetAgentStore()
	createAgent(t, agents, "agent-healthy", []string{"telemetry.network", "telemetry.process"}, now)
	createAgent(t, agents, "agent-stale", []string{"telemetry.process"}, now.Add(-10*time.Minute))
	createAgent(t, agents, "agent-revoked", []string{"telemetry.process"}, now)
	createAgent(t, agents, "agent-decommissioned", []string{"telemetry.process"}, now)
	if err := agents.Revoke(ctx, shared.ID("tenant-1"), shared.ID("agent-revoked"), shared.ID("operator"), "test", now); err != nil {
		t.Fatal(err)
	}
	if err := agents.Decommission(ctx, shared.ID("tenant-1"), shared.ID("agent-decommissioned"), now); err != nil {
		t.Fatal(err)
	}

	store := memory.NewFleetDesiredStore()
	put := func(agent string, caps ...string) {
		t.Helper()
		state := &desireddom.State{
			TenantID: shared.ID("tenant-1"), AgentID: shared.ID(agent), Capabilities: caps, UpdatedBy: shared.ID("operator"),
			Audit: shared.Audit{CreatedAt: now, UpdatedAt: now},
		}
		if err := store.Put(ctx, state); err != nil {
			t.Fatal(err)
		}
	}
	put("agent-healthy", "telemetry.file", "telemetry.network", "telemetry.process")
	put("agent-stale", "telemetry.process")
	put("agent-revoked", "telemetry.process")
	put("agent-decommissioned", "telemetry.process")
	put("agent-missing", "telemetry.process") // desired intent deliberately outlives a missing observed agent row.

	svc, err := desireduc.NewService(store, agents, &testAudit{}, clock, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := svc.Reconcile(ctx, shared.ID("tenant-1"))
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 7 {
		t.Fatalf("got %d rows: %#v", len(rows), rows)
	}
	want := map[string]desireddom.GapReason{
		"agent-healthy/telemetry.file": desireddom.GapCapabilityMissing,
		"agent-stale/telemetry.process": desireddom.GapAgentStale,
		"agent-revoked/telemetry.process": desireddom.GapAgentRevoked,
		"agent-decommissioned/telemetry.process": desireddom.GapAgentDecommissioned,
		"agent-missing/telemetry.process": desireddom.GapAgentMissing,
	}
	covered := 0
	for _, row := range rows {
		key := row.AgentID + "/" + row.Capability
		if row.Covered {
			covered++
			if row.GapReason != "" {
				t.Fatalf("covered row %s carries gap %q", key, row.GapReason)
			}
			continue
		}
		if got, ok := want[key]; !ok || row.GapReason != got {
			t.Fatalf("row %s gap=%q want=%q (known=%v)", key, row.GapReason, got, ok)
		}
	}
	if covered != 2 {
		t.Fatalf("covered=%d want 2", covered)
	}
	gaps, err := svc.Gaps(ctx, shared.ID("tenant-1"))
	if err != nil {
		t.Fatal(err)
	}
	if len(gaps) != len(want) {
		t.Fatalf("gaps=%d want %d: %#v", len(gaps), len(want), gaps)
	}
}
