// Package storetest holds the shared memory/PostgreSQL J01 conformance contract.
package storetest

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/ticketing"
	"github.com/KKloudTarus/synapse-ce/internal/domain/writeintent"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type Fixture struct {
	Tenant, Other, Integration, Engagement, Finding shared.ID
}

// Run exercises identical tenant isolation, copy safety, idempotency and CAS in both adapters.
// PostgreSQL callers must first seed matching integration/engagement/finding fixtures.
func Run(t *testing.T, store ports.TicketStore, f Fixture) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)
	mapping := ticketing.Mapping{ID: "ticket-j01-map-a", TenantID: f.Tenant, IntegrationID: f.Integration,
		Scope: ticketing.Engagement, ScopeID: f.Engagement, ProjectKey: "SEC", IssueType: "Bug",
		SecurityLevel: "restricted", Labels: []string{"synapse"}, PriorityMap: map[string]string{"high": "Highest"},
		Version: 1, CreatedAt: now, UpdatedAt: now}
	if err := store.CreateMapping(ctx, f.Tenant, mapping); err != nil {
		t.Fatalf("create mapping: %v", err)
	}
	if err := store.CreateMapping(ctx, f.Tenant, mapping); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("duplicate mapping: %v", err)
	}
	saved, err := store.GetMapping(ctx, f.Tenant, mapping.ID)
	if err != nil || saved.ProjectKey != "SEC" {
		t.Fatalf("mapping: %+v, %v", saved, err)
	}
	saved.Labels[0] = "mutated"
	saved.PriorityMap["high"] = "mutated"
	saved, err = store.GetMapping(ctx, f.Tenant, mapping.ID)
	if err != nil || saved.Labels[0] != "synapse" || saved.PriorityMap["high"] != "Highest" {
		t.Fatalf("mapping clone isolation: %+v, %v", saved, err)
	}
	if _, err = store.GetMapping(ctx, f.Other, mapping.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant mapping lookup: %v", err)
	}

	link := ticketing.Link{ID: "ticket-j01-link-a", TenantID: f.Tenant, EngagementID: f.Engagement,
		FindingID: f.Finding, ExternalURL: "https://jira.example/browse/SEC-12", CreatedAt: now}
	got, created, err := store.CreateLink(ctx, f.Tenant, link)
	if err != nil || !created || got.ID != link.ID {
		t.Fatalf("create manual link: %+v %t %v", got, created, err)
	}
	repeated := link
	repeated.ID = "ticket-j01-link-replay"
	got, created, err = store.CreateLink(ctx, f.Tenant, repeated)
	if err != nil || created || got.ID != link.ID {
		t.Fatalf("link replay: %+v %t %v", got, created, err)
	}
	repeated.IntegrationID = f.Integration
	repeated.ExternalID = "SEC-12"
	if _, _, err = store.CreateLink(ctx, f.Tenant, repeated); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("link identity mismatch: %v", err)
	}
	links, err := store.ListLinks(ctx, f.Other, f.Finding)
	if err != nil || len(links) != 0 {
		t.Fatalf("cross-tenant links: %+v %v", links, err)
	}
	if err = store.DeleteLink(ctx, f.Other, link.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant delete: %v", err)
	}

	intent := ticketing.Intent{ID: "ticket-j01-intent-a", TenantID: f.Tenant,
		IntegrationID: f.Integration, MappingID: mapping.ID, EngagementID: f.Engagement, FindingID: f.Finding,
		Action: ticketing.Create, RequestKey: "submit-once", PayloadDigest: strings.Repeat("a", 64),
		Marker: "synapse-intent-ticket-j01-intent-a", State: writeintent.Pending, Version: 1,
		CreatedAt: now, UpdatedAt: now}
	gotIntent, created, err := store.CreateOrGetIntent(ctx, f.Tenant, intent)
	if err != nil || !created || gotIntent.ID != intent.ID {
		t.Fatalf("create intent: %+v %t %v", gotIntent, created, err)
	}
	replay := intent
	replay.ID = "ticket-j01-new-id"
	replay.Marker = "synapse-intent-ticket-j01-new-id"
	gotIntent, created, err = store.CreateOrGetIntent(ctx, f.Tenant, replay)
	if err != nil || created || gotIntent.ID != intent.ID {
		t.Fatalf("intent replay: %+v %t %v", gotIntent, created, err)
	}
	replay.PayloadDigest = strings.Repeat("b", 64)
	if _, _, err = store.CreateOrGetIntent(ctx, f.Tenant, replay); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("mismatched request payload should conflict: %v", err)
	}
	if _, err = store.GetIntent(ctx, f.Other, intent.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant intent lookup: %v", err)
	}

	started := now.Add(time.Second)
	expires := started.Add(time.Minute)
	active, err := store.TransitionIntent(ctx, f.Tenant, intent.ID, 1, writeintent.Claim, &expires, started)
	if err != nil || active.State != writeintent.InFlight || active.Attempts != 1 || active.Version != 2 {
		t.Fatalf("claim: %+v %v", active, err)
	}
	if _, err = store.TransitionIntent(ctx, f.Tenant, intent.ID, 1, writeintent.Claim, &expires, started); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("stale CAS: %v", err)
	}
	if _, err = store.TransitionIntent(ctx, f.Tenant, intent.ID, 2, writeintent.LeaseExpired, nil, started.Add(time.Second)); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("premature lease expiry: %v", err)
	}
	uncertain, err := store.TransitionIntent(ctx, f.Tenant, intent.ID, 2, writeintent.LeaseExpired, nil, expires)
	if err != nil || uncertain.State != writeintent.Uncertain || uncertain.LeaseUntil != nil {
		t.Fatalf("expired lease must become uncertain: %+v %v", uncertain, err)
	}
	if _, err = store.TransitionIntent(ctx, f.Tenant, intent.ID, 3, writeintent.Claim, &expires, expires.Add(time.Second)); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("blind POST retry accepted: %v", err)
	}
	pending, err := store.TransitionIntent(ctx, f.Tenant, intent.ID, 3, writeintent.ReconcileAbsent, nil, expires.Add(time.Second))
	if err != nil || pending.State != writeintent.Pending {
		t.Fatalf("reconcile absent: %+v %v", pending, err)
	}
	expires2 := expires.Add(2 * time.Minute)
	active, err = store.TransitionIntent(ctx, f.Tenant, intent.ID, 4, writeintent.Claim, &expires2, expires.Add(2*time.Second))
	if err != nil || active.Attempts != 2 {
		t.Fatalf("reconciled retry: %+v %v", active, err)
	}
	done, err := store.TransitionIntent(ctx, f.Tenant, intent.ID, 5, writeintent.Acknowledge, nil, expires.Add(3*time.Second))
	if err != nil || done.State != writeintent.Done {
		t.Fatalf("acknowledge: %+v %v", done, err)
	}
	if _, err = store.TransitionIntent(ctx, f.Tenant, intent.ID, 6, writeintent.Claim, &expires2, expires.Add(4*time.Second)); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("terminal command was retried: %v", err)
	}

	// A provider-returned marker search is the only path out of uncertain.
	intent.ID = "ticket-j01-intent-b"
	intent.Marker = "synapse-intent-" + intent.ID.String()
	intent.RequestKey = "another-request"
	_, created, err = store.CreateOrGetIntent(ctx, f.Tenant, intent)
	if err != nil || !created {
		t.Fatalf("create second intent: %v", err)
	}
	active, err = store.TransitionIntent(ctx, f.Tenant, intent.ID, 1, writeintent.Claim, &expires, started)
	if err != nil {
		t.Fatalf("claim second: %v", err)
	}
	uncertain, err = store.TransitionIntent(ctx, f.Tenant, intent.ID, 2, writeintent.Ambiguous, nil, started.Add(time.Second))
	if err != nil || uncertain.State != writeintent.Uncertain {
		t.Fatalf("mark ambiguous: %+v %v", uncertain, err)
	}
	done, err = store.TransitionIntent(ctx, f.Tenant, intent.ID, 3, writeintent.ReconcileFound, nil, started.Add(2*time.Second))
	if err != nil || done.State != writeintent.Done {
		t.Fatalf("reconcile found: %+v %v", done, err)
	}
	if err = store.DeleteLink(ctx, f.Tenant, link.ID); err != nil {
		t.Fatalf("delete link: %v", err)
	}
	if remaining, listErr := store.ListLinks(ctx, f.Tenant, f.Finding); listErr != nil || len(remaining) != 0 {
		t.Fatalf("deleted links: %+v %v", remaining, listErr)
	}
}

// ConcurrentReplay proves an idempotency key can be won by just one caller, even
// when many requests generate different IDs before attempting to persist.
func ConcurrentReplay(t *testing.T, store ports.TicketStore, f Fixture) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)
	m, err := store.GetMapping(ctx, f.Tenant, "ticket-j01-map-a")
	if err != nil {
		t.Fatalf("load conformance mapping: %v", err)
	}
	const workers = 12
	type reply struct {
		id      shared.ID
		created bool
		err     error
	}
	result := make(chan reply, workers)
	var wg sync.WaitGroup
	for n := 0; n < workers; n++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			id := shared.ID("ticket-j01-race-" + string(rune('a'+n)))
			intent := ticketing.Intent{ID: id, TenantID: f.Tenant, IntegrationID: f.Integration,
				MappingID: m.ID, FindingID: f.Finding, EngagementID: f.Engagement, Action: ticketing.Create,
				RequestKey: "race-request", PayloadDigest: strings.Repeat("f", 64),
				Marker: "synapse-intent-" + id.String(), State: writeintent.Pending, Version: 1, CreatedAt: now, UpdatedAt: now}
			item, created, err := store.CreateOrGetIntent(ctx, f.Tenant, intent)
			result <- reply{id: item.ID, created: created, err: err}
		}(n)
	}
	wg.Wait()
	close(result)
	count := 0
	var winner shared.ID
	for r := range result {
		if r.err != nil {
			t.Fatalf("parallel retry: %v", r.err)
		}
		if r.created {
			count++
		}
		if winner.IsZero() {
			winner = r.id
		} else if winner != r.id {
			t.Fatalf("duplicate durable intents: %s != %s", winner, r.id)
		}
	}
	if count != 1 {
		t.Fatalf("created %d intents, expected 1", count)
	}
}
