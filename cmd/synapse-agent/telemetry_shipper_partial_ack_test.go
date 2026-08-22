package main

import (
	"context"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/fleetclient"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestShipTelemetryPriorityPartialACKRetainsUnackedTailAndConverges(t *testing.T) {
	agentID := shared.ID("agent-partial-ack")
	s := openShipperTestSpool(t, agentID)
	at := time.Now().UTC().Truncate(time.Microsecond)
	first := enqueueShipperRecord(t, s, 1, at)
	second := enqueueShipperRecord(t, s, 1, at.Add(time.Millisecond))
	if second.Sequence != first.Sequence+1 {
		t.Fatalf("test requires contiguous spool sequence: first=%+v second=%+v", first, second)
	}

	api := &fakeTelemetryTransport{ack: &fleetclient.FleetTelemetryACK{
		Priority: fleetagent.PriorityP3,
		Epoch:    first.Epoch,
		Through:  first.Sequence,
	}}
	cred := fleetclient.Credential{AgentID: agentID.String(), AssetID: "asset-server", Token: "secret"}
	signer := testTelemetrySigner(t, cred.AgentID)

	shipped, retryAfter, err := (&runner{}).shipTelemetryPriority(context.Background(), s, api, cred, signer, fleetagent.PriorityP3)
	if err != nil || !shipped || retryAfter != 0 {
		t.Fatalf("partial ACK should make durable progress: shipped=%t retry=%s err=%v", shipped, retryAfter, err)
	}
	left, err := s.PeekPriority(context.Background(), fleetagent.PriorityP3, ports.PeekSpoolRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if len(left) != 1 || left[0].Position != second {
		t.Fatalf("partial ACK must retain only the unacked tail: left=%+v want=%+v", left, second)
	}

	api.ack = nil
	shipped, retryAfter, err = (&runner{}).shipTelemetryPriority(context.Background(), s, api, cred, signer, fleetagent.PriorityP3)
	if err != nil || !shipped || retryAfter != 0 {
		t.Fatalf("retrying retained tail should converge: shipped=%t retry=%s err=%v", shipped, retryAfter, err)
	}
	left, err = s.PeekPriority(context.Background(), fleetagent.PriorityP3, ports.PeekSpoolRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if len(left) != 0 {
		t.Fatalf("fully ACKed tail must be removed after convergence, left=%d", len(left))
	}
}
