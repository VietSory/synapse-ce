package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/fleetclient"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/spool"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type fakeTelemetryGapTransport struct {
	seen   []fleetagent.SignedTelemetryGap
	err    error
	ackID  shared.ID
	onShip func()
}

func (f *fakeTelemetryGapTransport) ShipTelemetryGap(_ context.Context, _ string, gap fleetagent.SignedTelemetryGap) (fleetclient.TelemetryGapShipResponse, error) {
	f.seen = append(f.seen, gap)
	if f.onShip != nil {
		f.onShip()
	}
	if f.err != nil {
		return fleetclient.TelemetryGapShipResponse{}, f.err
	}
	id := f.ackID
	if id.IsZero() {
		id = gap.Manifest.GapID
	}
	return fleetclient.TelemetryGapShipResponse{GapID: id}, nil
}

func openGapShipperSpool(t *testing.T, agentID shared.ID) *spool.Spool {
	t.Helper()
	cfg := spool.DefaultConfig()
	cfg.Dir = t.TempDir()
	cfg.Session = fleetagent.CanonicalSessionID(agentID)
	cfg.Boot = fleetagent.BootID("boot-gap-ship")
	cfg.MaxBytes = 6 << 10
	cfg.MaxGapBytes = 4 << 10
	cfg.SegmentBytes = 1200
	cfg.MaxRecordBytes = 600
	cfg.Sync[fleetagent.PriorityP3] = spool.SyncAlways
	s, err := spool.Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func gapShipperItem(priority fleetagent.DeliveryPriority, id string) ports.SpoolItem {
	class := detection.ClassProcess
	mustNotShed := false
	if priority == fleetagent.PriorityP2 {
		class = detection.ClassPrivilege
		mustNotShed = true
	}
	return ports.SpoolItem{
		Kind: ports.SpoolRecordTelemetry, Priority: priority, EventID: shared.ID(id), EventClass: class,
		ContentType: "application/vnd.synapse.telemetry-envelope+json;version=1",
		Payload: bytes.Repeat([]byte("x"), 500), ObservedAt: time.Now().UTC(), MustNotShed: mustNotShed, SchemaVersion: 1,
	}
}

func forceUnknownP3Gap(t *testing.T, s *spool.Spool, suffix string) ports.SpoolGap {
	t.Helper()
	for i := 0; ; i++ {
		_, err := s.Enqueue(context.Background(), gapShipperItem(fleetagent.PriorityP2, fmt.Sprintf("critical-%s-%d", suffix, i)))
		if errors.Is(err, spool.ErrSaturated) {
			break
		}
		if err != nil {
			t.Fatalf("fill spool: %v", err)
		}
	}
	_, err := s.Enqueue(context.Background(), gapShipperItem(fleetagent.PriorityP3, "dropped-"+suffix))
	if !errors.Is(err, spool.ErrSaturated) {
		t.Fatalf("P3 saturation error=%v", err)
	}
	gaps, err := s.Gaps(context.Background())
	if err != nil || len(gaps) == 0 {
		t.Fatalf("gaps=%+v err=%v", gaps, err)
	}
	return gaps[0]
}

func TestShipNextTelemetryGapDeletesOnlyAfterMatchingServerACK(t *testing.T) {
	agentID := shared.ID("agent-gap-ship")
	s := openGapShipperSpool(t, agentID)
	gap := forceUnknownP3Gap(t, s, "one")
	cred := fleetclient.Credential{AgentID: agentID.String(), AssetID: "asset-gap-ship", Token: "token"}
	signer := testTelemetrySigner(t, cred.AgentID)
	api := &fakeTelemetryGapTransport{}

	shipped, retryAfter, err := (&runner{}).shipNextTelemetryGap(context.Background(), s, api, cred, signer)
	if err != nil || !shipped || retryAfter != 0 {
		t.Fatalf("ship gap: shipped=%t retry=%s err=%v", shipped, retryAfter, err)
	}
	if len(api.seen) != 1 || api.seen[0].Manifest.GapID != gap.ID || api.seen[0].Manifest.Count != gap.Count {
		t.Fatalf("signed gap=%+v", api.seen)
	}
	left, err := s.Gaps(context.Background())
	if err != nil || len(left) != 0 {
		t.Fatalf("matching ACK did not delete local evidence: gaps=%+v err=%v", left, err)
	}
}

func TestShipNextTelemetryGapRetainsOnRetryableFailureAndForgedACK(t *testing.T) {
	agentID := shared.ID("agent-gap-retry")
	s := openGapShipperSpool(t, agentID)
	gap := forceUnknownP3Gap(t, s, "retry")
	cred := fleetclient.Credential{AgentID: agentID.String(), AssetID: "asset-gap-retry", Token: "token"}
	signer := testTelemetrySigner(t, cred.AgentID)

	api := &fakeTelemetryGapTransport{err: &fleetclient.HTTPStatusError{StatusCode: 503, RetryAfter: 3 * time.Second}}
	shipped, retryAfter, err := (&runner{}).shipNextTelemetryGap(context.Background(), s, api, cred, signer)
	if err == nil || shipped || retryAfter != 3*time.Second {
		t.Fatalf("503 gap retry: shipped=%t retry=%s err=%v", shipped, retryAfter, err)
	}
	left, _ := s.Gaps(context.Background())
	if len(left) != 1 || left[0].ID != gap.ID {
		t.Fatalf("503 deleted local gap: %+v", left)
	}

	api = &fakeTelemetryGapTransport{ackID: "forged-gap-id"}
	shipped, _, err = (&runner{}).shipNextTelemetryGap(context.Background(), s, api, cred, signer)
	if err == nil || shipped {
		t.Fatalf("forged gap ACK accepted: shipped=%t err=%v", shipped, err)
	}
	left, _ = s.Gaps(context.Background())
	if len(left) != 1 || left[0].ID != gap.ID {
		t.Fatalf("forged ACK deleted local gap: %+v", left)
	}
}

func TestShipNextTelemetryGapRetainsGrowthThatRacesACKThenConverges(t *testing.T) {
	agentID := shared.ID("agent-gap-growth")
	s := openGapShipperSpool(t, agentID)
	first := forceUnknownP3Gap(t, s, "growth")
	cred := fleetclient.Credential{AgentID: agentID.String(), AssetID: "asset-gap-growth", Token: "token"}
	signer := testTelemetrySigner(t, cred.AgentID)

	api := &fakeTelemetryGapTransport{}
	api.onShip = func() {
		api.onShip = nil
		_, err := s.Enqueue(context.Background(), gapShipperItem(fleetagent.PriorityP3, "dropped-growth-race"))
		if !errors.Is(err, spool.ErrSaturated) {
			t.Errorf("racing P3 loss error=%v", err)
		}
	}
	shipped, _, err := (&runner{}).shipNextTelemetryGap(context.Background(), s, api, cred, signer)
	if err != nil || !shipped {
		t.Fatalf("first gap ship: shipped=%t err=%v", shipped, err)
	}
	left, err := s.Gaps(context.Background())
	if err != nil || len(left) != 1 || left[0].ID != first.ID || left[0].Count <= first.Count {
		t.Fatalf("in-flight growth was lost: first=%+v left=%+v err=%v", first, left, err)
	}

	shipped, _, err = (&runner{}).shipNextTelemetryGap(context.Background(), s, api, cred, signer)
	if err != nil || !shipped {
		t.Fatalf("updated gap ship: shipped=%t err=%v", shipped, err)
	}
	if len(api.seen) != 2 || api.seen[1].Manifest.GapID != first.ID || api.seen[1].Manifest.Count != left[0].Count {
		t.Fatalf("updated evidence not re-sent: %+v", api.seen)
	}
	left, err = s.Gaps(context.Background())
	if err != nil || len(left) != 0 {
		t.Fatalf("current ACK did not converge local journal: gaps=%+v err=%v", left, err)
	}
}
