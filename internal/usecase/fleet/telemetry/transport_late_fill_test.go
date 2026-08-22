package telemetry

import (
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/telemetry"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestTransportLateFillResolvesGapAndAdvancesACK(t *testing.T) {
	f := newTransportFixture(t)

	if res, err := f.svc.IngestSigned(f.ctx, f.agent, f.batch(t, telemetry.SchemaVersion, 1, 1)); err != nil {
		t.Fatal(err)
	} else if res.ACK.Through != 1 {
		t.Fatalf("first ACK through = %d, want 1", res.ACK.Through)
	}

	if res, err := f.svc.IngestSigned(f.ctx, f.agent, f.batch(t, telemetry.SchemaVersion, 1, 3)); err != nil {
		t.Fatal(err)
	} else {
		if res.ACK.Through != 1 {
			t.Fatalf("ACK crossed an unresolved gap: through=%d, want 1", res.ACK.Through)
		}
		if len(res.Gaps) != 1 || res.Gaps[0].FromSequence != 2 || res.Gaps[0].ToSequence != 2 {
			t.Fatalf("missing sequence 2 was not surfaced as the current gap: %+v", res.Gaps)
		}
	}

	res, err := f.svc.IngestSigned(f.ctx, f.agent, f.batch(t, telemetry.SchemaVersion, 1, 2))
	if err != nil {
		t.Fatalf("late fill sequence 2: %v", err)
	}
	if res.NewEvents != 1 {
		t.Fatalf("late fill new events = %d, want 1", res.NewEvents)
	}
	if res.ACK.Through != 3 {
		t.Fatalf("highest-contiguous ACK after late fill = %d, want 3", res.ACK.Through)
	}
	if len(res.Gaps) != 0 {
		t.Fatalf("resolved gap remained current after late fill: %+v", res.Gaps)
	}

	gaps, err := f.store.QueryDeliveryGaps(f.ctx, ports.HuntQuery{AssetID: f.assetID})
	if err != nil {
		t.Fatal(err)
	}
	if len(gaps) != 0 {
		t.Fatalf("resolved gap must not remain queryable as current incompleteness: %+v", gaps)
	}
}
