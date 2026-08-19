package fleetdesired

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestNormalizeCapabilitiesCanonical(t *testing.T) {
	got, err := NormalizeCapabilities([]string{" telemetry.process ", "inventory.host", "telemetry.process", ""})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"inventory.host", "telemetry.process"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestNormalizeCapabilitiesBounds(t *testing.T) {
	tooMany := make([]string, MaxCapabilities+1)
	for i := range tooMany {
		tooMany[i] = fmt.Sprintf("cap.%d", i)
	}
	if _, err := NormalizeCapabilities(tooMany); err == nil {
		t.Fatal("expected capability-count validation error")
	}
	if _, err := NormalizeCapabilities([]string{strings.Repeat("x", MaxCapabilityLen+1)}); err == nil {
		t.Fatal("expected capability-length validation error")
	}
	if _, err := NormalizeCapabilities([]string{"sensor\nexec"}); err == nil {
		t.Fatal("expected control-character validation error")
	}
}

func TestStateValidateRequiresCanonicalCapabilities(t *testing.T) {
	now := time.Date(2026, 8, 19, 1, 2, 3, 0, time.UTC)
	state := State{
		TenantID: shared.ID("tenant-1"), AgentID: shared.ID("agent-1"), UpdatedBy: shared.ID("operator-1"),
		Capabilities: []string{"z", "a"}, Audit: shared.Audit{CreatedAt: now, UpdatedAt: now},
	}
	if err := state.Validate(); err == nil {
		t.Fatal("expected non-canonical ordering to be rejected")
	}
	state.Capabilities = []string{"a", "z"}
	if err := state.Validate(); err != nil {
		t.Fatalf("canonical state rejected: %v", err)
	}
}
