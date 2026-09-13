package ebpf

import (
	"errors"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestRuntimeSymbolProbeValidation(t *testing.T) {
	valid, err := (RuntimeSymbolProbe{Path: " /usr/lib/libexample.so ", Symbol: " vulnerable ", PID: 7}).validate()
	if err != nil {
		t.Fatalf("valid probe rejected: %v", err)
	}
	if valid.Path != "/usr/lib/libexample.so" || valid.Symbol != "vulnerable" || valid.PID != 7 {
		t.Fatalf("probe normalization = %+v", valid)
	}
	for _, probe := range []RuntimeSymbolProbe{
		{Path: "relative/lib.so", Symbol: "f"},
		{Path: "/usr/lib/lib.so", Symbol: ""},
		{Path: "/usr/lib/lib.so", Symbol: "f", PID: -1},
	} {
		if _, err := probe.validate(); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("expected validation error for %+v, got %v", probe, err)
		}
	}
}
