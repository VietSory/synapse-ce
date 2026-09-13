package ebpf

import (
	"context"
	"errors"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestRuntimeSymbolProbeValidation(t *testing.T) {
	valid, err := (RuntimeSymbolProbe{Path: "/usr/lib/libexample.so", Symbol: " vulnerable ", PID: 0}).validate()
	if err != nil {
		t.Fatalf("valid probe rejected: %v", err)
	}
	if valid.Symbol != "vulnerable" {
		t.Fatalf("symbol not normalized: %q", valid.Symbol)
	}
	if valid.Path != "/usr/lib/libexample.so" {
		t.Fatalf("path not normalized: %q", valid.Path)
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

func TestRuntimeProbeKeySeparatesPathSymbolAndPID(t *testing.T) {
	base := RuntimeSymbolProbe{Path: "/usr/lib/libexample.so", Symbol: "f", PID: 7}
	keys := map[string]bool{}
	for _, probe := range []RuntimeSymbolProbe{
		base,
		{Path: base.Path + ".2", Symbol: base.Symbol, PID: base.PID},
		{Path: base.Path, Symbol: "g", PID: base.PID},
		{Path: base.Path, Symbol: base.Symbol, PID: 8},
	} {
		key := runtimeProbeKey(probe)
		if keys[key] {
			t.Fatalf("probe key collision for %+v", probe)
		}
		keys[key] = true
	}
}

func TestNewRuntimeSensorRequiresHost(t *testing.T) {
	if _, err := NewRuntimeSensor(""); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("expected missing-host validation error, got %v", err)
	}
}

func TestAttachSymbolProbeHonorsCanceledContext(t *testing.T) {
	sensor, err := NewRuntimeSensor("host-runtime-test")
	if err != nil {
		t.Fatalf("new runtime sensor: %v", err)
	}
	defer func() { _ = sensor.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err = sensor.AttachSymbolProbe(ctx, RuntimeSymbolProbe{Path: "/usr/lib/libexample.so", Symbol: "f"})
	if !errors.Is(err, ErrRuntimeSensorUnavailable) {
		t.Fatalf("expected canceled attach to report sensor-unavailable without evidence, got %v", err)
	}
}
