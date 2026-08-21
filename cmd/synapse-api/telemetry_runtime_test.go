package main

import "testing"

func TestWireFleetTelemetryRejectsPartialDependencies(t *testing.T) {
	t.Parallel()

	if err := wireFleetTelemetry(nil, nil, nil, nil, nil); err == nil {
		t.Fatal("expected telemetry runtime wiring to reject a partial dependency set")
	}
}
