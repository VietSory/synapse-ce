package main

import (
	"context"
	"os"
	"testing"
)

func TestTelemetrySpoolExistsOnlyForDurableStateDirectory(t *testing.T) {
	r := &runner{cfg: config{stateDir: t.TempDir()}}
	if r.telemetrySpoolExists() {
		t.Fatal("fresh agent state falsely reported a telemetry backlog")
	}
	if err := os.MkdirAll(r.telemetrySpoolDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	if !r.telemetrySpoolExists() {
		t.Fatal("existing telemetry spool directory was not recognized for backlog drain")
	}
}

func TestStartSpoolMetricsWithoutListenerReturnsCompletedWorker(t *testing.T) {
	r := &runner{}
	done, err := r.startSpoolMetrics(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	default:
		t.Fatal("disabled metrics worker did not report completion")
	}
}
