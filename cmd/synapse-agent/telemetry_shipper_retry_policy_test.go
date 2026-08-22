package main

import (
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/fleetclient"
)

func TestTelemetryDeliveryRetryStopsOnTerminal4xx(t *testing.T) {
	retry, wait := telemetryDeliveryRetry(&fleetclient.HTTPStatusError{StatusCode: 422}, 0)
	if retry || wait != 0 {
		t.Fatalf("terminal telemetry rejection must not retry: retry=%t wait=%s", retry, wait)
	}
}

func TestTelemetryDeliveryRetryHonorsBackpressureAndNetworkErrors(t *testing.T) {
	retry, wait := telemetryDeliveryRetry(&fleetclient.HTTPStatusError{StatusCode: 503, RetryAfter: 4 * time.Second}, 4*time.Second)
	if !retry || wait != 4*time.Second {
		t.Fatalf("503 retry policy lost: retry=%t wait=%s", retry, wait)
	}
	retry, wait = telemetryDeliveryRetry(errors.New("temporary network failure"), 0)
	if !retry || wait != telemetryShipBackoff {
		t.Fatalf("network failure must use bounded retry: retry=%t wait=%s", retry, wait)
	}
}
