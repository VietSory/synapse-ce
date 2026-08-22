package main

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/fleetclient"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestShipTelemetryPriorityTooManyRequestsKeepsWALAndSchedulesRetry(t *testing.T) {
	agentID := shared.ID("agent-429")
	s := openShipperTestSpool(t, agentID)
	enqueueShipperRecord(t, s, 1, time.Now().UTC())
	api := &fakeTelemetryTransport{shipErr: &fleetclient.HTTPStatusError{
		StatusCode: http.StatusTooManyRequests,
		RetryAfter: 3 * time.Second,
	}}
	cred := fleetclient.Credential{AgentID: agentID.String(), AssetID: "asset-server", Token: "secret"}

	shipped, retryAfter, err := (&runner{}).shipTelemetryPriority(
		context.Background(), s, api, cred, testTelemetrySigner(t, cred.AgentID), fleetagent.PriorityP3,
	)
	if err == nil || shipped || retryAfter != 3*time.Second {
		t.Fatalf("expected retryable 429, shipped=%t retry=%s err=%v", shipped, retryAfter, err)
	}
	var status *fleetclient.HTTPStatusError
	if !errors.As(err, &status) || !status.Retryable() || status.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("429 retry contract lost: %v", err)
	}
	left, peekErr := s.PeekPriority(context.Background(), fleetagent.PriorityP3, ports.PeekSpoolRequest{})
	if peekErr != nil {
		t.Fatalf("peek retained WAL: %v", peekErr)
	}
	if len(left) != 1 {
		t.Fatalf("429 backpressure must not delete WAL record, left=%d", len(left))
	}
}
