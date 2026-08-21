package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/fleetclient"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/spool"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	telemetryShipMaxRecords = 256
	telemetryShipMaxBytes   = 1 << 20
	telemetryShipIdle       = 500 * time.Millisecond
	telemetryShipBackoff    = time.Second
)

// telemetryTransport is deliberately narrower than fleetAPI so older/unit-test fakes
// remain valid. The real *fleetclient.Client implements it.
type telemetryTransport interface {
	RegisterTelemetrySigningKey(context.Context, string, fleetagent.AgentSigningKey, string) error
	ShipTelemetry(context.Context, string, fleetagent.SignedTelemetryBatch) (fleetclient.TelemetryShipResponse, error)
}

func (r *runner) startTelemetryShipper(ctx context.Context, durable *spool.Spool, cred fleetclient.Credential) {
	api, ok := r.api.(telemetryTransport)
	if !ok {
		return
	}
	if cred.AgentID == "" || cred.AssetID == "" {
		log.Printf("telemetry transport disabled: canonical agent/asset binding is incomplete")
		return
	}
	signer, err := r.store.EnsureTelemetrySigner(cred.AgentID, time.Now().UTC())
	if err != nil {
		log.Printf("telemetry transport signer unavailable: %v", err)
		return
	}
	proof := fleetagent.ProveKeyPossession(signer.PrivateKey, signer.Key)
	if err := api.RegisterTelemetrySigningKey(ctx, cred.Token, signer.Key, proof); err != nil {
		log.Printf("telemetry signing-key registration failed (will not ship unsigned data): %v", err)
		return
	}
	go r.telemetryShipLoop(ctx, durable, api, cred, signer)
}

func (r *runner) telemetryShipLoop(ctx context.Context, durable *spool.Spool, api telemetryTransport, cred fleetclient.Credential, signer fleetclient.TelemetrySigner) {
	for {
		progress := false
		for _, priority := range []fleetagent.DeliveryPriority{fleetagent.PriorityP2, fleetagent.PriorityP3} {
			shipped, retryAfter, err := r.shipTelemetryPriority(ctx, durable, api, cred, signer, priority)
			if err != nil {
				if errors.Is(err, context.Canceled) {
					return
				}
				log.Printf("telemetry %s ship failed: %v", priority, err)
				wait := telemetryShipBackoff
				if retryAfter > wait {
					wait = retryAfter
				}
				if !sleepContext(ctx, wait) {
					return
				}
				break
			}
			progress = progress || shipped
		}
		if progress {
			continue
		}
		if !sleepContext(ctx, telemetryShipIdle) {
			return
		}
	}
}

func (r *runner) shipTelemetryPriority(ctx context.Context, durable *spool.Spool, api telemetryTransport, cred fleetclient.Credential, signer fleetclient.TelemetrySigner, priority fleetagent.DeliveryPriority) (bool, time.Duration, error) {
	records, err := durable.PeekPriority(ctx, priority, ports.PeekSpoolRequest{MaxRecords: telemetryShipMaxRecords, MaxBytes: telemetryShipMaxBytes})
	if err != nil {
		return false, 0, err
	}
	if len(records) == 0 {
		return false, 0, nil
	}
	// A3 owns raw telemetry only. P2/P3 are the raw telemetry lanes, but fail
	// closed if a future producer places another record kind there rather than
	// accidentally signing it under the telemetry purpose.
	if records[0].Kind != ports.SpoolRecordTelemetry {
		return false, 0, fmt.Errorf("unexpected %s record in raw telemetry lane %s", records[0].Kind, priority)
	}
	batchRecords := contiguousTelemetryPrefix(records)
	batch, err := buildSignedTelemetryBatch(cred, signer, batchRecords)
	if err != nil {
		return false, 0, err
	}
	resp, err := api.ShipTelemetry(ctx, cred.Token, batch)
	if err != nil {
		var status *fleetclient.HTTPStatusError
		if errors.As(err, &status) {
			if status.Retryable() {
				return false, status.RetryAfter, err
			}
			// 4xx is a permanent contract/security failure for these exact bytes.
			// Never ACK/drop them locally; operator intervention is required.
			return false, 0, fmt.Errorf("non-retryable telemetry rejection: %w", err)
		}
		return false, 0, err
	}
	ackPriority, ackEpoch, through := resp.Ack()
	last := batchRecords[len(batchRecords)-1].Position
	if ackPriority != priority || ackEpoch != last.Epoch {
		return false, 0, fmt.Errorf("server ACK coordinates do not match sent lane: got %s/%d want %s/%d", ackPriority, ackEpoch, priority, last.Epoch)
	}
	if through == 0 || through > last.Sequence {
		return false, 0, fmt.Errorf("server ACK through=%d is outside sent durable range ending at %d", through, last.Sequence)
	}
	if _, err := durable.Ack(ctx, ports.SpoolACK{Priority: ackPriority, Epoch: ackEpoch, Through: through}); err != nil {
		return false, 0, fmt.Errorf("apply telemetry ACK: %w", err)
	}
	return true, 0, nil
}

func contiguousTelemetryPrefix(records []ports.SpoolRecord) []ports.SpoolRecord {
	if len(records) == 0 {
		return nil
	}
	first := records[0]
	out := records[:1]
	for i := 1; i < len(records); i++ {
		previous := out[len(out)-1]
		current := records[i]
		if current.Kind != ports.SpoolRecordTelemetry ||
			current.SchemaVersion != first.SchemaVersion ||
			current.Position.Priority != first.Position.Priority ||
			current.Position.Epoch != first.Position.Epoch ||
			current.Position.Session != first.Position.Session ||
			current.Position.Sequence != previous.Position.Sequence+1 {
			break
		}
		out = append(out, current)
	}
	return out
}

func buildSignedTelemetryBatch(cred fleetclient.Credential, signer fleetclient.TelemetrySigner, records []ports.SpoolRecord) (fleetagent.SignedTelemetryBatch, error) {
	if len(records) == 0 {
		return fleetagent.SignedTelemetryBatch{}, fmt.Errorf("telemetry batch requires records")
	}
	agentID := shared.ID(cred.AgentID)
	assetID := shared.ID(cred.AssetID)
	if agentID.IsZero() || assetID.IsZero() {
		return fleetagent.SignedTelemetryBatch{}, fmt.Errorf("telemetry batch requires canonical agent and asset identity")
	}
	first := records[0]
	last := records[len(records)-1]
	session := fleetagent.CanonicalSessionID(agentID)
	streamID, err := fleetagent.TelemetryDeliveryStreamID(agentID, session, first.Position.Priority)
	if err != nil {
		return fleetagent.SignedTelemetryBatch{}, err
	}
	payload := make([]byte, 0, totalPayloadBytes(records)+len(records)+1)
	payload = append(payload, '[')
	eventIDs := make([]shared.ID, 0, len(records))
	digests := make([]string, 0, len(records))
	minAt, maxAt := first.ObservedAt.UTC(), first.ObservedAt.UTC()
	for i, record := range records {
		if err := record.Validate(); err != nil {
			return fleetagent.SignedTelemetryBatch{}, err
		}
		if record.SchemaVersion != first.SchemaVersion || record.Position.Epoch != first.Position.Epoch || record.Position.Priority != first.Position.Priority {
			return fleetagent.SignedTelemetryBatch{}, fmt.Errorf("telemetry batch records cross schema/lane/incarnation boundary")
		}
		if i > 0 {
			payload = append(payload, ',')
		}
		payload = append(payload, record.Payload...)
		eventIDs = append(eventIDs, record.EventID)
		digests = append(digests, fleetagent.SHA256Hex(record.Payload))
		at := record.ObservedAt.UTC()
		if at.Before(minAt) {
			minAt = at
		}
		if at.After(maxAt) {
			maxAt = at
		}
	}
	payload = append(payload, ']')
	// No sampling is applied by the A1→A2 adapter today. Commit the complete
	// required policy tuple rather than an ad-hoc label so a future sampler cannot
	// silently reuse this digest with different semantics.
	policyDigest := fleetagent.SHA256Hex([]byte(`{"SamplingAlgorithm":"none","SamplingPolicyID":"none","Seed":"","Version":1}`))
	manifest := fleetagent.TelemetryBatchManifest{
		ProtocolVersion: 1, SchemaVersion: first.SchemaVersion,
		AgentID: agentID, HostID: agentID, AgentSessionID: session, AssetID: assetID,
		StreamID: streamID, Priority: first.Position.Priority, Epoch: first.Position.Epoch,
		Sequence: last.Position.Sequence, PreviousSequence: first.Position.Sequence - 1,
		EventTimeMin: minAt, EventTimeMax: maxAt,
		ObservedCount: uint64(len(records)), KeptCount: uint64(len(records)),
		SamplingPolicyDigest: policyDigest, EventIDs: eventIDs, EventDigests: digests,
	}
	return fleetagent.SignTelemetryBatch(manifest, payload, signer.Key.KeyID, signer.PrivateKey)
}

func totalPayloadBytes(records []ports.SpoolRecord) int {
	total := 0
	for _, record := range records {
		total += len(record.Payload)
	}
	return total
}

func sleepContext(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

var _ = bytes.Equal // retained as a compile-time import guard for byte-exact commitment work.
