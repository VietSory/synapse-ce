package main

import (
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
	// Registration is deliberately part of the background loop: a transient 429/5xx
	// or network failure must not disable telemetry until the whole agent restarts.
	go r.telemetryShipLoop(ctx, durable, api, cred)
}

func (r *runner) telemetryShipLoop(ctx context.Context, durable *spool.Spool, api telemetryTransport, cred fleetclient.Credential) {
	var signer fleetclient.TelemetrySigner
	for {
		registered, err := r.ensureTelemetrySignerRegistered(ctx, api, cred, signer)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return
			}
			retry, wait := telemetryRegistrationRetry(err)
			if !retry {
				log.Printf("telemetry signing-key registration rejected; transport disabled: %v", err)
				return
			}
			log.Printf("telemetry signing-key registration failed (will retry): %v", err)
			if !sleepContext(ctx, wait) {
				return
			}
			continue
		}
		signer = registered

		progress := false
		for _, priority := range []fleetagent.DeliveryPriority{fleetagent.PriorityP2, fleetagent.PriorityP3} {
			shipped, retryAfter, err := r.shipTelemetryPriority(ctx, durable, api, cred, signer, priority)
			if err != nil {
				if errors.Is(err, context.Canceled) {
					return
				}
				retry, wait := telemetryDeliveryRetry(err, retryAfter)
				if !retry {
					log.Printf("telemetry %s rejected by control plane; transport disabled with WAL retained: %v", priority, err)
					return
				}
				log.Printf("telemetry %s ship failed (will retry): %v", priority, err)
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

func (r *runner) ensureTelemetrySignerRegistered(ctx context.Context, api telemetryTransport, cred fleetclient.Credential, current fleetclient.TelemetrySigner) (fleetclient.TelemetrySigner, error) {
	now := time.Now().UTC()
	if !current.NeedsRotation(now) {
		return current, nil
	}
	signer, err := r.store.EnsureTelemetrySigner(cred.AgentID, now)
	if err != nil {
		return fleetclient.TelemetrySigner{}, err
	}
	proof := fleetagent.ProveKeyPossession(signer.PrivateKey, signer.Key)
	if err := api.RegisterTelemetrySigningKey(ctx, cred.Token, signer.Key, proof); err != nil {
		return fleetclient.TelemetrySigner{}, err
	}
	return signer, nil
}

func telemetryRegistrationRetry(err error) (bool, time.Duration) {
	if err == nil || errors.Is(err, context.Canceled) {
		return false, 0
	}
	var status *fleetclient.HTTPStatusError
	if errors.As(err, &status) {
		if !status.Retryable() {
			return false, 0
		}
		wait := telemetryShipBackoff
		if status.RetryAfter > wait {
			wait = status.RetryAfter
		}
		return true, wait
	}
	// Network/transport errors do not carry an HTTP status. They are transient by
	// default and use the bounded local backoff rather than permanently disabling A3.
	return true, telemetryShipBackoff
}

func telemetryDeliveryRetry(err error, retryAfter time.Duration) (bool, time.Duration) {
	if err == nil || errors.Is(err, context.Canceled) {
		return false, 0
	}
	var status *fleetclient.HTTPStatusError
	if errors.As(err, &status) && !status.Retryable() {
		return false, 0
	}
	wait := telemetryShipBackoff
	if retryAfter > wait {
		wait = retryAfter
	}
	return true, wait
}

func (r *runner) shipTelemetryPriority(ctx context.Context, durable *spool.Spool, api telemetryTransport, cred fleetclient.Credential, signer fleetclient.TelemetrySigner, priority fleetagent.DeliveryPriority) (bool, time.Duration, error) {
	records, err := durable.PeekPriority(ctx, priority, ports.PeekSpoolRequest{MaxRecords: telemetryShipMaxRecords, MaxBytes: telemetryShipMaxBytes})
	if err != nil {
		return false, 0, err
	}
	if len(records) == 0 {
		return false, 0, nil
	}
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
	policyDigest, err := fleetagent.SamplingPolicyDigest("none", "none", "", 1)
	if err != nil {
		return fleetagent.SignedTelemetryBatch{}, err
	}
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
