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

type telemetryGapTransport interface {
	ShipTelemetryGap(context.Context, string, fleetagent.SignedTelemetryGap) (fleetclient.TelemetryGapShipResponse, error)
}

func (r *runner) startTelemetryGapShipper(ctx context.Context, durable *spool.Spool, cred fleetclient.Credential) {
	base, ok := r.api.(telemetryTransport)
	if !ok {
		return
	}
	gapAPI, ok := r.api.(telemetryGapTransport)
	if !ok {
		return
	}
	if cred.AgentID == "" || cred.AssetID == "" {
		return
	}
	go r.telemetryGapShipLoop(ctx, durable, base, gapAPI, cred)
}

func (r *runner) telemetryGapShipLoop(ctx context.Context, durable *spool.Spool, base telemetryTransport, gapAPI telemetryGapTransport, cred fleetclient.Credential) {
	var signer fleetclient.TelemetrySigner
	for {
		registered, err := r.ensureTelemetrySignerRegistered(ctx, base, cred, signer)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return
			}
			retry, wait := telemetryRegistrationRetry(err)
			if !retry {
				log.Printf("telemetry gap signing-key registration rejected; gap transport disabled: %v", err)
				return
			}
			log.Printf("telemetry gap signing-key registration failed (will retry): %v", err)
			if !sleepContext(ctx, wait) {
				return
			}
			continue
		}
		signer = registered

		shipped, retryAfter, err := r.shipNextTelemetryGap(ctx, durable, gapAPI, cred, signer)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return
			}
			retry, wait := telemetryDeliveryRetry(err, retryAfter)
			if !retry {
				log.Printf("telemetry gap rejected by control plane; local gap retained and gap transport disabled: %v", err)
				return
			}
			log.Printf("telemetry gap ship failed (will retry): %v", err)
			if !sleepContext(ctx, wait) {
				return
			}
			continue
		}
		if shipped {
			continue
		}
		if !sleepContext(ctx, telemetryShipIdle) {
			return
		}
	}
}

func (r *runner) shipNextTelemetryGap(ctx context.Context, durable *spool.Spool, api telemetryGapTransport, cred fleetclient.Credential, signer fleetclient.TelemetrySigner) (bool, time.Duration, error) {
	gaps, err := durable.Gaps(ctx)
	if err != nil {
		return false, 0, err
	}
	if len(gaps) == 0 {
		return false, 0, nil
	}
	gap := gaps[0]
	signed, err := buildSignedTelemetryGap(cred, signer, gap)
	if err != nil {
		return false, 0, err
	}
	resp, err := api.ShipTelemetryGap(ctx, cred.Token, signed)
	if err != nil {
		var status *fleetclient.HTTPStatusError
		if errors.As(err, &status) && status.Retryable() {
			return false, status.RetryAfter, err
		}
		return false, 0, err
	}
	if resp.GapID.IsZero() || resp.GapID != gap.ID {
		return false, 0, fmt.Errorf("server telemetry gap ACK id %q does not match sent gap %q", resp.GapID, gap.ID)
	}
	if err := durable.AckGap(ctx, gap.ID); err != nil {
		return false, 0, fmt.Errorf("apply telemetry gap ACK: %w", err)
	}
	return true, 0, nil
}

func buildSignedTelemetryGap(cred fleetclient.Credential, signer fleetclient.TelemetrySigner, gap ports.SpoolGap) (fleetagent.SignedTelemetryGap, error) {
	if err := gap.Validate(); err != nil {
		return fleetagent.SignedTelemetryGap{}, err
	}
	agentID := shared.ID(cred.AgentID)
	assetID := shared.ID(cred.AssetID)
	if agentID.IsZero() || assetID.IsZero() {
		return fleetagent.SignedTelemetryGap{}, fmt.Errorf("telemetry gap requires canonical agent and asset identity")
	}
	session := fleetagent.CanonicalSessionID(agentID)
	streamID, err := fleetagent.TelemetryDeliveryStreamID(agentID, session, gap.Priority)
	if err != nil {
		return fleetagent.SignedTelemetryGap{}, err
	}
	manifest := fleetagent.TelemetryGapManifest{
		ProtocolVersion: 1,
		GapID: gap.ID, AgentID: agentID, HostID: agentID, AgentSessionID: session, AssetID: assetID,
		StreamID: streamID, Priority: gap.Priority, Epoch: gap.Epoch,
		KnownSequence: gap.KnownSequence, FromSequence: gap.FromSequence, ToSequence: gap.ToSequence,
		Reason: string(gap.Reason), Count: gap.Count, OccurredAt: gap.OccurredAt.UTC(),
	}
	return fleetagent.SignTelemetryGap(manifest, signer.Key.KeyID, signer.PrivateKey)
}
