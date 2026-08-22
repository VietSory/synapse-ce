package main

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/adapter/httpapi"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/postgres"
	telemetryuc "github.com/KKloudTarus/synapse-ce/internal/usecase/fleet/telemetry"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	telemetryHotRetention   = 7 * 24 * time.Hour
	telemetryWarmRetention  = 30 * 24 * time.Hour
	fleetTelemetryMaxEvents = 4096
)

type telemetryRuntimeStore interface {
	ports.TelemetryStore
	ports.TelemetryDeliveryStore
	ports.TelemetryGapReader
	ports.TelemetryAssetBindingStore
}

// wireFleetTelemetry composes the live A3 transport onto the already-enabled
// agent plane. Postgres deployments use RLS-scoped telemetry repositories for
// rows, ACK/gaps, authoritative bindings, and agent-origin spool loss; memory mode
// uses contract-equivalent stores. No endpoint is enabled with a partial dependency set.
func wireFleetTelemetry(router *httpapi.Router, pool *pgxpool.Pool, audit ports.AuditLogger, clock ports.Clock, log *slog.Logger) error {
	if router == nil || audit == nil || clock == nil {
		return fmt.Errorf("telemetry runtime requires router, audit and clock")
	}
	var (
		store     telemetryRuntimeStore
		keys      ports.AgentSigningKeyStore
		agentGaps ports.TelemetryAgentGapStore
	)
	if pool != nil {
		store = postgres.NewTelemetryRepository(pool, telemetryHotRetention, telemetryWarmRetention)
		keys = postgres.NewAgentSigningKeyRepository(pool)
		agentGaps = postgres.NewTelemetryAgentGapRepository(pool)
	} else {
		store = memory.NewTelemetryStore(telemetryHotRetention, telemetryWarmRetention)
		keys = memory.NewAgentSigningKeyStore()
		agentGaps = memory.NewTelemetryAgentGapStore()
	}
	base, err := telemetryuc.NewTransportService(store, keys, store, audit, clock, fleetTelemetryMaxEvents)
	if err != nil {
		return fmt.Errorf("construct telemetry transport: %w", err)
	}
	transport, err := telemetryuc.NewGapTransportService(base, agentGaps)
	if err != nil {
		return fmt.Errorf("construct telemetry gap transport: %w", err)
	}
	router.SetFleetTelemetry(transport, keys, store)
	if log != nil {
		backend := "memory"
		if pool != nil {
			backend = "postgres"
		}
		log.Info("fleet telemetry transport ENABLED", "backend", backend, "max_events_per_batch", fleetTelemetryMaxEvents)
	}
	return nil
}
