package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/adapter/agentspool"
	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/ebpf"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/fleetclient"
	detectuc "github.com/KKloudTarus/synapse-ce/internal/usecase/fleet/detect"
)

func detectionIdentity(cred fleetclient.Credential) (host, agent shared.ID, ok bool) {
	id := shared.ID(strings.TrimSpace(cred.AgentID))
	if id == "" {
		return "", "", false
	}
	return id, id, true
}

func (r *runner) startDetection(ctx context.Context, cred fleetclient.Credential) {
	classes, err := parseDetectClasses(r.cfg.detectClasses)
	if err != nil {
		log.Printf("detection: %v; detection engine disabled", err)
		return
	}
	if len(classes) == 0 {
		return
	}

	host, agent, ok := detectionIdentity(cred)
	if !ok {
		log.Print("detection: enrolled credential has no canonical agent id; detection engine disabled")
		return
	}
	durable, identity, err := r.openTelemetrySpool(ctx, cred)
	if err != nil {
		log.Printf("detection: open durable telemetry spool: %v; detection engine disabled", err)
		return
	}
	rawSensor := ebpf.NewSensor(host, agent, classes)
	sensor, err := agentspool.NewDurableSensor(rawSensor, durable, identity)
	if err != nil {
		log.Printf("detection: wire durable telemetry sensor: %v; detection engine disabled", err)
		_ = durable.Close()
		return
	}
	sink, err := agentspool.NewDetectionSink(durable)
	if err != nil {
		log.Printf("detection: wire durable detection sink: %v; detection engine disabled", err)
		_ = durable.Close()
		return
	}
	eng, err := detectuc.NewEngine(sensor, sink, host, agent, detectuc.Options{Classes: classes, CPUCeilingPct: r.cfg.detectCeiling})
	if err != nil {
		log.Printf("detection: %v; detection engine disabled", err)
		_ = durable.Close()
		return
	}
	runCtx, cancelRun := context.WithCancel(ctx)
	// The shipper and sensor own exactly the same WAL lifecycle. If the engine
	// stops, runCtx is cancelled before the shared spool is closed, so no shipper
	// goroutine can spin forever against a closed WAL.
	r.startTelemetryShipper(runCtx, durable, cred)
	if err := r.startSpoolMetrics(runCtx, durable); err != nil {
		log.Printf("detection: agent metrics listener unavailable: %v", err)
	}

	log.Printf("detection engine starting: classes=%s ceiling=%.0f%% durable_spool=%s", r.cfg.detectClasses, r.cfg.detectCeiling, r.telemetrySpoolDir())
	coverageDone := make(chan struct{})
	go func() {
		defer close(coverageDone)
		timer := time.NewTimer(3 * time.Second)
		defer timer.Stop()
		select {
		case <-runCtx.Done():
		case <-timer.C:
			coverage := eng.Coverage()
			log.Printf("detection coverage: %s", formatCoverage(coverage))
			if err := agentspool.RecordCoverage(runCtx, durable, coverage, time.Now().UTC()); err != nil && !errors.Is(err, context.Canceled) {
				log.Printf("detection: persist coverage/sensor state: %v", err)
			}
		}
	}()
	go func() {
		err := eng.Run(runCtx)
		if err != nil && !errors.Is(err, context.Canceled) {
			log.Printf("detection engine stopped: %v", err)
		}
		cancelRun()
		<-coverageDone
		if closeErr := durable.Close(); closeErr != nil {
			log.Printf("detection: close durable spool: %v", closeErr)
		}
	}()
}

func parseDetectClasses(s string) ([]detection.Class, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	var out []detection.Class
	for _, part := range strings.Split(s, ",") {
		p := strings.TrimSpace(part)
		if p == "" {
			continue
		}
		c := detection.Class(p)
		if !c.Valid() {
			return nil, fmt.Errorf("unknown detection class %q (want any of process,network,file,privilege)", p)
		}
		out = append(out, c)
	}
	return out, nil
}

func parseCeiling(s string) float64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil || v < 0 {
		log.Print("detection: ignoring invalid SYNAPSE_DETECT_CPU_CEIL_PCT (want a non-negative number)")
		return 0
	}
	return v
}

func formatCoverage(cov []detection.ClassCoverage) string {
	parts := make([]string, 0, len(cov))
	for _, c := range cov {
		state := string(c.State)
		if c.IsObservationGap() && c.Reason != "" {
			state = fmt.Sprintf("%s(%s)", c.State, c.Reason)
		}
		parts = append(parts, fmt.Sprintf("%s=%s", c.Class, state))
	}
	sort.Strings(parts)
	return strings.Join(parts, " ")
}
