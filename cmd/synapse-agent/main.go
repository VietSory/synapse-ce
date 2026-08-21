// Command synapse-agent is the fleet VM agent (#410, epic #405). It enrols with the control plane's
// fleet API, then repeatedly heartbeats, claims host-inventory work orders, collects the host's
// facts and installed OS packages (reusing the engine's owned package cataloger), and reports the
// outcome. The private key is generated locally and never leaves the host; only a CSR is sent.
//
// Scope for this issue: host facts + OS package inventory + the fleet transport loop. Listener/
// service enumeration, local-config evaluation, source-tree scanning, and cgroup resource limits are
// deferred follow-ups, and Windows hosts are out of scope (documented in the collector).
//
// It is a composition root only: no business logic lives here beyond wiring and the run loop, and the
// loop is exercised by main_test.go against a fake API.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetversion"
	"github.com/KKloudTarus/synapse-ce/internal/domain/hostinventory"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/fleetclient"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/hostinv"
	"github.com/KKloudTarus/synapse-ce/internal/platform/buildinfo"
)

var agentVersion = buildinfo.App()

const hostInventoryCapability = "scan.host"
const minControlPlaneVersion = "0.1.0"

type fleetAPI interface {
	Enrol(ctx context.Context, enrolToken string, req fleetclient.EnrolRequest) (fleetclient.EnrolResponse, error)
	Heartbeat(ctx context.Context, token string, req fleetclient.EnrolRequest) (fleetclient.HeartbeatResponse, error)
	ClaimWork(ctx context.Context, token string, max int) ([]fleetclient.Order, error)
	Progress(ctx context.Context, token, orderID string) error
	SubmitResult(ctx context.Context, token, orderID, status, reason string) error
	SendHostInventory(ctx context.Context, token string, inv any) error
}

// hostInventoryResolvedAPI is optional so old test doubles remain source-compatible.
// The real fleet client implements it and returns the canonical server asset binding.
type hostInventoryResolvedAPI interface {
	SendHostInventoryResolved(ctx context.Context, token string, inv any) (fleetclient.HostInventoryResponse, error)
}

type config struct {
	baseURL       string
	enrolToken    string
	stateDir      string
	root          string
	name          string
	poll          time.Duration
	maxOrders     int
	once          bool
	detectClasses string
	detectCeiling float64
	spoolBytes    int64
	metricsAddr   string
}

func main() {
	log.SetFlags(0)
	if err := checkOSFloor(); err != nil {
		log.Fatalf("synapse-agent: %v", err)
	}
	cfg := parseConfig()
	if cfg.baseURL == "" {
		log.Fatal("synapse-agent: SYNAPSE_FLEET_URL (or -url) is required")
	}
	if err := fleetclient.ValidateControlPlaneURL(cfg.baseURL); err != nil {
		log.Fatalf("synapse-agent: %v", err)
	}
	r := &runner{
		api:     fleetclient.New(cfg.baseURL, 30*time.Second),
		collect: hostinv.Collect,
		cfg:     cfg,
		store:   fleetclient.NewCredentialStore(cfg.stateDir),
	}
	if runAsService(r.run) {
		return
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := r.run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		log.Fatalf("synapse-agent: %v", err)
	}
}

func parseConfig() config {
	var cfg config
	var enrolTokenFile string
	flag.StringVar(&cfg.baseURL, "url", os.Getenv("SYNAPSE_FLEET_URL"), "control plane fleet API base URL (https required, except a loopback host)")
	flag.StringVar(&cfg.enrolToken, "enrol-token", os.Getenv("SYNAPSE_FLEET_ENROL_TOKEN"), "one-time enrolment token, first run only (DISCOURAGED: visible in ps; prefer -enrol-token-file)")
	flag.StringVar(&enrolTokenFile, "enrol-token-file", os.Getenv("SYNAPSE_FLEET_ENROL_TOKEN_FILE"), "file to read the one-time enrolment token from (preferred over -enrol-token)")
	flag.StringVar(&cfg.stateDir, "state-dir", envOr("SYNAPSE_AGENT_STATE_DIR", defaultStateDir()), "directory for the agent credential + offline buffer")
	flag.StringVar(&cfg.root, "root", envOr("SYNAPSE_AGENT_ROOT", "/"), "host filesystem root to inventory")
	flag.StringVar(&cfg.name, "name", envOr("SYNAPSE_AGENT_NAME", hostname()), "agent display name")
	flag.DurationVar(&cfg.poll, "poll", 60*time.Second, "poll interval between claim cycles")
	flag.IntVar(&cfg.maxOrders, "max-orders", 8, "max work orders to claim per cycle")
	flag.BoolVar(&cfg.once, "once", false, "run a single cycle then exit")
	flag.StringVar(&cfg.detectClasses, "detect-classes", os.Getenv("SYNAPSE_DETECT_CLASSES"), "comma-separated eBPF detection classes to run (process,network,file,privilege); empty = detection engine off (#422, Linux+root only)")
	flag.Float64Var(&cfg.detectCeiling, "detect-ceiling", parseCeiling(os.Getenv("SYNAPSE_DETECT_CPU_CEIL_PCT")), "CPU ceiling percent for the detection engine; over it, classes are shed in a defined order (0 = no shedding)")
	flag.Int64Var(&cfg.spoolBytes, "telemetry-spool-bytes", parsePositiveBytes(os.Getenv("SYNAPSE_TELEMETRY_SPOOL_BYTES"), 512<<20), "maximum bytes retained by the priority telemetry WAL")
	flag.StringVar(&cfg.metricsAddr, "agent-metrics-addr", os.Getenv("SYNAPSE_AGENT_METRICS_ADDR"), "optional address for private agent Prometheus metrics (for example 127.0.0.1:9465)")
	flag.Parse()
	if cfg.enrolToken == "" {
		tok, err := fleetclient.ReadEnrolTokenFile(enrolTokenFile)
		if err != nil {
			log.Fatalf("synapse-agent: %v", err)
		}
		cfg.enrolToken = tok
	}
	return cfg
}

type runner struct {
	api     fleetAPI
	collect func(ctx context.Context, root string) (hostinventory.HostInventory, error)
	cfg     config
	store   *fleetclient.CredentialStore
}

func (r *runner) run(ctx context.Context) error {
	cred, err := r.ensureEnrolled(ctx)
	if err != nil {
		return err
	}
	detectionStarted := false
	for {
		// A0.1: never manufacture an asset identity locally. The first successful
		// host reconciliation establishes and persists it; only then may telemetry
		// observation/signing start.
		if !detectionStarted && cred.AssetID != "" {
			r.startDetection(ctx, cred)
			detectionStarted = true
		}
		if err := r.cycle(ctx, cred); err != nil {
			if errors.Is(err, context.Canceled) {
				return err
			}
			log.Printf("cycle error (will retry): %v", err)
		}
		if current, ok := r.store.Load(); ok && current.AgentID == cred.AgentID {
			cred = current
		}
		if !detectionStarted && cred.AssetID != "" {
			r.startDetection(ctx, cred)
			detectionStarted = true
		}
		if r.cfg.once {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(r.cfg.poll):
		}
	}
}

func (r *runner) ensureEnrolled(ctx context.Context) (fleetclient.Credential, error) {
	return fleetclient.EnsureEnrolled(ctx, r.api, r.store, r.cfg.enrolToken, fleetclient.EnrolRequest{
		Name:         r.cfg.name,
		Platform:     runtime.GOOS,
		AgentVersion: agentVersion,
		Capabilities: []string{hostInventoryCapability},
	})
}

func (r *runner) cycle(ctx context.Context, cred fleetclient.Credential) error {
	hb, err := r.api.Heartbeat(ctx, cred.Token, fleetclient.EnrolRequest{
		Name: r.cfg.name, Platform: runtime.GOOS, AgentVersion: agentVersion,
	})
	if err != nil {
		return fmt.Errorf("heartbeat: %w", err)
	}
	if !fleetversion.MeetsFloor(agentVersion, hb.MinSupportedAgentVersion) {
		log.Printf("version skew: agent %s is below the control plane minimum %s — update this agent", agentVersion, hb.MinSupportedAgentVersion)
	}
	if cp, ok := fleetversion.Parse(hb.ControlPlaneVersion); ok {
		if floor, fok := fleetversion.Parse(minControlPlaneVersion); fok && cp.Less(floor) {
			log.Printf("version skew: control plane %s is older than this agent requires (%s) — skipping claim this cycle", hb.ControlPlaneVersion, minControlPlaneVersion)
			return nil
		}
	}
	orders, err := r.api.ClaimWork(ctx, cred.Token, r.cfg.maxOrders)
	if err != nil {
		return fmt.Errorf("claim: %w", err)
	}
	for _, o := range orders {
		if err := ctx.Err(); err != nil {
			return err
		}
		r.handle(ctx, cred, o)
	}
	return nil
}

func (r *runner) handle(ctx context.Context, cred fleetclient.Credential, o fleetclient.Order) {
	if o.Capability != "" && o.Capability != hostInventoryCapability {
		_ = r.api.SubmitResult(ctx, cred.Token, o.ID, "failed", "unsupported capability: "+o.Capability)
		return
	}
	if err := r.api.Progress(ctx, cred.Token, o.ID); err != nil {
		log.Printf("order %s: progress: %v", o.ID, err)
	}
	inv, err := r.collect(ctx, r.cfg.root)
	if err != nil {
		_ = r.api.SubmitResult(ctx, cred.Token, o.ID, "failed", "collect: "+err.Error())
		return
	}
	if err := r.buffer(o.ID, inv); err != nil {
		log.Printf("order %s: buffer: %v", o.ID, err)
		_ = r.api.SubmitResult(ctx, cred.Token, o.ID, "failed", "buffer inventory: "+err.Error())
		return
	}
	if resolved, ok := r.api.(hostInventoryResolvedAPI); ok {
		resp, reportErr := resolved.SendHostInventoryResolved(ctx, cred.Token, inv)
		if reportErr != nil {
			log.Printf("order %s: report inventory: %v", o.ID, reportErr)
			_ = r.api.SubmitResult(ctx, cred.Token, o.ID, "failed", "report inventory: "+reportErr.Error())
			return
		}
		if resp.AssetID == "" {
			_ = r.api.SubmitResult(ctx, cred.Token, o.ID, "failed", "report inventory: control plane returned no canonical asset id")
			return
		}
		cred.AssetID = resp.AssetID
		if err := r.store.Persist(cred, nil); err != nil {
			log.Printf("order %s: persist canonical asset binding: %v", o.ID, err)
			_ = r.api.SubmitResult(ctx, cred.Token, o.ID, "failed", "persist canonical asset binding: "+err.Error())
			return
		}
	} else if err := r.api.SendHostInventory(ctx, cred.Token, inv); err != nil {
		log.Printf("order %s: report inventory: %v", o.ID, err)
		_ = r.api.SubmitResult(ctx, cred.Token, o.ID, "failed", "report inventory: "+err.Error())
		return
	}
	status := "succeeded"
	if inv.Degraded() {
		status = "failed"
	}
	if err := r.api.SubmitResult(ctx, cred.Token, o.ID, status, summary(inv)); err != nil {
		log.Printf("order %s: submit result: %v", o.ID, err)
	}
}

func summary(inv hostinventory.HostInventory) string {
	s := fmt.Sprintf("%d packages, os=%s/%s", len(inv.Packages), inv.Facts.OS, inv.Facts.OSVersion)
	if inv.Degraded() {
		s += " (DEGRADED: a package database could not be read)"
	}
	if !inv.Complete {
		s += fmt.Sprintf(" (INCOMPLETE: %d coverage issue(s))", len(inv.Coverage))
	}
	return s
}

func (r *runner) buffer(orderID string, inv hostinventory.HostInventory) error {
	if err := os.MkdirAll(r.cfg.stateDir, 0o700); err != nil {
		return fmt.Errorf("state dir: %w", err)
	}
	b, err := json.MarshalIndent(inv, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal inventory: %w", err)
	}
	if err := fleetclient.WriteSecret(filepath.Join(r.cfg.stateDir, "inventory-"+safe(orderID)+".json"), b, 0o600); err != nil {
		return fmt.Errorf("write inventory: %w", err)
	}
	return nil
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func parsePositiveBytes(value string, def int64) int64 {
	if value == "" {
		return def
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil || parsed <= 0 {
		log.Printf("ignoring invalid telemetry spool byte count (want a positive integer)")
		return def
	}
	return parsed
}

func defaultStateDir() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(os.Getenv("ProgramData"), "synapse-agent")
	}
	return "/var/lib/synapse-agent"
}

func hostname() string {
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return "synapse-agent"
}

func safe(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		if r == '/' || r == '\\' || r == '.' {
			out = append(out, '_')
			continue
		}
		out = append(out, r)
	}
	if len(out) == 0 {
		return "order"
	}
	return string(out)
}
