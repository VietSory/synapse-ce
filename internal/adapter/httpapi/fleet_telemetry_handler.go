package httpapi

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/fleet/telemetryingest"
)

const (
	fleetTelemetryWireCap    = 8 << 20
	fleetTelemetryDecodedCap = 32 << 20
)

// fleetTelemetryIngest is the narrow agent-plane telemetry ingest surface the handler consumes.
type fleetTelemetryIngest interface {
	Ingest(ctx context.Context, authAgentID shared.ID, req telemetryingest.IngestRequest) (telemetryingest.IngestResult, error)
	IngestGap(ctx context.Context, authAgentID shared.ID, report fleetagent.TelemetryGapReport) (telemetryingest.GapIngestResult, error)
}

// ingestTelemetry is the agent-plane endpoint (POST /api/v1/fleet/telemetry). The HTTP layer accepts
// raw or gzip JSON, bounds both compressed and decoded sizes, and rejects trailing/unknown fields before
// the use case reaches the identity/signature/schema trust boundary.
func (f *fleetRouter) ingestTelemetry(w http.ResponseWriter, r *http.Request) {
	if f.telemetry == nil {
		writeJSON(w, http.StatusNotFound, errorBody{Error: "telemetry ingest not enabled"})
		return
	}
	agent, ok := agentFrom(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, errorBody{Error: "unauthenticated"})
		return
	}
	body, err := readFleetTelemetryBody(w, r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid telemetry batch body"})
		return
	}
	var req telemetryingest.IngestRequest
	if err := decodeStrictFleetTelemetry(body, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid telemetry batch body"})
		return
	}
	res, err := f.telemetry.Ingest(r.Context(), agent.ID, req)
	if err != nil {
		writeError(w, f.log, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"accepted":   res.Accepted,
		"duplicate":  res.Duplicate,
		"ack":        res.ACK,
		"provenance": res.Provenance,
		"gap_open":   res.GapOpen,
	})
}

// ingestTelemetryGap is the durable-loss companion endpoint. A successful response
// acknowledges the exact stable GapID only after the signed report has passed the
// server-authoritative trust boundary and been durably persisted.
func (f *fleetRouter) ingestTelemetryGap(w http.ResponseWriter, r *http.Request) {
	if f.telemetry == nil {
		writeJSON(w, http.StatusNotFound, errorBody{Error: "telemetry ingest not enabled"})
		return
	}
	agent, ok := agentFrom(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, errorBody{Error: "unauthenticated"})
		return
	}
	body, err := readFleetTelemetryBody(w, r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid telemetry gap body"})
		return
	}
	var report fleetagent.TelemetryGapReport
	if err := decodeStrictFleetTelemetry(body, &report); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid telemetry gap body"})
		return
	}
	res, err := f.telemetry.IngestGap(r.Context(), agent.ID, report)
	if err != nil {
		writeError(w, f.log, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"acknowledged": true,
		"gap_id":       res.GapID,
	})
}

func readFleetTelemetryBody(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	raw := http.MaxBytesReader(w, r.Body, fleetTelemetryWireCap)
	var reader io.Reader = raw
	var closeGzip func() error
	switch enc := strings.TrimSpace(strings.ToLower(r.Header.Get("Content-Encoding"))); enc {
	case "":
	case "gzip":
		zr, err := gzip.NewReader(raw)
		if err != nil {
			return nil, err
		}
		reader = zr
		closeGzip = zr.Close
	default:
		return nil, fmt.Errorf("unsupported content encoding %q", enc)
	}
	if closeGzip != nil {
		defer func() { _ = closeGzip() }()
	}
	payload, err := io.ReadAll(io.LimitReader(reader, fleetTelemetryDecodedCap+1))
	if err != nil {
		return nil, err
	}
	if len(payload) == 0 {
		return nil, errors.New("empty telemetry request")
	}
	if len(payload) > fleetTelemetryDecodedCap {
		return nil, errors.New("telemetry request exceeds decoded limit")
	}
	return payload, nil
}

func decodeStrictFleetTelemetry(body []byte, out any) error {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}
