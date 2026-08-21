package httpapi

import (
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	fleetTelemetryWireCap    = 8 << 20
	fleetTelemetryDecodedCap = 32 << 20
)

type fleetTelemetryTransport interface {
	IngestSigned(context.Context, *fleetagent.Agent, fleetagent.SignedTelemetryBatch) (ports.TelemetryDeliveryResult, error)
}

// SetFleetTelemetry wires A3 onto the already-authenticated agent plane. All three
// dependencies are required together: transport verification without the durable key
// registry or authoritative asset binding would silently weaken the admission contract.
func (rt *Router) SetFleetTelemetry(transport fleetTelemetryTransport, keys ports.AgentSigningKeyStore, bindings ports.TelemetryAssetBindingStore) {
	if rt.fleet == nil {
		return
	}
	rt.fleet.telemetry = transport
	rt.fleet.signingKeys = keys
	rt.fleet.telemetryBindings = bindings
}

func (f *fleetRouter) registerTelemetrySigningKey(w http.ResponseWriter, r *http.Request) {
	if f.signingKeys == nil {
		writeJSON(w, http.StatusNotFound, errorBody{Error: "telemetry signing-key registration not enabled"})
		return
	}
	agent, ok := agentFrom(r.Context())
	if !ok || agent == nil {
		writeJSON(w, http.StatusUnauthorized, errorBody{Error: "unauthenticated"})
		return
	}
	var req struct {
		PublicKeyB64 string    `json:"public_key"`
		NotBefore    time.Time `json:"not_before"`
		NotAfter     time.Time `json:"not_after"`
		Proof        string    `json:"proof"`
	}
	if err := decodeFleetJSON(w, r, fleetBodyCap, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid signing-key registration body"})
		return
	}
	pub, err := base64.StdEncoding.DecodeString(req.PublicKeyB64)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid signing public key"})
		return
	}
	key, err := fleetagent.NewSigningKey(agent.ID, fleetagent.PurposeTelemetryBatch, ed25519.PublicKey(pub), req.NotBefore, req.NotAfter)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid signing-key registration"})
		return
	}
	if err := fleetagent.VerifyKeyPossession(key, req.Proof); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid key-possession proof"})
		return
	}
	if err := f.signingKeys.Register(r.Context(), key); err != nil {
		writeFleetTelemetryError(w, f, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"key_id": key.KeyID, "purpose": string(key.Purpose), "not_before": key.NotBefore, "not_after": key.NotAfter,
	})
}

func (f *fleetRouter) ingestTelemetry(w http.ResponseWriter, r *http.Request) {
	if f.telemetry == nil {
		writeJSON(w, http.StatusNotFound, errorBody{Error: "telemetry ingest not enabled"})
		return
	}
	agent, ok := agentFrom(r.Context())
	if !ok || agent == nil {
		writeJSON(w, http.StatusUnauthorized, errorBody{Error: "unauthenticated"})
		return
	}
	body, err := readTelemetryRequest(w, r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid telemetry batch body"})
		return
	}
	var batch fleetagent.SignedTelemetryBatch
	if err := json.Unmarshal(body, &batch); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid telemetry batch body"})
		return
	}
	result, err := f.telemetry.IngestSigned(r.Context(), agent, batch)
	if err != nil {
		writeFleetTelemetryError(w, f, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ack": result.ACK, "new_events": result.NewEvents, "gaps": result.Gaps,
	})
}

func readTelemetryRequest(w http.ResponseWriter, r *http.Request) ([]byte, error) {
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
	if len(payload) > fleetTelemetryDecodedCap {
		return nil, fmt.Errorf("telemetry request exceeds decompressed limit")
	}
	if len(payload) == 0 {
		return nil, errors.New("empty telemetry request")
	}
	return payload, nil
}

func decodeFleetJSON(w http.ResponseWriter, r *http.Request, limit int64, out any) error {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, limit))
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

func writeFleetTelemetryError(w http.ResponseWriter, f *fleetRouter, err error) {
	switch {
	case errors.Is(err, shared.ErrForbidden):
		writeJSON(w, http.StatusForbidden, errorBody{Error: "forbidden"})
	case errors.Is(err, shared.ErrValidation):
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid telemetry request"})
	case errors.Is(err, shared.ErrConflict):
		writeJSON(w, http.StatusConflict, errorBody{Error: "telemetry conflict"})
	case errors.Is(err, shared.ErrSaturated):
		w.Header().Set("Retry-After", "1")
		writeJSON(w, http.StatusTooManyRequests, errorBody{Error: "telemetry backpressure"})
	default:
		// Durable-store/key-registry failures are retryable server failures. Do not reflect
		// internal details to the untrusted agent plane.
		f.log.Error("fleet telemetry request failed", "err", err)
		w.Header().Set("Retry-After", "1")
		writeJSON(w, http.StatusServiceUnavailable, errorBody{Error: "telemetry unavailable"})
	}
}
