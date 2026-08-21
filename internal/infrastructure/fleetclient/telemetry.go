package fleetclient

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// HostInventoryResponse returns the server-reconciled canonical asset identity. The
// agent persists this value and never substitutes its mutable name or AgentID for it.
type HostInventoryResponse struct {
	AssetID string `json:"asset_id"`
}

func (c *Client) SendHostInventoryResolved(ctx context.Context, token string, inv any) (HostInventoryResponse, error) {
	var out HostInventoryResponse
	err := c.do(ctx, http.MethodPost, "/api/v1/fleet/inventory/host", token, inv, &out)
	return out, err
}

// RegisterTelemetrySigningKey proves possession of the private half before the
// control plane persists the purpose-bound telemetry public key.
func (c *Client) RegisterTelemetrySigningKey(ctx context.Context, token string, key fleetagent.AgentSigningKey, proof string) error {
	if err := key.Validate(); err != nil {
		return err
	}
	if key.Purpose != fleetagent.PurposeTelemetryBatch {
		return fmt.Errorf("fleetclient: telemetry registration requires purpose %q", fleetagent.PurposeTelemetryBatch)
	}
	return c.do(ctx, http.MethodPost, "/api/v1/fleet/signing-keys", token, map[string]any{
		"public_key": base64.StdEncoding.EncodeToString(key.PublicKey),
		"not_before": key.NotBefore,
		"not_after":  key.NotAfter,
		"proof":      proof,
	}, nil)
}

// TelemetryShipResponse is the durable server acknowledgement. Through is the
// highest contiguous sequence for the returned priority/epoch, never merely the
// highest sequence observed in this request.
type TelemetryShipResponse struct {
	ACK       FleetTelemetryACK `json:"ack"`
	NewEvents int               `json:"new_events"`
}

// FleetTelemetryACK is the client-side wire view of the server durable ACK.
type FleetTelemetryACK struct {
	Priority fleetagent.DeliveryPriority `json:"priority"`
	Epoch    uint64                      `json:"epoch"`
	Through  uint64                      `json:"through"`
}

func (r TelemetryShipResponse) Ack() (fleetagent.DeliveryPriority, uint64, uint64) {
	return r.ACK.Priority, r.ACK.Epoch, r.ACK.Through
}

// HTTPStatusError preserves the status required by A2's retry policy without
// exposing or depending on server response text.
type HTTPStatusError struct {
	StatusCode int
	RetryAfter time.Duration
}

func (e *HTTPStatusError) Error() string {
	return fmt.Sprintf("fleetclient: telemetry status %d", e.StatusCode)
}

func (e *HTTPStatusError) Retryable() bool {
	return e.StatusCode == http.StatusTooManyRequests || e.StatusCode >= 500
}

// ShipTelemetry sends the JSON wire value gzip-compressed. The signature already
// commits to the canonical UNCOMPRESSED manifest/payload; HTTP compression is applied
// only after signing and therefore cannot change the commitment.
func (c *Client) ShipTelemetry(ctx context.Context, token string, batch fleetagent.SignedTelemetryBatch) (TelemetryShipResponse, error) {
	var out TelemetryShipResponse
	body, err := json.Marshal(batch)
	if err != nil {
		return out, fmt.Errorf("fleetclient: marshal telemetry: %w", err)
	}
	var compressed bytes.Buffer
	zw := gzip.NewWriter(&compressed)
	if _, err := zw.Write(body); err != nil {
		_ = zw.Close()
		return out, fmt.Errorf("fleetclient: gzip telemetry: %w", err)
	}
	if err := zw.Close(); err != nil {
		return out, fmt.Errorf("fleetclient: gzip telemetry close: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/v1/fleet/telemetry", bytes.NewReader(compressed.Bytes()))
	if err != nil {
		return out, fmt.Errorf("fleetclient: telemetry request: %w", err)
	}
	req.Header.Set(protoHeader, protoVersion)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return out, fmt.Errorf("fleetclient: telemetry: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		h := &HTTPStatusError{StatusCode: resp.StatusCode}
		if seconds, parseErr := strconv.Atoi(resp.Header.Get("Retry-After")); parseErr == nil && seconds > 0 {
			h.RetryAfter = time.Duration(seconds) * time.Second
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
		return out, h
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(&out); err != nil {
		return out, fmt.Errorf("fleetclient: decode telemetry ack: %w", err)
	}
	return out, nil
}

// BuildTelemetrySigningKey reconstructs the public lifecycle value from an agent's
// persisted private key and exact registration window.
func BuildTelemetrySigningKey(agentID string, private ed25519.PrivateKey, notBefore, notAfter time.Time) (fleetagent.AgentSigningKey, error) {
	if len(private) != ed25519.PrivateKeySize {
		return fleetagent.AgentSigningKey{}, fmt.Errorf("fleetclient: invalid telemetry private key")
	}
	pub, ok := private.Public().(ed25519.PublicKey)
	if !ok {
		return fleetagent.AgentSigningKey{}, fmt.Errorf("fleetclient: telemetry private key has no Ed25519 public key")
	}
	return fleetagent.NewSigningKey(shared.ID(agentID), fleetagent.PurposeTelemetryBatch, pub, notBefore, notAfter)
}
