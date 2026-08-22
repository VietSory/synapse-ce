package httpapi

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type fakeFleetTelemetryMux struct {
	gapID      shared.ID
	gapCalls   int
	batchCalls int
}

func (f *fakeFleetTelemetryMux) IngestSigned(context.Context, *fleetagent.Agent, fleetagent.SignedTelemetryBatch) (ports.TelemetryDeliveryResult, error) {
	f.batchCalls++
	return ports.TelemetryDeliveryResult{}, nil
}

func (f *fakeFleetTelemetryMux) IngestGapSigned(context.Context, *fleetagent.Agent, fleetagent.SignedTelemetryGap) (shared.ID, error) {
	f.gapCalls++
	return f.gapID, nil
}

func TestIngestTelemetryDispatchesGapMediaType(t *testing.T) {
	gapID := shared.ID("gap-http-dispatch")
	transport := &fakeFleetTelemetryMux{gapID: gapID}
	f := &fleetRouter{telemetry: transport, log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	body, err := json.Marshal(fleetagent.SignedTelemetryGap{
		Manifest: fleetagent.TelemetryGapManifest{GapID: gapID},
	})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/fleet/telemetry", bytes.NewReader(body))
	req.Header.Set("Content-Type", fleetTelemetryGapContentType+"; charset=utf-8")
	req = req.WithContext(context.WithValue(req.Context(), agentKeyCtx, &fleetagent.Agent{ID: "agent-gap-http"}))
	rr := httptest.NewRecorder()

	f.ingestTelemetry(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if transport.gapCalls != 1 || transport.batchCalls != 0 {
		t.Fatalf("dispatch gapCalls=%d batchCalls=%d", transport.gapCalls, transport.batchCalls)
	}
	var response struct {
		GapID shared.ID `json:"gap_id"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.GapID != gapID {
		t.Fatalf("gap ACK=%q want=%q", response.GapID, gapID)
	}
}

func TestIngestTelemetryGapRejectsUnknownJSONBeforeTransport(t *testing.T) {
	transport := &fakeFleetTelemetryMux{gapID: "gap-should-not-run"}
	f := &fleetRouter{telemetry: transport, log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/fleet/telemetry", bytes.NewBufferString(`{"manifest":{"gap_id":"gap-strict"},"key_id":"key","signature":"","unexpected":true}`))
	req.Header.Set("Content-Type", fleetTelemetryGapContentType)
	req = req.WithContext(context.WithValue(req.Context(), agentKeyCtx, &fleetagent.Agent{ID: "agent-gap-strict"}))
	rr := httptest.NewRecorder()

	f.ingestTelemetry(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d want=%d body=%s", rr.Code, http.StatusBadRequest, rr.Body.String())
	}
	if transport.gapCalls != 0 || transport.batchCalls != 0 {
		t.Fatalf("invalid gap reached transport: gapCalls=%d batchCalls=%d", transport.gapCalls, transport.batchCalls)
	}
}

func TestFleetTelemetryErrorBackpressureContract(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	f := &fleetRouter{log: log}
	for _, tc := range []struct {
		name  string
		err   error
		code  int
		retry bool
	}{
		{"forbidden", shared.ErrForbidden, http.StatusForbidden, false},
		{"validation", shared.ErrValidation, http.StatusBadRequest, false},
		{"conflict", shared.ErrConflict, http.StatusConflict, false},
		{"saturated", shared.ErrSaturated, http.StatusTooManyRequests, true},
		{"infrastructure", errors.New("database unavailable"), http.StatusServiceUnavailable, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			writeFleetTelemetryError(rr, f, tc.err)
			if rr.Code != tc.code {
				t.Fatalf("status=%d want=%d body=%s", rr.Code, tc.code, rr.Body.String())
			}
			if got := rr.Header().Get("Retry-After"); (got != "") != tc.retry {
				t.Fatalf("Retry-After=%q retry=%t", got, tc.retry)
			}
		})
	}
}

func TestReadTelemetryRequestAcceptsGzipAndEnforcesDecodedCap(t *testing.T) {
	body := []byte(`{"manifest":{"protocol_version":1}}`)
	var compressed bytes.Buffer
	zw := gzip.NewWriter(&compressed)
	if _, err := zw.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/fleet/telemetry", bytes.NewReader(compressed.Bytes()))
	req.Header.Set("Content-Encoding", "gzip")
	got, err := readTelemetryRequest(httptest.NewRecorder(), req)
	if err != nil {
		t.Fatalf("gzip body rejected: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("decoded body=%q want=%q", got, body)
	}

	var bomb bytes.Buffer
	zw = gzip.NewWriter(&bomb)
	chunk := bytes.Repeat([]byte{'x'}, 1<<20)
	for i := 0; i < 33; i++ {
		if _, err := zw.Write(chunk); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	req = httptest.NewRequest(http.MethodPost, "/api/v1/fleet/telemetry", bytes.NewReader(bomb.Bytes()))
	req.Header.Set("Content-Encoding", "gzip")
	if _, err := readTelemetryRequest(httptest.NewRecorder(), req); err == nil {
		t.Fatal("decompressed body over cap must be rejected")
	}
}

func TestReadTelemetryRequestEnforcesWireCap(t *testing.T) {
	body := bytes.Repeat([]byte{'x'}, fleetTelemetryWireCap+1)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/fleet/telemetry", bytes.NewReader(body))
	if _, err := readTelemetryRequest(httptest.NewRecorder(), req); err == nil {
		t.Fatal("wire body over cap must be rejected")
	}
}

func TestReadTelemetryRequestRejectsEmptyAndCorruptGzip(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/fleet/telemetry", http.NoBody)
		if _, err := readTelemetryRequest(httptest.NewRecorder(), req); err == nil {
			t.Fatal("empty telemetry body must be rejected")
		}
	})

	t.Run("corrupt gzip", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/fleet/telemetry", bytes.NewBufferString("not-gzip"))
		req.Header.Set("Content-Encoding", "gzip")
		if _, err := readTelemetryRequest(httptest.NewRecorder(), req); err == nil {
			t.Fatal("corrupt gzip body must be rejected")
		}
	})
}

func TestReadTelemetryRequestRejectsUnknownEncoding(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/fleet/telemetry", bytes.NewBufferString("{}"))
	req.Header.Set("Content-Encoding", "br")
	if _, err := readTelemetryRequest(httptest.NewRecorder(), req); err == nil {
		t.Fatal("unsupported content encoding must fail closed")
	}
}

func TestDecodeFleetJSONRejectsUnknownFieldsAndTrailingValues(t *testing.T) {
	t.Parallel()

	t.Run("unknown field", func(t *testing.T) {
		var dst struct {
			PublicKey string `json:"public_key"`
		}
		req := httptest.NewRequest(http.MethodPost, "/api/v1/fleet/signing-keys", bytes.NewBufferString(`{"public_key":"abc","unexpected":true}`))
		if err := decodeFleetJSON(httptest.NewRecorder(), req, fleetBodyCap, &dst); err == nil {
			t.Fatal("unknown signing-key registration field must be rejected")
		}
	})

	t.Run("trailing value", func(t *testing.T) {
		var dst struct {
			PublicKey string `json:"public_key"`
		}
		req := httptest.NewRequest(http.MethodPost, "/api/v1/fleet/signing-keys", bytes.NewBufferString(`{"public_key":"abc"} {"public_key":"def"}`))
		if err := decodeFleetJSON(httptest.NewRecorder(), req, fleetBodyCap, &dst); err == nil {
			t.Fatal("multiple signing-key registration values must be rejected")
		}
	})
}
