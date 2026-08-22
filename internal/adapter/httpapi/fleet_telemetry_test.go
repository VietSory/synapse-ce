package httpapi

import (
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

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
