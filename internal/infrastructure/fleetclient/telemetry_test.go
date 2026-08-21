package fleetclient

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
)

func TestShipTelemetryUsesGzipAndDecodesACK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/fleet/telemetry" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get(protoHeader) != protoVersion || r.Header.Get("Authorization") != "Bearer token" {
			t.Fatalf("missing fleet auth/proto headers")
		}
		if r.Header.Get("Content-Encoding") != "gzip" {
			t.Fatalf("telemetry must be compressed on wire")
		}
		zr, err := gzip.NewReader(r.Body)
		if err != nil {
			t.Fatalf("gzip reader: %v", err)
		}
		defer zr.Close()
		var got fleetagent.SignedTelemetryBatch
		if err := json.NewDecoder(zr).Decode(&got); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ack": map[string]any{"priority": 3, "epoch": 7, "through": 12},
			"new_events": 4,
			"gaps": []any{},
		})
	}))
	t.Cleanup(srv.Close)

	resp, err := New(srv.URL, 5*time.Second).ShipTelemetry(context.Background(), "token", fleetagent.SignedTelemetryBatch{})
	if err != nil {
		t.Fatalf("ShipTelemetry: %v", err)
	}
	priority, epoch, through := resp.Ack()
	if priority != fleetagent.PriorityP3 || epoch != 7 || through != 12 || resp.NewEvents != 4 {
		t.Fatalf("unexpected response: %+v", resp)
	}
}

func TestShipTelemetryPreservesRetryAfter(t *testing.T) {
	for _, statusCode := range []int{http.StatusTooManyRequests, http.StatusServiceUnavailable} {
		t.Run(http.StatusText(statusCode), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Retry-After", "7")
				w.WriteHeader(statusCode)
				_, _ = w.Write([]byte("busy"))
			}))
			defer srv.Close()
			_, err := New(srv.URL, 5*time.Second).ShipTelemetry(context.Background(), "token", fleetagent.SignedTelemetryBatch{})
			var status *HTTPStatusError
			if !errors.As(err, &status) {
				t.Fatalf("want HTTPStatusError, got %v", err)
			}
			if !status.Retryable() || status.RetryAfter != 7*time.Second || status.StatusCode != statusCode {
				t.Fatalf("retry contract lost: %+v", status)
			}
		})
	}
}
