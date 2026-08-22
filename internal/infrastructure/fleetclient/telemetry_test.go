package fleetclient

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
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

func TestShipTelemetryGapUsesDistinctMediaTypeAndDecodesACK(t *testing.T) {
	gapID := shared.ID("gap-client-wire")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/fleet/telemetry" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get(protoHeader) != protoVersion || r.Header.Get("Authorization") != "Bearer token" {
			t.Fatalf("missing fleet auth/proto headers")
		}
		if got := r.Header.Get("Content-Type"); got != telemetryGapContentType {
			t.Fatalf("gap Content-Type=%q want=%q", got, telemetryGapContentType)
		}
		if got := r.Header.Get("Content-Encoding"); got != "" {
			t.Fatalf("gap Content-Encoding=%q want empty", got)
		}
		var got fleetagent.SignedTelemetryGap
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatalf("decode gap request: %v", err)
		}
		if got.Manifest.GapID != gapID {
			t.Fatalf("gap id=%q want=%q", got.Manifest.GapID, gapID)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"gap_id": gapID})
	}))
	t.Cleanup(srv.Close)

	resp, err := New(srv.URL, 5*time.Second).ShipTelemetry(context.Background(), "token", fleetagent.SignedTelemetryGap{
		Manifest: fleetagent.TelemetryGapManifest{GapID: gapID},
	})
	if err != nil {
		t.Fatalf("ShipTelemetryGap: %v", err)
	}
	if resp.GapID != gapID {
		t.Fatalf("gap ACK=%q want=%q", resp.GapID, gapID)
	}
}

func TestShipTelemetryGapPreservesRetryAfter(t *testing.T) {
	for _, statusCode := range []int{http.StatusTooManyRequests, http.StatusServiceUnavailable} {
		t.Run(http.StatusText(statusCode), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Retry-After", "6")
				w.WriteHeader(statusCode)
				_, _ = w.Write([]byte("busy"))
			}))
			defer srv.Close()

			_, err := New(srv.URL, 5*time.Second).ShipTelemetryGap(context.Background(), "token", fleetagent.SignedTelemetryGap{})
			var status *HTTPStatusError
			if !errors.As(err, &status) {
				t.Fatalf("want HTTPStatusError, got %v", err)
			}
			if !status.Retryable() || status.RetryAfter != 6*time.Second || status.StatusCode != statusCode {
				t.Fatalf("gap retry contract lost: %+v", status)
			}
		})
	}
}

func TestRegisterTelemetrySigningKeyPreservesRetryAfter(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/fleet/signing-keys" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Retry-After", "9")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	signer, err := NewCredentialStore(t.TempDir()).EnsureTelemetrySigner("agent-register-retry", time.Now().UTC())
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	proof := fleetagent.ProveKeyPossession(signer.PrivateKey, signer.Key)
	err = New(srv.URL, 5*time.Second).RegisterTelemetrySigningKey(context.Background(), "token", signer.Key, proof)
	var status *HTTPStatusError
	if !errors.As(err, &status) {
		t.Fatalf("want HTTPStatusError, got %v", err)
	}
	if !status.Retryable() || status.RetryAfter != 9*time.Second || status.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("registration retry contract lost: %+v", status)
	}
}

func TestEnsureTelemetrySignerPersistsAcrossStoreRestart(t *testing.T) {
	dir := t.TempDir()
	now := time.Now().UTC().Truncate(time.Second)
	first, err := NewCredentialStore(dir).EnsureTelemetrySigner("agent-persist", now)
	if err != nil {
		t.Fatalf("first signer: %v", err)
	}
	second, err := NewCredentialStore(dir).EnsureTelemetrySigner("agent-persist", now.Add(time.Hour))
	if err != nil {
		t.Fatalf("reloaded signer: %v", err)
	}
	if first.Key.KeyID != second.Key.KeyID || !bytes.Equal(first.PrivateKey, second.PrivateKey) {
		t.Fatalf("usable telemetry signer did not survive credential-store restart")
	}
	proof := fleetagent.ProveKeyPossession(second.PrivateKey, second.Key)
	if err := fleetagent.VerifyKeyPossession(second.Key, proof); err != nil {
		t.Fatalf("reloaded signer lost proof-of-possession: %v", err)
	}
}

func TestEnsureTelemetrySignerRotatesBeforeExpiry(t *testing.T) {
	dir := t.TempDir()
	now := time.Now().UTC().Truncate(time.Second)
	first, err := NewCredentialStore(dir).EnsureTelemetrySigner("agent-rotate-early", now)
	if err != nil {
		t.Fatalf("first signer: %v", err)
	}
	second, err := NewCredentialStore(dir).EnsureTelemetrySigner("agent-rotate-early", first.Key.NotAfter.Add(-telemetrySigningKeyRotateBefore / 2))
	if err != nil {
		t.Fatalf("rotated signer: %v", err)
	}
	if first.Key.KeyID == second.Key.KeyID || bytes.Equal(first.PrivateKey, second.PrivateKey) {
		t.Fatalf("near-expiry telemetry signer was reused instead of rotated")
	}
}

func TestEnsureTelemetrySignerRotatesAfterExpiry(t *testing.T) {
	dir := t.TempDir()
	now := time.Now().UTC().Truncate(time.Second)
	first, err := NewCredentialStore(dir).EnsureTelemetrySigner("agent-rotate", now)
	if err != nil {
		t.Fatalf("first signer: %v", err)
	}
	second, err := NewCredentialStore(dir).EnsureTelemetrySigner("agent-rotate", first.Key.NotAfter.Add(time.Second))
	if err != nil {
		t.Fatalf("rotated signer: %v", err)
	}
	if first.Key.KeyID == second.Key.KeyID || bytes.Equal(first.PrivateKey, second.PrivateKey) {
		t.Fatalf("expired telemetry signer was reused instead of rotated")
	}
	if !second.Key.NotAfter.After(first.Key.NotAfter) {
		t.Fatalf("rotated signer did not advance validity window: first=%s second=%s", first.Key.NotAfter, second.Key.NotAfter)
	}
}
