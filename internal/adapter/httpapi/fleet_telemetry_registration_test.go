package httpapi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

type captureTelemetrySigningKeyStore struct {
	registered []fleetagent.AgentSigningKey
}

func (s *captureTelemetrySigningKeyStore) Register(_ context.Context, key fleetagent.AgentSigningKey) error {
	s.registered = append(s.registered, key)
	return nil
}

func (s *captureTelemetrySigningKeyStore) ResolveSigningKey(context.Context, shared.ID, string) (fleetagent.AgentSigningKey, error) {
	return fleetagent.AgentSigningKey{}, shared.ErrNotFound
}

func (s *captureTelemetrySigningKeyStore) ListByAgent(context.Context, shared.ID) ([]fleetagent.AgentSigningKey, error) {
	return nil, nil
}

func (s *captureTelemetrySigningKeyStore) Revoke(context.Context, shared.ID, string, time.Time) error {
	return nil
}

func TestRegisterTelemetrySigningKeyVerifiesPossessionBeforePersistence(t *testing.T) {
	t.Parallel()

	agent := &fleetagent.Agent{ID: shared.ID("agent:telemetry-http"), TenantID: shared.ID("tenant:telemetry-http")}
	notBefore := time.Unix(1_700_000_000, 0).UTC()
	notAfter := notBefore.Add(24 * time.Hour)
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	key, err := fleetagent.NewSigningKey(agent.ID, fleetagent.PurposeTelemetryBatch, pub, notBefore, notAfter)
	if err != nil {
		t.Fatalf("NewSigningKey: %v", err)
	}

	body := func(proof string) []byte {
		t.Helper()
		b, err := json.Marshal(map[string]any{
			"public_key": base64.StdEncoding.EncodeToString(pub),
			"not_before": notBefore,
			"not_after":  notAfter,
			"proof":      proof,
		})
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	request := func(payload []byte) *http.Request {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/fleet/signing-keys", bytes.NewReader(payload))
		ctx := context.WithValue(req.Context(), agentKeyCtx, agent)
		ctx = shared.WithTenant(ctx, agent.TenantID)
		return req.WithContext(ctx)
	}

	t.Run("genuine proof is persisted under authenticated agent", func(t *testing.T) {
		store := &captureTelemetrySigningKeyStore{}
		f := &fleetRouter{signingKeys: store, log: slog.New(slog.NewTextHandler(io.Discard, nil))}
		rr := httptest.NewRecorder()
		f.registerTelemetrySigningKey(rr, request(body(fleetagent.ProveKeyPossession(priv, key))))

		if rr.Code != http.StatusCreated {
			t.Fatalf("status=%d want=%d body=%s", rr.Code, http.StatusCreated, rr.Body.String())
		}
		if len(store.registered) != 1 {
			t.Fatalf("registered keys=%d want=1", len(store.registered))
		}
		got := store.registered[0]
		if got.AgentID != agent.ID || got.Purpose != fleetagent.PurposeTelemetryBatch || got.KeyID != key.KeyID {
			t.Fatalf("persisted key binding=(agent=%s purpose=%s key=%s), want=(%s %s %s)", got.AgentID, got.Purpose, got.KeyID, agent.ID, fleetagent.PurposeTelemetryBatch, key.KeyID)
		}
		if !bytes.Equal(got.PublicKey, pub) {
			t.Fatal("persisted public key differs from proof-bound public key")
		}
	})

	t.Run("proof from different private key is rejected before persistence", func(t *testing.T) {
		_, attackerPriv, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatal(err)
		}
		store := &captureTelemetrySigningKeyStore{}
		f := &fleetRouter{signingKeys: store, log: slog.New(slog.NewTextHandler(io.Discard, nil))}
		rr := httptest.NewRecorder()
		f.registerTelemetrySigningKey(rr, request(body(fleetagent.ProveKeyPossession(attackerPriv, key))))

		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status=%d want=%d body=%s", rr.Code, http.StatusBadRequest, rr.Body.String())
		}
		if len(store.registered) != 0 {
			t.Fatalf("invalid possession proof reached persistence: %d keys registered", len(store.registered))
		}
	})
}
