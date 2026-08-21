package fleetclient

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
)

const telemetrySigningKeyLifetime = 30 * 24 * time.Hour

type persistedTelemetrySigner struct {
	PrivateKeyB64 string    `json:"private_key"`
	NotBefore     time.Time `json:"not_before"`
	NotAfter      time.Time `json:"not_after"`
}

// TelemetrySigner is the private agent-side half plus the exact public lifecycle
// registration it proves possession of. The private key never crosses the API.
type TelemetrySigner struct {
	PrivateKey ed25519.PrivateKey
	Key        fleetagent.AgentSigningKey
}

func (s *CredentialStore) telemetrySignerPath() string {
	return filepath.Join(s.dir, "telemetry-signing-key.json")
}

// EnsureTelemetrySigner loads a still-usable signer or creates one. Rotation is
// deliberately done only after expiry; batches are signed at send time from WAL data,
// so an expired signer does not strand already-spooled records under an old signature.
func (s *CredentialStore) EnsureTelemetrySigner(agentID string, now time.Time) (TelemetrySigner, error) {
	if agentID == "" {
		return TelemetrySigner{}, fmt.Errorf("fleetclient: telemetry signer requires agent id")
	}
	if material, err := s.loadTelemetrySigner(agentID); err == nil && now.Before(material.Key.NotAfter) {
		return material, nil
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return TelemetrySigner{}, fmt.Errorf("fleetclient: generate telemetry signing key: %w", err)
	}
	// One minute of backwards tolerance prevents a tiny local/server clock skew from
	// making a freshly registered key pending. The bounded expiry keeps rotation real.
	notBefore := now.UTC().Add(-time.Minute).Truncate(time.Second)
	notAfter := now.UTC().Add(telemetrySigningKeyLifetime).Truncate(time.Second)
	key, err := BuildTelemetrySigningKey(agentID, priv, notBefore, notAfter)
	if err != nil {
		return TelemetrySigner{}, err
	}
	persisted := persistedTelemetrySigner{
		PrivateKeyB64: base64.StdEncoding.EncodeToString(priv), NotBefore: key.NotBefore, NotAfter: key.NotAfter,
	}
	data, err := json.MarshalIndent(persisted, "", "  ")
	if err != nil {
		return TelemetrySigner{}, fmt.Errorf("fleetclient: marshal telemetry signer: %w", err)
	}
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return TelemetrySigner{}, fmt.Errorf("fleetclient: telemetry signer state dir: %w", err)
	}
	if err := WriteSecret(s.telemetrySignerPath(), data, 0o600); err != nil {
		return TelemetrySigner{}, fmt.Errorf("fleetclient: persist telemetry signer: %w", err)
	}
	return TelemetrySigner{PrivateKey: priv, Key: key}, nil
}

func (s *CredentialStore) loadTelemetrySigner(agentID string) (TelemetrySigner, error) {
	data, err := os.ReadFile(s.telemetrySignerPath())
	if err != nil {
		return TelemetrySigner{}, err
	}
	var persisted persistedTelemetrySigner
	if err := json.Unmarshal(data, &persisted); err != nil {
		return TelemetrySigner{}, fmt.Errorf("fleetclient: decode telemetry signer: %w", err)
	}
	raw, err := base64.StdEncoding.DecodeString(persisted.PrivateKeyB64)
	if err != nil || len(raw) != ed25519.PrivateKeySize {
		return TelemetrySigner{}, fmt.Errorf("fleetclient: persisted telemetry private key is invalid")
	}
	priv := ed25519.PrivateKey(append([]byte(nil), raw...))
	key, err := BuildTelemetrySigningKey(agentID, priv, persisted.NotBefore, persisted.NotAfter)
	if err != nil {
		return TelemetrySigner{}, err
	}
	return TelemetrySigner{PrivateKey: priv, Key: key}, nil
}
