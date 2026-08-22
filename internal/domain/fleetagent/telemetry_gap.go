package fleetagent

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

const (
	telemetryGapSignatureContext = "synapse-telemetry-gap:v1"
	maxTelemetryGapInteger       = uint64(1<<63 - 1)
	maxTelemetryGapIDBytes       = 128
)

// TelemetryGapManifest is the signed A2->A3 loss evidence emitted by the durable
// agent spool. It is deliberately separate from sequence holes inferred by the
// control plane: local disk/quota/corruption loss may have no trustworthy sequence.
type TelemetryGapManifest struct {
	ProtocolVersion int              `json:"protocol_version"`
	GapID           shared.ID        `json:"gap_id"`
	AgentID         shared.ID        `json:"agent_id"`
	HostID          shared.ID        `json:"host_id"`
	AgentSessionID  SessionID        `json:"agent_session_id"`
	AssetID         shared.ID        `json:"asset_id"`
	StreamID        shared.ID        `json:"stream_id"`
	Priority        DeliveryPriority `json:"priority"`
	Epoch           uint64           `json:"epoch"`
	KnownSequence   bool             `json:"known_sequence"`
	FromSequence    uint64           `json:"from_sequence"`
	ToSequence      uint64           `json:"to_sequence"`
	Reason          string           `json:"reason"`
	Count           uint64           `json:"count"`
	OccurredAt      time.Time        `json:"occurred_at"`
}

type SignedTelemetryGap struct {
	Manifest  TelemetryGapManifest `json:"manifest"`
	KeyID     string               `json:"key_id"`
	Signature []byte               `json:"signature"`
}

func (m TelemetryGapManifest) Validate() error {
	if m.ProtocolVersion != 1 {
		return fmt.Errorf("%w: telemetry gap protocol version %d is unsupported", shared.ErrValidation, m.ProtocolVersion)
	}
	if m.GapID.IsZero() || m.AgentID.IsZero() || m.HostID.IsZero() || m.AssetID.IsZero() || m.StreamID.IsZero() || m.AgentSessionID == "" {
		return fmt.Errorf("%w: telemetry gap identity is incomplete", shared.ErrValidation)
	}
	if len(m.GapID.String()) > maxTelemetryGapIDBytes {
		return fmt.Errorf("%w: telemetry gap id exceeds %d bytes", shared.ErrValidation, maxTelemetryGapIDBytes)
	}
	if !m.Priority.Valid() || m.Epoch == 0 || m.Count == 0 || m.Reason == "" || m.OccurredAt.IsZero() {
		return fmt.Errorf("%w: telemetry gap coordinates/reason are incomplete", shared.ErrValidation)
	}
	if m.Epoch > maxTelemetryGapInteger || m.Count > maxTelemetryGapInteger {
		return fmt.Errorf("%w: telemetry gap epoch/count exceeds durable integer range", shared.ErrValidation)
	}
	if m.KnownSequence {
		if m.FromSequence == 0 || m.ToSequence < m.FromSequence || m.Count != m.ToSequence-m.FromSequence+1 {
			return fmt.Errorf("%w: telemetry gap sequence range/count is invalid", shared.ErrValidation)
		}
		if m.FromSequence > maxTelemetryGapInteger || m.ToSequence > maxTelemetryGapInteger {
			return fmt.Errorf("%w: telemetry gap sequence exceeds durable integer range", shared.ErrValidation)
		}
	} else if m.FromSequence != 0 || m.ToSequence != 0 {
		return fmt.Errorf("%w: unknown-coordinate telemetry gap cannot claim a sequence range", shared.ErrValidation)
	}
	return nil
}

func (g SignedTelemetryGap) Validate() error {
	if err := g.Manifest.Validate(); err != nil {
		return err
	}
	if g.KeyID == "" || len(g.Signature) != ed25519.SignatureSize {
		return fmt.Errorf("%w: telemetry gap key id/signature is invalid", shared.ErrValidation)
	}
	return nil
}

func SignTelemetryGap(manifest TelemetryGapManifest, keyID string, privateKey ed25519.PrivateKey) (SignedTelemetryGap, error) {
	if len(privateKey) != ed25519.PrivateKeySize || keyID == "" {
		return SignedTelemetryGap{}, fmt.Errorf("%w: telemetry gap requires Ed25519 key material", shared.ErrValidation)
	}
	if err := manifest.Validate(); err != nil {
		return SignedTelemetryGap{}, err
	}
	return SignedTelemetryGap{Manifest: manifest, KeyID: keyID, Signature: ed25519.Sign(privateKey, telemetryGapCommitment(manifest, keyID))}, nil
}

func VerifyTelemetryGapWithKey(key AgentSigningKey, now time.Time, gap SignedTelemetryGap) error {
	if err := gap.Validate(); err != nil {
		return err
	}
	if key.Purpose != PurposeTelemetryBatch || key.AgentID != gap.Manifest.AgentID || key.KeyID != gap.KeyID {
		return fmt.Errorf("%w: telemetry gap signing key binding is invalid", shared.ErrForbidden)
	}
	if err := key.UsableAt(now); err != nil {
		return err
	}
	if !ed25519.Verify(key.PublicKey, telemetryGapCommitment(gap.Manifest, gap.KeyID), gap.Signature) {
		return fmt.Errorf("%w: telemetry gap signature verification failed", shared.ErrValidation)
	}
	return nil
}

func telemetryGapCommitment(m TelemetryGapManifest, keyID string) []byte {
	var buf bytes.Buffer
	writeCommitString(&buf, telemetryGapSignatureContext)
	writeCommitString(&buf, keyID)
	writeCommitUint64(&buf, uint64(m.ProtocolVersion))
	writeCommitString(&buf, m.GapID.String())
	writeCommitString(&buf, m.AgentID.String())
	writeCommitString(&buf, m.HostID.String())
	writeCommitString(&buf, string(m.AgentSessionID))
	writeCommitString(&buf, m.AssetID.String())
	writeCommitString(&buf, m.StreamID.String())
	writeCommitUint64(&buf, uint64(m.Priority))
	writeCommitUint64(&buf, m.Epoch)
	if m.KnownSequence {
		writeCommitUint64(&buf, 1)
	} else {
		writeCommitUint64(&buf, 0)
	}
	writeCommitUint64(&buf, m.FromSequence)
	writeCommitUint64(&buf, m.ToSequence)
	writeCommitString(&buf, m.Reason)
	writeCommitUint64(&buf, m.Count)
	writeCommitInt64(&buf, m.OccurredAt.UTC().UnixNano())
	return buf.Bytes()
}
