package fleetagent

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/telemetryschema"
)

const telemetryBatchSignatureContext = "synapse-telemetry-batch:v1"

// TelemetryBatchManifest is the signed, uncompressed commitment for one contiguous
// telemetry delivery range. Payload compression is a wire concern and MUST happen
// only after this manifest has been signed.
type TelemetryBatchManifest struct {
	ProtocolVersion      int              `json:"protocol_version"`
	SchemaVersion        int              `json:"schema_version"`
	BatchID              shared.ID        `json:"batch_id"`
	AgentID              shared.ID        `json:"agent_id"`
	AgentSessionID       SessionID        `json:"agent_session_id"`
	AssetID              shared.ID        `json:"asset_id"`
	StreamID             shared.ID        `json:"stream_id"`
	Priority             DeliveryPriority `json:"priority"`
	Epoch                uint64           `json:"epoch"`
	Sequence             uint64           `json:"sequence"`
	PreviousSequence     uint64           `json:"previous_sequence"`
	EventTimeMin         time.Time        `json:"event_time_min"`
	EventTimeMax         time.Time        `json:"event_time_max"`
	ObservedCount        uint64           `json:"observed_count"`
	KeptCount            uint64           `json:"kept_count"`
	SampledOutCount      uint64           `json:"sampled_out_count"`
	TruncatedCount       uint64           `json:"truncated_count"`
	DroppedCount         uint64           `json:"dropped_count"`
	SamplingPolicyDigest string           `json:"sampling_policy_digest"`
	EventIDs             []shared.ID      `json:"event_ids"`
	EventDigests         []string         `json:"event_digests"`
	PayloadDigest        string           `json:"payload_digest"`
}

// SignedTelemetryBatch is the agent-to-control-plane wire value before optional
// HTTP compression. Payload is the canonical uncompressed JSON array of telemetry
// envelopes whose SHA-256 is committed by Manifest.PayloadDigest.
type SignedTelemetryBatch struct {
	Manifest  TelemetryBatchManifest `json:"manifest"`
	KeyID     string                 `json:"key_id"`
	Signature []byte                 `json:"signature"`
	Payload   []byte                 `json:"payload"`
}

// Validate checks the manifest's structural and delivery invariants. Identity
// authorization is deliberately NOT done here; the server use case compares these
// values against the authenticated agent/session/asset binding.
func (m TelemetryBatchManifest) Validate() error {
	if m.ProtocolVersion != 1 {
		return fmt.Errorf("%w: telemetry batch protocol version %d is unsupported", shared.ErrValidation, m.ProtocolVersion)
	}
	if err := telemetryschema.Validate(m.SchemaVersion); err != nil {
		return err
	}
	if m.BatchID.IsZero() || m.AgentID.IsZero() || m.AssetID.IsZero() || m.StreamID.IsZero() {
		return fmt.Errorf("%w: telemetry batch identity is incomplete", shared.ErrValidation)
	}
	if m.AgentSessionID == "" {
		return fmt.Errorf("%w: telemetry batch agent session is required", shared.ErrValidation)
	}
	if !m.Priority.Valid() {
		return fmt.Errorf("%w: unknown delivery priority %d", shared.ErrValidation, int(m.Priority))
	}
	if m.Epoch == 0 || m.Sequence == 0 {
		return fmt.Errorf("%w: telemetry batch epoch and sequence must be positive", shared.ErrValidation)
	}
	if m.PreviousSequence >= m.Sequence {
		return fmt.Errorf("%w: telemetry batch previous sequence must precede sequence", shared.ErrValidation)
	}
	if m.EventTimeMin.IsZero() || m.EventTimeMax.IsZero() || m.EventTimeMin.After(m.EventTimeMax) {
		return fmt.Errorf("%w: telemetry batch event-time range is invalid", shared.ErrValidation)
	}
	if m.ObservedCount < m.KeptCount || m.ObservedCount != m.KeptCount+m.SampledOutCount+m.TruncatedCount+m.DroppedCount {
		return fmt.Errorf("%w: telemetry batch accounting is inconsistent", shared.ErrValidation)
	}
	if m.KeptCount == 0 || uint64(len(m.EventIDs)) != m.KeptCount || len(m.EventIDs) != len(m.EventDigests) {
		return fmt.Errorf("%w: telemetry batch kept/event digest counts disagree", shared.ErrValidation)
	}
	// A contiguous range contains one kept spool record per sequence. Losses are
	// represented by durable gap records instead of pretending a sparse range is contiguous.
	if width := m.Sequence - m.PreviousSequence; width != m.KeptCount {
		return fmt.Errorf("%w: telemetry batch sequence width %d disagrees with kept count %d", shared.ErrValidation, width, m.KeptCount)
	}
	if !validSHA256Hex(m.SamplingPolicyDigest) || !validSHA256Hex(m.PayloadDigest) {
		return fmt.Errorf("%w: telemetry batch policy/payload digest must be sha256 hex", shared.ErrValidation)
	}
	seen := make(map[shared.ID]struct{}, len(m.EventIDs))
	for i, id := range m.EventIDs {
		if id.IsZero() || !validSHA256Hex(m.EventDigests[i]) {
			return fmt.Errorf("%w: telemetry batch event commitment %d is invalid", shared.ErrValidation, i)
		}
		if _, ok := seen[id]; ok {
			return fmt.Errorf("%w: telemetry batch contains duplicate event id %q", shared.ErrValidation, id)
		}
		seen[id] = struct{}{}
	}
	return nil
}

// Validate verifies the full signed batch value except the public-key signature.
func (b SignedTelemetryBatch) Validate() error {
	if err := b.Manifest.Validate(); err != nil {
		return err
	}
	if b.KeyID == "" || len(b.Signature) != ed25519.SignatureSize {
		return fmt.Errorf("%w: telemetry batch key id/signature is invalid", shared.ErrValidation)
	}
	if got := SHA256Hex(b.Payload); got != b.Manifest.PayloadDigest {
		return fmt.Errorf("%w: telemetry batch payload digest mismatch", shared.ErrValidation)
	}
	wantID := DeriveTelemetryBatchID(
		b.Manifest.AgentID,
		b.Manifest.AgentSessionID,
		b.Manifest.StreamID,
		b.Manifest.Epoch,
		b.Manifest.Sequence,
		b.Manifest.PayloadDigest,
	)
	if b.Manifest.BatchID != wantID {
		return fmt.Errorf("%w: telemetry batch id %q does not match committed delivery coordinates", shared.ErrValidation, b.Manifest.BatchID)
	}
	return nil
}

// SignTelemetryBatch signs the canonical uncompressed manifest commitment plus
// KeyID. Binding KeyID into the signature prevents an intermediary from swapping
// the resolver selector while leaving the signed payload untouched.
func SignTelemetryBatch(manifest TelemetryBatchManifest, payload []byte, keyID string, privateKey ed25519.PrivateKey) (SignedTelemetryBatch, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return SignedTelemetryBatch{}, fmt.Errorf("%w: telemetry batch requires an Ed25519 private key", shared.ErrValidation)
	}
	if keyID == "" {
		return SignedTelemetryBatch{}, fmt.Errorf("%w: telemetry batch key id is required", shared.ErrValidation)
	}
	manifest.PayloadDigest = SHA256Hex(payload)
	manifest.BatchID = DeriveTelemetryBatchID(manifest.AgentID, manifest.AgentSessionID, manifest.StreamID, manifest.Epoch, manifest.Sequence, manifest.PayloadDigest)
	if err := manifest.Validate(); err != nil {
		return SignedTelemetryBatch{}, err
	}
	msg := telemetrySignedCommitment(manifest, keyID)
	return SignedTelemetryBatch{
		Manifest: manifest,
		KeyID: keyID,
		Signature: ed25519.Sign(privateKey, msg),
		Payload: append([]byte(nil), payload...),
	}, nil
}

// VerifyTelemetryBatch verifies structural commitments and the Ed25519 signature.
func VerifyTelemetryBatch(batch SignedTelemetryBatch, publicKey ed25519.PublicKey) error {
	if err := batch.Validate(); err != nil {
		return err
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: telemetry batch requires an Ed25519 public key", shared.ErrValidation)
	}
	if !ed25519.Verify(publicKey, telemetrySignedCommitment(batch.Manifest, batch.KeyID), batch.Signature) {
		return fmt.Errorf("%w: telemetry batch signature verification failed", shared.ErrValidation)
	}
	return nil
}

// VerifyTelemetryBatchWithKey is the lifecycle-aware admission gate for A3. It
// applies the same key binding used by the other signed agent streams: telemetry
// purpose only, canonical agent binding, exact KeyID, validity/revocation, then
// cryptographic verification.
func VerifyTelemetryBatchWithKey(key AgentSigningKey, now time.Time, batch SignedTelemetryBatch) error {
	if key.Purpose != PurposeTelemetryBatch {
		return fmt.Errorf("%w: signing key %s is for %q, not %q", shared.ErrForbidden, key.KeyID, key.Purpose, PurposeTelemetryBatch)
	}
	if key.AgentID != batch.Manifest.AgentID {
		return fmt.Errorf("%w: signing key %s is bound to agent %s, not %s", shared.ErrForbidden, key.KeyID, key.AgentID, batch.Manifest.AgentID)
	}
	if batch.KeyID != key.KeyID {
		return fmt.Errorf("%w: telemetry batch names key %s but was resolved as %s", shared.ErrForbidden, batch.KeyID, key.KeyID)
	}
	if err := key.UsableAt(now); err != nil {
		return err
	}
	return VerifyTelemetryBatch(batch, key.PublicKey)
}

// DeriveTelemetryBatchID gives retries of the same committed range the same batch
// identity while a changed payload necessarily gets a different id.
func DeriveTelemetryBatchID(agentID shared.ID, session SessionID, streamID shared.ID, epoch, sequence uint64, payloadDigest string) shared.ID {
	var buf bytes.Buffer
	writeCommitString(&buf, "synapse-telemetry-batch-id:v1")
	writeCommitString(&buf, agentID.String())
	writeCommitString(&buf, string(session))
	writeCommitString(&buf, streamID.String())
	writeCommitUint64(&buf, epoch)
	writeCommitUint64(&buf, sequence)
	writeCommitString(&buf, payloadDigest)
	sum := sha256.Sum256(buf.Bytes())
	return shared.ID("tb_" + hex.EncodeToString(sum[:16]))
}

// SHA256Hex returns the lowercase SHA-256 commitment used by the transport.
func SHA256Hex(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

func telemetrySignedCommitment(m TelemetryBatchManifest, keyID string) []byte {
	var buf bytes.Buffer
	writeCommitString(&buf, telemetryBatchSignatureContext)
	writeCommitString(&buf, keyID)
	_, _ = buf.Write(telemetryManifestCommitment(m))
	return buf.Bytes()
}

func telemetryManifestCommitment(m TelemetryBatchManifest) []byte {
	var buf bytes.Buffer
	writeCommitUint64(&buf, uint64(m.ProtocolVersion))
	writeCommitUint64(&buf, uint64(m.SchemaVersion))
	writeCommitString(&buf, m.BatchID.String())
	writeCommitString(&buf, m.AgentID.String())
	writeCommitString(&buf, string(m.AgentSessionID))
	writeCommitString(&buf, m.AssetID.String())
	writeCommitString(&buf, m.StreamID.String())
	writeCommitUint64(&buf, uint64(m.Priority))
	writeCommitUint64(&buf, m.Epoch)
	writeCommitUint64(&buf, m.Sequence)
	writeCommitUint64(&buf, m.PreviousSequence)
	writeCommitInt64(&buf, m.EventTimeMin.UTC().UnixNano())
	writeCommitInt64(&buf, m.EventTimeMax.UTC().UnixNano())
	writeCommitUint64(&buf, m.ObservedCount)
	writeCommitUint64(&buf, m.KeptCount)
	writeCommitUint64(&buf, m.SampledOutCount)
	writeCommitUint64(&buf, m.TruncatedCount)
	writeCommitUint64(&buf, m.DroppedCount)
	writeCommitString(&buf, m.SamplingPolicyDigest)
	writeCommitUint64(&buf, uint64(len(m.EventIDs)))
	for i := range m.EventIDs {
		writeCommitString(&buf, m.EventIDs[i].String())
		writeCommitString(&buf, m.EventDigests[i])
	}
	writeCommitString(&buf, m.PayloadDigest)
	return buf.Bytes()
}

func writeCommitString(buf *bytes.Buffer, value string) {
	writeCommitUint64(buf, uint64(len(value)))
	_, _ = buf.WriteString(value)
}

func writeCommitUint64(buf *bytes.Buffer, value uint64) {
	var raw [8]byte
	binary.BigEndian.PutUint64(raw[:], value)
	_, _ = buf.Write(raw[:])
}

func writeCommitInt64(buf *bytes.Buffer, value int64) {
	writeCommitUint64(buf, uint64(value))
}

func validSHA256Hex(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
