package signing

import (
	"context"
	"errors"
	"strings"
	"testing"

	evdom "github.com/KKloudTarus/synapse-ce/internal/domain/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// a fixed 32-byte seed (hex) for deterministic tests.
const seedHex = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

func TestSignThenDomainVerifyRoundTrip(t *testing.T) {
	seed, err := DecodeSeed(seedHex)
	if err != nil {
		t.Fatalf("decode seed: %v", err)
	}
	s, err := NewEd25519Signer(seed)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	att, err := s.Sign(context.Background(), "deadbeefhead")
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if att.Algorithm != "ed25519" || att.KeyID != s.KeyID() || att.PublicKey != s.PublicKey() || att.Head != "deadbeefhead" {
		t.Fatalf("attestation fields wrong: %+v", att)
	}
	// The domain verifier (public-key only) must accept it.
	if err := evdom.VerifyAttestation(att); err != nil {
		t.Fatalf("valid attestation must verify: %v", err)
	}
}

func TestSignIsDeterministicForSameSeedAndHead(t *testing.T) {
	seed, _ := DecodeSeed(seedHex)
	s1, _ := NewEd25519Signer(seed)
	s2, _ := NewEd25519Signer(seed)
	if s1.KeyID() != s2.KeyID() {
		t.Fatalf("same seed must yield same key id: %s vs %s", s1.KeyID(), s2.KeyID())
	}
	a1, _ := s1.Sign(context.Background(), "head-1")
	a2, _ := s2.Sign(context.Background(), "head-1")
	if a1.Signature != a2.Signature {
		t.Fatal("ed25519 over the same head must be byte-identical (report reproducibility)")
	}
}

func TestDomainSeparationPreventsCrossContextReplay(t *testing.T) {
	seed, _ := DecodeSeed(seedHex)
	base, _ := NewEd25519Signer(seed)
	ev := base.WithContext(evdom.AttestationContextEvidence)
	au := base.WithContext(evdom.AttestationContextAudit)

	const head = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	evAtt, _ := ev.Sign(context.Background(), head)
	auAtt, _ := au.Sign(context.Background(), head)

	// Same key, same head, different context → DIFFERENT signatures, each self-verifying.
	if evAtt.Signature == auAtt.Signature {
		t.Fatal("evidence and audit attestations over the same head must differ (domain separation)")
	}
	if evAtt.Context != evdom.AttestationContextEvidence || auAtt.Context != evdom.AttestationContextAudit {
		t.Fatalf("attestation must record its context: ev=%q au=%q", evAtt.Context, auAtt.Context)
	}
	if err := evdom.VerifyAttestation(evAtt); err != nil {
		t.Fatalf("evidence attestation must verify: %v", err)
	}
	if err := evdom.VerifyAttestation(auAtt); err != nil {
		t.Fatalf("audit attestation must verify: %v", err)
	}

	// Replay attempt: present the evidence signature but relabel its context as audit
	// (the cross-context replay the domain tag is meant to stop). Verification fails
	// because the signed message no longer matches.
	forged := evAtt
	forged.Context = evdom.AttestationContextAudit
	if err := evdom.VerifyAttestation(forged); !errors.Is(err, evdom.ErrBadAttestation) {
		t.Fatalf("relabelling an evidence attestation as audit must fail verification, got %v", err)
	}
	// And the audit signature cannot be passed off under the evidence context.
	forged2 := auAtt
	forged2.Context = evdom.AttestationContextEvidence
	if err := evdom.VerifyAttestation(forged2); !errors.Is(err, evdom.ErrBadAttestation) {
		t.Fatalf("relabelling an audit attestation as evidence must fail verification, got %v", err)
	}
}

func TestVerifyAttestationRejectsTamperedHead(t *testing.T) {
	seed, _ := DecodeSeed(seedHex)
	s, _ := NewEd25519Signer(seed)
	att, _ := s.Sign(context.Background(), "original-head")
	att.Head = "tampered-head" // signature no longer matches
	if err := evdom.VerifyAttestation(att); !errors.Is(err, evdom.ErrBadAttestation) {
		t.Fatalf("a tampered head must fail verification, got %v", err)
	}
}

func TestVerifyAttestationRejectsForeignKeyID(t *testing.T) {
	seed, _ := DecodeSeed(seedHex)
	s, _ := NewEd25519Signer(seed)
	att, _ := s.Sign(context.Background(), "head")
	att.KeyID = "0000000000000000" // claim a different key than the embedded public key
	if err := evdom.VerifyAttestation(att); !errors.Is(err, evdom.ErrBadAttestation) {
		t.Fatalf("key_id mismatch must fail verification, got %v", err)
	}
}

func TestEphemeralWhenNoSeed(t *testing.T) {
	s, err := NewEd25519Signer(nil)
	if err != nil {
		t.Fatalf("ephemeral signer: %v", err)
	}
	if !s.Ephemeral() {
		t.Fatal("a signer built without a seed must report Ephemeral")
	}
	att, _ := s.Sign(context.Background(), "h")
	if err := evdom.VerifyAttestation(att); err != nil {
		t.Fatalf("ephemeral attestations must still self-verify: %v", err)
	}
}

func TestNewSignerRejectsBadSeedLength(t *testing.T) {
	if _, err := NewEd25519Signer([]byte("too-short")); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("a wrong-length seed must be ErrValidation, got %v", err)
	}
}

func TestSignRejectsEmptyHead(t *testing.T) {
	s, _ := NewEd25519Signer(nil)
	if _, err := s.Sign(context.Background(), ""); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("signing an empty head must be ErrValidation, got %v", err)
	}
}

func TestDecodeSeedAcceptsHexAndBase64(t *testing.T) {
	hexSeed, err := DecodeSeed(seedHex)
	if err != nil || len(hexSeed) != 32 {
		t.Fatalf("hex seed: len=%d err=%v", len(hexSeed), err)
	}
	// Build a signer from hex, then re-encode its key the other way and confirm a
	// base64 seed of the same 32 bytes yields the same key id.
	b64 := "ABEiM0RVZneImaq7zN3u/wARIjNEVWZ3iJmqu8zd7v8=" // base64 of seedHex bytes
	b64Seed, err := DecodeSeed(b64)
	if err != nil {
		t.Fatalf("base64 seed: %v", err)
	}
	h, _ := NewEd25519Signer(hexSeed)
	b, _ := NewEd25519Signer(b64Seed)
	if h.KeyID() != b.KeyID() {
		t.Fatal("hex and base64 of the same 32 bytes must produce the same key")
	}
	if _, err := DecodeSeed(""); err != nil {
		t.Fatalf("empty seed must be allowed (ephemeral), got %v", err)
	}
	if _, err := DecodeSeed("not!valid!base64!!"); err == nil || !strings.Contains(err.Error(), "seed") {
		t.Fatalf("garbage seed must error, got %v", err)
	}
}
