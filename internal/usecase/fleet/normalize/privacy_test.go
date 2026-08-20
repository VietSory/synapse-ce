package normalize

import (
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/privacy"
)

func privateProcess() DecodedEvent {
	now := time.Unix(1_700_000_000, 0).UTC()
	return DecodedEvent{
		Class: detection.ClassProcess, AgentID: "a", AssetID: "asset", BootID: "boot", StreamID: "stream",
		Sequence: 1, OccurredAt: now, ObservedAt: now,
		Process: &DecodedProcess{
			Kind: "exec", PID: 5, Comm: "curl", Path: "/usr/bin/curl",
			Args: []string{"curl", "--password", "hunter2", "https://u:p@example/x"}, StartTimeNanos: 9,
		},
	}
}

func TestZeroNormalizerScrubsBeforeReturn(t *testing.T) {
	env, err := (Normalizer{}).Normalize(privateProcess())
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(env.Event.Process.Args, " ")
	for _, secret := range []string{"hunter2", "u:p"} {
		if strings.Contains(got, secret) {
			t.Fatalf("secret survived: %q", got)
		}
	}
	if env.RedactionPolicyDigest == "" {
		t.Fatal("missing redaction digest")
	}
}

func TestNormalizerTenantHashPolicy(t *testing.T) {
	p := privacy.DefaultPolicy()
	p.HashKeyID = "k1"
	p.HashKey = []byte("0123456789abcdef")
	p.Overrides = map[privacy.Field]privacy.FieldDisposition{privacy.FieldProcessPath: privacy.Hash}
	n, err := New(p)
	if err != nil {
		t.Fatal(err)
	}
	env, err := n.Normalize(privateProcess())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(env.Event.Process.Path, "hmac-sha256:") || strings.Contains(env.Event.Process.Path, "/usr/bin") {
		t.Fatalf("path not hashed: %q", env.Event.Process.Path)
	}
}

func TestNormalizerCopiesTenantPolicy(t *testing.T) {
	p := privacy.DefaultPolicy()
	p.HashKeyID = "k1"
	p.HashKey = []byte("0123456789abcdef")
	p.Overrides = map[privacy.Field]privacy.FieldDisposition{privacy.FieldProcessPath: privacy.Hash}
	n, err := New(p)
	if err != nil {
		t.Fatal(err)
	}

	p.HashKey[0] = 'X'
	p.Overrides[privacy.FieldProcessPath] = privacy.Allow
	env, err := n.Normalize(privateProcess())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(env.Event.Process.Path, "hmac-sha256:") {
		t.Fatalf("normalizer policy changed through caller-owned config: %q", env.Event.Process.Path)
	}
}
