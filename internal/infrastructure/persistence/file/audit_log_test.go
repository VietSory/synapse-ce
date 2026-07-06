package file

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestAuditLogAppends(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "audit.jsonl") // also exercises dir creation
	a := NewAuditLog(path)
	ctx := context.Background()

	for i := 0; i < 2; i++ {
		entry := ports.AuditEntry{Actor: "operator", Action: "aup.accept", Target: "aup:1.0", At: time.Unix(int64(i), 0).UTC()}
		if err := a.Record(ctx, entry); err != nil {
			t.Fatalf("record: %v", err)
		}
	}

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if n := strings.Count(string(b), "\n"); n != 2 {
		t.Fatalf("append-only: want 2 lines, got %d (%q)", n, b)
	}
	if !strings.Contains(string(b), `"action":"aup.accept"`) {
		t.Fatalf("audit entry not recorded: %s", b)
	}
}

func TestAuditLogChainsAndVerifies(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	ctx := context.Background()

	// First process: write two entries.
	a := NewAuditLog(path)
	for i := 0; i < 2; i++ {
		if err := a.Record(ctx, ports.AuditEntry{Actor: "operator", Action: "x", Target: "t", At: time.Unix(int64(i), 0).UTC()}); err != nil {
			t.Fatalf("record: %v", err)
		}
	}
	// Second process (new AuditLog, same path): the head must be recovered from the
	// file so the chain continues unbroken across a restart.
	a2 := NewAuditLog(path)
	if err := a2.Record(ctx, ports.AuditEntry{Actor: "alice", Action: "y", Target: "t", At: time.Unix(2, 0).UTC()}); err != nil {
		t.Fatalf("record after restart: %v", err)
	}

	rep, err := a2.Verify(ctx)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !rep.Intact || rep.Verified != 3 || rep.Unchained != 0 {
		t.Fatalf("fresh chain must be intact 3/0, got %+v", rep)
	}

	// List returns newest-first with the chain hashes populated.
	got, err := a2.List(ctx, 10)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 3 || got[0].Action != "y" || got[0].Hash == "" || got[0].PreviousHash == "" {
		t.Fatalf("list must expose chain links newest-first, got %+v", got)
	}
}

func TestAuditLogVerifyDetectsTampering(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	ctx := context.Background()
	a := NewAuditLog(path)
	for _, act := range []string{"a", "b", "c"} {
		if err := a.Record(ctx, ports.AuditEntry{Actor: "operator", Action: act, Target: "t", At: time.Unix(0, 0).UTC()}); err != nil {
			t.Fatalf("record: %v", err)
		}
	}
	// Tamper: rewrite the middle line's action in place (hash now mismatches content).
	raw, _ := os.ReadFile(path)
	tampered := strings.Replace(string(raw), `"action":"b"`, `"action":"HACKED"`, 1)
	if tampered == string(raw) {
		t.Fatal("test setup: nothing was replaced")
	}
	if err := os.WriteFile(path, []byte(tampered), 0o600); err != nil {
		t.Fatalf("write tampered: %v", err)
	}
	rep, err := NewAuditLog(path).Verify(ctx)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if rep.Intact {
		t.Fatalf("tampering must be detected, report = %+v", rep)
	}
}
