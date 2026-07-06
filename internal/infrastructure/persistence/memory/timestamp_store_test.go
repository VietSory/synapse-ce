package memory

import (
	"context"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestTimestampStoreGetPutIdempotent(t *testing.T) {
	s := NewTimestampStore()
	ctx := context.Background()
	if got, _ := s.Get(ctx, "evidence", "e1", "head"); got != nil {
		t.Fatal("empty store must return nil")
	}
	tok := ports.TimestampToken{Authority: "tsa", Token: "abc"}
	if err := s.Put(ctx, "evidence", "e1", "head", tok); err != nil {
		t.Fatal(err)
	}
	got, _ := s.Get(ctx, "evidence", "e1", "head")
	if got == nil || got.Token != "abc" {
		t.Fatalf("get after put = %+v", got)
	}
	// First write wins (idempotent), like the SQL ON CONFLICT DO NOTHING.
	_ = s.Put(ctx, "evidence", "e1", "head", ports.TimestampToken{Authority: "tsa", Token: "second"})
	got, _ = s.Get(ctx, "evidence", "e1", "head")
	if got.Token != "abc" {
		t.Errorf("put must be idempotent (first wins), got %q", got.Token)
	}
	// Keys are independent across chain + engagement.
	if got, _ := s.Get(ctx, "audit", "", "head"); got != nil {
		t.Error("a different (chain,engagement) must not collide")
	}
}
