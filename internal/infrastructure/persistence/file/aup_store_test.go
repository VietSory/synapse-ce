package file

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/aup"
)

func TestAUPStoreRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "aup.json") // also exercises dir creation
	s := NewAUPStore(path)
	ctx := context.Background()

	if ok, err := s.Accepted(ctx, "1.0"); err != nil || ok {
		t.Fatalf("fresh store: ok=%v err=%v", ok, err)
	}

	if err := s.Save(ctx, aup.Acceptance{Version: "1.0", Actor: "operator", AcceptedAt: time.Unix(1, 0).UTC()}); err != nil {
		t.Fatalf("save: %v", err)
	}

	if ok, err := s.Accepted(ctx, "1.0"); err != nil || !ok {
		t.Fatalf("after save: ok=%v err=%v", ok, err)
	}

	// persists across instances (re-open same path)
	if ok, _ := NewAUPStore(path).Accepted(ctx, "1.0"); !ok {
		t.Fatal("acceptance should persist across instances")
	}

	// a different version is not accepted
	if ok, _ := s.Accepted(ctx, "2.0"); ok {
		t.Fatal("version 2.0 should not be accepted")
	}
}
