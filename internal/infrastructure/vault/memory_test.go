package vault

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func newMemVault(t *testing.T) *MemoryVault {
	t.Helper()
	c, err := NewCipher(testKey(t))
	if err != nil {
		t.Fatal(err)
	}
	return NewMemoryVault(c, nil)
}

func TestMemoryVaultPutResolve(t *testing.T) {
	v := newMemVault(t)
	ctx := context.Background()
	if err := v.Put(ctx, "eng1", "github_pat", []byte("ghp_secret")); err != nil {
		t.Fatal(err)
	}
	got, err := v.Resolve(ctx, "eng1", "github_pat")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte("ghp_secret")) {
		t.Fatalf("resolve = %q", got)
	}
	// Scoped per engagement: another engagement cannot read it.
	if _, err := v.Resolve(ctx, "eng2", "github_pat"); !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("cross-engagement resolve must be ErrNotFound, got %v", err)
	}
}

func TestMemoryVaultUpsertReplacesSecret(t *testing.T) {
	v := newMemVault(t)
	ctx := context.Background()
	_ = v.Put(ctx, "eng1", "tok", []byte("old"))
	metas, _ := v.List(ctx, "eng1")
	created := metas[0].CreatedAt
	_ = v.Put(ctx, "eng1", "tok", []byte("new"))
	got, _ := v.Resolve(ctx, "eng1", "tok")
	if !bytes.Equal(got, []byte("new")) {
		t.Errorf("upsert must replace the secret, got %q", got)
	}
	metas, _ = v.List(ctx, "eng1")
	if !metas[0].CreatedAt.Equal(created) {
		t.Error("upsert must preserve the original CreatedAt")
	}
}

func TestMemoryVaultListNamesOnly(t *testing.T) {
	v := newMemVault(t)
	ctx := context.Background()
	_ = v.Put(ctx, "eng1", "b_tok", []byte("x"))
	_ = v.Put(ctx, "eng1", "a_tok", []byte("y"))
	_ = v.Put(ctx, "eng2", "other", []byte("z"))
	metas, err := v.List(ctx, "eng1")
	if err != nil {
		t.Fatal(err)
	}
	if len(metas) != 2 || metas[0].Name != "a_tok" || metas[1].Name != "b_tok" {
		t.Fatalf("list should be the 2 eng1 names, sorted: %+v", metas)
	}
}

func TestMemoryVaultDelete(t *testing.T) {
	v := newMemVault(t)
	ctx := context.Background()
	_ = v.Put(ctx, "eng1", "tok", []byte("x"))
	if err := v.Delete(ctx, "eng1", "tok"); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Resolve(ctx, "eng1", "tok"); !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("resolve after delete must be ErrNotFound, got %v", err)
	}
	if err := v.Delete(ctx, "eng1", "tok"); !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("deleting a missing credential must be ErrNotFound, got %v", err)
	}
}

func TestMemoryVaultRejectsBadName(t *testing.T) {
	v := newMemVault(t)
	for _, bad := range []string{"", "has space", "semi;colon", "$(inject)", "a/b"} {
		if err := v.Put(context.Background(), "eng1", bad, []byte("x")); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("name %q must be rejected, got %v", bad, err)
		}
	}
}
