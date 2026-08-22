package spool

import (
	"context"
	"encoding/binary"
	"os"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestRecoveryInfersKnownSequenceForUntrustedCorruptHeader(t *testing.T) {
	cfg := testConfig(t)
	cfg.Sync[fleetagent.PriorityP3] = SyncAlways
	s, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	first := mustEnqueue(t, s, testItem(fleetagent.PriorityP3, "first", 80))
	second := mustEnqueue(t, s, testItem(fleetagent.PriorityP3, "lost-header", 80))
	third := mustEnqueue(t, s, testItem(fleetagent.PriorityP3, "third", 80))
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	path := onlySegment(t, cfg.Dir)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	firstLength := frameHeaderSize + int(binary.LittleEndian.Uint32(data[8:12]))
	// Destroy the second frame magic so its own sequence is no longer trusted.
	// Recovery must resynchronise on the third frame and infer sequence 2 from
	// the segment start plus the surrounding trusted sequence coordinates.
	data[firstLength] ^= 0xff
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	recovered, err := Open(cfg)
	if err != nil {
		t.Fatalf("recover untrusted middle header: %v", err)
	}
	defer recovered.Close()
	requireIDs(t, mustPeek(t, recovered), "first", "third")
	gaps, err := recovered.Gaps(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	assertKnownGap(t, gaps, ports.SpoolGapCorruptFrame, second.Epoch, second.Sequence, second.Sequence)

	unknown := 0
	for _, gap := range gaps {
		if gap.Reason == ports.SpoolGapCorruptFrame && !gap.KnownSequence {
			unknown++
		}
	}
	if unknown == 0 {
		t.Fatal("untrusted-header corruption provenance was lost when exact sequence was inferred")
	}
	if first.Sequence != 1 || third.Sequence != 3 {
		t.Fatalf("test coordinates unexpected: first=%#v third=%#v", first, third)
	}
}
