package memory

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// memoryDeliveryLane is the durable-in-memory twin of the A3 stream ledger. Historical
// epochs are retained so a delayed exact retry is idempotent while a stale *new* payload
// cannot be admitted after a reboot advanced the lane.
type memoryDeliveryLane struct {
	maxEpoch uint64
	epochs   map[uint64]*memoryDeliveryEpoch
	batches  map[shared.ID]memoryDeliveryBatch
}

type memoryDeliveryEpoch struct {
	sequences map[uint64]memoryDeliverySequence
}

type memoryDeliverySequence struct {
	eventID     shared.ID
	eventDigest string
	deliveryKey string
	batchID     shared.ID
}

type memoryDeliveryBatch struct {
	manifest fleetagent.TelemetryBatchManifest
	state    ports.TelemetryBatchState
}

// IngestDelivery atomically persists a verified A3 batch, its canonical/schema
// provenance, sequence ledger, explicit gaps, and highest-contiguous ACK.
func (s *TelemetryStore) IngestDelivery(ctx context.Context, batch ports.TelemetryDeliveryBatch) (ports.TelemetryDeliveryResult, error) {
	if err := batch.Validate(); err != nil {
		return ports.TelemetryDeliveryResult{}, err
	}
	tenant, err := requireTelemetryTenant(ctx)
	if err != nil {
		return ports.TelemetryDeliveryResult{}, err
	}
	if tenant != batch.TenantID {
		return ports.TelemetryDeliveryResult{}, fmt.Errorf("%w: telemetry delivery tenant disagrees with context", shared.ErrForbidden)
	}
	m := batch.Manifest
	wantStream, err := fleetagent.TelemetryDeliveryStreamID(batch.AgentID, batch.AgentSessionID, m.Priority)
	if err != nil {
		return ports.TelemetryDeliveryResult{}, err
	}
	if m.StreamID != wantStream {
		return ports.TelemetryDeliveryResult{}, fmt.Errorf("%w: telemetry delivery stream is not canonical", shared.ErrValidation)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.delivery[tenant] == nil {
		s.delivery[tenant] = map[string]*memoryDeliveryLane{}
	}
	laneKey := m.StreamID.String()
	lane := s.delivery[tenant][laneKey]
	if lane == nil {
		lane = &memoryDeliveryLane{epochs: map[uint64]*memoryDeliveryEpoch{}, batches: map[shared.ID]memoryDeliveryBatch{}}
		s.delivery[tenant][laneKey] = lane
	}
	epoch := lane.epochs[m.Epoch]
	if epoch == nil {
		epoch = &memoryDeliveryEpoch{sequences: map[uint64]memoryDeliverySequence{}}
		lane.epochs[m.Epoch] = epoch
	}

	from := m.PreviousSequence + 1
	// Preflight every occupied sequence before mutating anything. A retry with the
	// same event commitment is a no-op even if batching boundaries changed; a
	// different event at an occupied delivery coordinate is a hard conflict.
	allDuplicate := true
	for i := range batch.Envelopes {
		seq := from + uint64(i)
		key, kerr := fleetagent.TelemetryDeliveryKey(batch.AgentID, batch.AgentSessionID, m.StreamID, m.Priority, m.Epoch, seq, 0)
		if kerr != nil {
			return ports.TelemetryDeliveryResult{}, kerr
		}
		if existing, ok := epoch.sequences[seq]; ok {
			if existing.eventID != m.EventIDs[i] || existing.eventDigest != m.EventDigests[i] || existing.deliveryKey != key {
				return ports.TelemetryDeliveryResult{}, fmt.Errorf("%w: telemetry delivery sequence %d is already committed to different content", shared.ErrConflict, seq)
			}
			continue
		}
		allDuplicate = false
	}
	if m.Epoch < lane.maxEpoch && !allDuplicate {
		return ports.TelemetryDeliveryResult{}, fmt.Errorf("%w: telemetry delivery epoch %d is stale; current epoch is %d", shared.ErrConflict, m.Epoch, lane.maxEpoch)
	}
	if m.Epoch > lane.maxEpoch {
		lane.maxEpoch = m.Epoch
	}

	newEvents := 0
	for i := range batch.Envelopes {
		seq := from + uint64(i)
		if _, ok := epoch.sequences[seq]; ok {
			continue
		}
		key, _ := fleetagent.TelemetryDeliveryKey(batch.AgentID, batch.AgentSessionID, m.StreamID, m.Priority, m.Epoch, seq, 0)
		epoch.sequences[seq] = memoryDeliverySequence{
			eventID: m.EventIDs[i], eventDigest: m.EventDigests[i], deliveryKey: key, batchID: m.BatchID,
		}
		canonical := batch.Envelopes[i].Clone()
		s.rows[tenant] = append(s.rows[tenant], telemetryRow{
			host: batch.HostID, asset: batch.AssetID, agent: batch.AgentID,
			class: batch.Envelopes[i].EventClass, seq: seq, idx: 0, sampleRate: 1,
			event: batch.ProjectedEvents[i], delivery: true, schemaVersion: m.SchemaVersion,
			deliveryKey: key, deliveryStream: m.StreamID, epoch: m.Epoch, canonical: &canonical,
		})
		newEvents++
	}

	ack := highestMemoryContiguous(epoch.sequences)
	state := ports.TelemetryStateDurable
	if m.Sequence <= ack {
		state = ports.TelemetryStateAcknowledged
	}
	lane.batches[m.BatchID] = memoryDeliveryBatch{manifest: m, state: state}
	currentGaps := s.reconcileMemoryDeliveryGapsLocked(tenant, batch, epoch.sequences, batch.ReceivedAt)

	return ports.TelemetryDeliveryResult{
		ACK: ports.TelemetryDeliveryACK{Priority: m.Priority, Epoch: m.Epoch, Through: ack},
		NewEvents: newEvents,
		Gaps: append([]ports.TelemetryGap(nil), currentGaps...),
	}, nil
}

func highestMemoryContiguous(sequences map[uint64]memoryDeliverySequence) uint64 {
	var through uint64
	for {
		if _, ok := sequences[through+1]; !ok {
			return through
		}
		through++
	}
}

func memoryMissingRanges(sequences map[uint64]memoryDeliverySequence) []fleetagent.SeqRange {
	if len(sequences) == 0 {
		return nil
	}
	seqs := make([]uint64, 0, len(sequences))
	for seq := range sequences {
		seqs = append(seqs, seq)
	}
	sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })
	var out []fleetagent.SeqRange
	var previous uint64
	for _, seq := range seqs {
		if seq > previous+1 {
			out = append(out, fleetagent.SeqRange{From: previous + 1, To: seq - 1})
		}
		previous = seq
	}
	return out
}

func (s *TelemetryStore) reconcileMemoryDeliveryGapsLocked(tenant shared.ID, batch ports.TelemetryDeliveryBatch, sequences map[uint64]memoryDeliverySequence, now time.Time) []ports.TelemetryGap {
	m := batch.Manifest
	ranges := memoryMissingRanges(sequences)
	wanted := make(map[string]fleetagent.SeqRange, len(ranges))
	for _, r := range ranges {
		wanted[gapRangeKey(r.From, r.To)] = r
	}
	for i := range s.deliveryGaps[tenant] {
		g := &s.deliveryGaps[tenant][i]
		if g.StreamID != m.StreamID || g.Epoch != m.Epoch || g.ResolvedAt != nil {
			continue
		}
		key := gapRangeKey(g.FromSequence, g.ToSequence)
		if _, stillMissing := wanted[key]; stillMissing {
			delete(wanted, key)
			continue
		}
		resolved := now.UTC()
		g.ResolvedAt = &resolved
	}
	for _, r := range wanted {
		gap := ports.TelemetryGap{
			TenantID: batch.TenantID, HostID: batch.HostID, AssetID: batch.AssetID, AgentID: batch.AgentID,
			AgentSessionID: batch.AgentSessionID, StreamID: m.StreamID, Priority: m.Priority, Epoch: m.Epoch,
			FromSequence: r.From, ToSequence: r.To, FromAt: m.EventTimeMin.UTC(), ToAt: m.EventTimeMax.UTC(), DetectedAt: now.UTC(),
		}
		if gap.Validate() == nil {
			s.deliveryGaps[tenant] = append(s.deliveryGaps[tenant], gap)
		}
	}
	return currentMemoryGaps(s.deliveryGaps[tenant], m.StreamID, m.Epoch)
}

func currentMemoryGaps(gaps []ports.TelemetryGap, stream shared.ID, epoch uint64) []ports.TelemetryGap {
	out := make([]ports.TelemetryGap, 0)
	for _, gap := range gaps {
		if gap.StreamID == stream && gap.Epoch == epoch && gap.ResolvedAt == nil {
			out = append(out, gap)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].FromSequence < out[j].FromSequence })
	return out
}

func gapRangeKey(from, to uint64) string {
	return strconv.FormatUint(from, 10) + ":" + strconv.FormatUint(to, 10)
}

// QueryDeliveryGaps returns persisted gaps that intersect the hunt. Resolved gaps remain
// durable provenance but are not current incompleteness, so they are not returned here.
func (s *TelemetryStore) QueryDeliveryGaps(ctx context.Context, q ports.HuntQuery) ([]ports.TelemetryGap, error) {
	tenant, err := requireTelemetryTenant(ctx)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []ports.TelemetryGap
	for _, gap := range s.deliveryGaps[tenant] {
		if gap.ResolvedAt == nil && matchesDeliveryGapQuery(gap, q) {
			out = append(out, gap)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Epoch == out[j].Epoch {
			return out[i].FromSequence < out[j].FromSequence
		}
		return out[i].Epoch < out[j].Epoch
	})
	return out, nil
}

func matchesDeliveryGapQuery(g ports.TelemetryGap, q ports.HuntQuery) bool {
	if q.HostID != "" && g.HostID != q.HostID {
		return false
	}
	if q.AssetID != "" && g.AssetID != q.AssetID {
		return false
	}
	if q.Class != "" {
		priority, err := fleetagent.TelemetryPriority(q.Class)
		if err != nil || priority != g.Priority {
			return false
		}
	}
	if !q.Since.IsZero() && g.ToAt.Before(q.Since) {
		return false
	}
	if !q.Until.IsZero() && g.FromAt.After(q.Until) {
		return false
	}
	return true
}

// BindTelemetryAsset records the authoritative agent→asset reconciliation result.
// A stale write cannot roll a newer binding backwards.
func (s *TelemetryStore) BindTelemetryAsset(ctx context.Context, binding ports.TelemetryAssetBinding) error {
	tenant, err := requireTelemetryTenant(ctx)
	if err != nil {
		return err
	}
	if binding.TenantID.IsZero() || binding.AgentID.IsZero() || binding.AssetID.IsZero() || binding.UpdatedAt.IsZero() {
		return fmt.Errorf("%w: telemetry asset binding is incomplete", shared.ErrValidation)
	}
	if binding.TenantID != tenant {
		return fmt.Errorf("%w: telemetry asset binding tenant disagrees with context", shared.ErrForbidden)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.bindings[tenant] == nil {
		s.bindings[tenant] = map[shared.ID]ports.TelemetryAssetBinding{}
	}
	if current, ok := s.bindings[tenant][binding.AgentID]; ok && binding.UpdatedAt.Before(current.UpdatedAt) {
		return fmt.Errorf("%w: stale telemetry asset binding update", shared.ErrConflict)
	}
	s.bindings[tenant][binding.AgentID] = binding
	return nil
}

func (s *TelemetryStore) ResolveTelemetryAsset(ctx context.Context, agentID shared.ID) (shared.ID, error) {
	tenant, err := requireTelemetryTenant(ctx)
	if err != nil {
		return "", err
	}
	if agentID.IsZero() {
		return "", fmt.Errorf("%w: telemetry asset resolution requires agent id", shared.ErrValidation)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	binding, ok := s.bindings[tenant][agentID]
	if !ok || binding.AssetID.IsZero() {
		return "", shared.ErrNotFound
	}
	return binding.AssetID, nil
}

var _ = errors.Is // keep errors available for parity with the Postgres implementation tests.
