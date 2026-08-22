package memory

import (
	"context"
	"fmt"
	"sort"
	"sync"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// TelemetryTransportStore is the in-memory twin of the A3 transport-sequencing store: per-stream ACK
// state (with an optimistic-concurrency version), durable raw batch events, per-sequence batch commitments,
// authoritative agent->asset bindings, and a materialized current-gap view. The ACK snapshot remains the
// source of truth; gaps are reconciled when that snapshot changes so a filled hole cannot linger as a phantom.
type TelemetryTransportStore struct {
	mu       sync.Mutex
	states   map[shared.ID]map[streamEpoch]ports.TelemetryStreamState
	commits  map[shared.ID]map[batchKey]storedBatchCommit
	events   map[shared.ID]map[eventKey]storedTransportEvent
	gaps     map[shared.ID]map[streamEpoch][]ports.TelemetryGap
	bindings map[shared.ID]map[shared.ID]ports.TelemetryAssetBinding
}

// streamEpoch and eventKey carry agent so an agent-chosen StreamID can never address another agent's
// stream space within the tenant (see migration 0109).
type streamEpoch struct {
	agent  shared.ID
	stream shared.ID
	epoch  uint64
}

type batchKey struct {
	agent    shared.ID
	stream   shared.ID
	epoch    uint64
	sequence uint64
}

type eventKey struct {
	agent    shared.ID
	stream   shared.ID
	epoch    uint64
	sequence uint64
	eventID  shared.ID
}

type storedBatchCommit struct {
	batchID       shared.ID
	payloadDigest string
	asset         shared.ID
	schemaVersion int
	eventCount    int
}

type storedTransportEvent struct {
	asset         shared.ID
	class         string
	digest        string
	payload       []byte
	schemaVersion int
}

var _ ports.TelemetryTransportStore = (*TelemetryTransportStore)(nil)
var _ ports.TelemetryAssetBindingStore = (*TelemetryTransportStore)(nil)

// NewTelemetryTransportStore constructs an empty in-memory transport store.
func NewTelemetryTransportStore() *TelemetryTransportStore {
	return &TelemetryTransportStore{
		states:   map[shared.ID]map[streamEpoch]ports.TelemetryStreamState{},
		commits:  map[shared.ID]map[batchKey]storedBatchCommit{},
		events:   map[shared.ID]map[eventKey]storedTransportEvent{},
		gaps:     map[shared.ID]map[streamEpoch][]ports.TelemetryGap{},
		bindings: map[shared.ID]map[shared.ID]ports.TelemetryAssetBinding{},
	}
}

func (s *TelemetryTransportStore) StreamState(ctx context.Context, agentID, streamID shared.ID, epoch uint64) (ports.TelemetryStreamState, error) {
	tenant, err := requireTelemetryTenant(ctx)
	if err != nil {
		return ports.TelemetryStreamState{}, err
	}
	if agentID.IsZero() || streamID.IsZero() || epoch == 0 {
		return ports.TelemetryStreamState{}, shared.ErrValidation
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if st, ok := s.states[tenant][streamEpoch{agentID, streamID, epoch}]; ok {
		return cloneStreamState(st), nil
	}
	return ports.TelemetryStreamState{AgentID: agentID, StreamID: streamID, Epoch: epoch}, nil
}

func (s *TelemetryTransportStore) SaveStreamState(ctx context.Context, state ports.TelemetryStreamState) error {
	if err := state.Validate(); err != nil {
		return err
	}
	tenant, err := requireTelemetryTenant(ctx)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.states[tenant] == nil {
		s.states[tenant] = map[streamEpoch]ports.TelemetryStreamState{}
	}
	if s.gaps[tenant] == nil {
		s.gaps[tenant] = map[streamEpoch][]ports.TelemetryGap{}
	}
	key := streamEpoch{state.AgentID, state.StreamID, state.Epoch}
	if cur, ok := s.states[tenant][key]; ok {
		if cur.Version != state.Version {
			return shared.ErrConflict
		}
	} else if state.Version != 0 {
		return shared.ErrConflict
	}
	next := cloneStreamState(state)
	next.Version = state.Version + 1
	s.states[tenant][key] = next
	// Materialize after the CAS succeeds. In memory this is the queryable twin of
	// the Postgres gap table; the state snapshot remains authoritative.
	s.gaps[tenant][key] = append([]ports.TelemetryGap(nil), next.GapsFrom()...)
	return nil
}

func (s *TelemetryTransportStore) MaxEpoch(ctx context.Context, agentID, streamID shared.ID) (uint64, error) {
	tenant, err := requireTelemetryTenant(ctx)
	if err != nil {
		return 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var highest uint64
	for key := range s.states[tenant] {
		if key.agent == agentID && key.stream == streamID && key.epoch > highest {
			highest = key.epoch
		}
	}
	return highest, nil
}

func (s *TelemetryTransportStore) ListGaps(ctx context.Context, agentID, streamID shared.ID) ([]ports.TelemetryGap, error) {
	tenant, err := requireTelemetryTenant(ctx)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []ports.TelemetryGap
	for key, materialized := range s.gaps[tenant] {
		if key.agent == agentID && key.stream == streamID {
			out = append(out, materialized...)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Epoch != out[j].Epoch {
			return out[i].Epoch < out[j].Epoch
		}
		return out[i].FromSequence < out[j].FromSequence
	})
	return out, nil
}

func (s *TelemetryTransportStore) IngestBatchEvents(ctx context.Context, batch ports.TelemetryEventBatch) (int, error) {
	if err := batch.Validate(); err != nil {
		return 0, err
	}
	tenant, err := requireTelemetryTenant(ctx)
	if err != nil {
		return 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.commits[tenant] == nil {
		s.commits[tenant] = map[batchKey]storedBatchCommit{}
	}
	if s.events[tenant] == nil {
		s.events[tenant] = map[eventKey]storedTransportEvent{}
	}

	coord := batchKey{batch.AgentID, batch.StreamID, batch.Epoch, batch.Sequence}
	wantCommit := storedBatchCommit{
		batchID: batch.BatchID, payloadDigest: batch.PayloadDigest, asset: batch.AssetID,
		schemaVersion: batch.SchemaVersion, eventCount: len(batch.Events),
	}
	if existing, ok := s.commits[tenant][coord]; ok && existing != wantCommit {
		return 0, fmt.Errorf("%w: telemetry delivery sequence is already committed to a different batch", shared.ErrConflict)
	}

	// Validate every event collision before mutating either the commitment or event map. This keeps the
	// in-memory implementation transaction-like: a conflicting replay cannot leave a partial new batch.
	stored := 0
	for _, e := range batch.Events {
		key := eventKey{batch.AgentID, batch.StreamID, batch.Epoch, batch.Sequence, e.EventID}
		if existing, exists := s.events[tenant][key]; exists {
			if existing.asset != batch.AssetID || existing.class != string(e.Class) || existing.digest != e.Digest || existing.schemaVersion != batch.SchemaVersion || string(existing.payload) != string(e.Payload) {
				return 0, fmt.Errorf("%w: telemetry event coordinate is already committed to different content", shared.ErrConflict)
			}
			continue
		}
		stored++
	}
	if _, ok := s.commits[tenant][coord]; !ok {
		s.commits[tenant][coord] = wantCommit
	}
	for _, e := range batch.Events {
		key := eventKey{batch.AgentID, batch.StreamID, batch.Epoch, batch.Sequence, e.EventID}
		if _, exists := s.events[tenant][key]; exists {
			continue
		}
		s.events[tenant][key] = storedTransportEvent{
			asset: batch.AssetID, class: string(e.Class),
			digest: e.Digest, payload: append([]byte(nil), e.Payload...), schemaVersion: batch.SchemaVersion,
		}
	}
	return stored, nil
}

func (s *TelemetryTransportStore) CountBatchEvents(ctx context.Context, agentID, streamID shared.ID, epoch, sequence uint64) (int, error) {
	tenant, err := requireTelemetryTenant(ctx)
	if err != nil {
		return 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for key := range s.events[tenant] {
		if key.agent == agentID && key.stream == streamID && key.epoch == epoch && key.sequence == sequence {
			n++
		}
	}
	return n, nil
}

func (s *TelemetryTransportStore) BindTelemetryAsset(ctx context.Context, binding ports.TelemetryAssetBinding) error {
	if err := binding.Validate(); err != nil {
		return err
	}
	tenant, err := requireTelemetryTenant(ctx)
	if err != nil {
		return err
	}
	if tenant != binding.TenantID {
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

func (s *TelemetryTransportStore) ResolveTelemetryAsset(ctx context.Context, agentID shared.ID) (shared.ID, error) {
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

func cloneStreamState(s ports.TelemetryStreamState) ports.TelemetryStreamState {
	c := s
	c.Pending = append([]uint64(nil), s.Pending...)
	return c
}
