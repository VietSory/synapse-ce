package fleetagent

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// TelemetryDeliveryStreamID derives the server-verifiable identity of one A2 telemetry
// delivery lane. A2 sequence/Epoch coordinates are per priority lane, while an individual
// TelemetryEnvelope.StreamID identifies its sensor/class provenance; the two are deliberately
// distinct. Binding the lane to agent + enrollment session + priority prevents a producer from
// choosing an arbitrary stream namespace to evade ACK/replay state.
func TelemetryDeliveryStreamID(agentID shared.ID, session SessionID, priority DeliveryPriority) (shared.ID, error) {
	if agentID.IsZero() || session == "" {
		return "", fmt.Errorf("%w: telemetry delivery stream needs agent and session identity", shared.ErrValidation)
	}
	if !priority.Valid() {
		return "", fmt.Errorf("%w: unknown telemetry delivery priority %d", shared.ErrValidation, int(priority))
	}
	h := sha256.New()
	writeTelemetryStreamField := func(value string) {
		_, _ = h.Write([]byte(strconv.Itoa(len(value))))
		_, _ = h.Write([]byte{':'})
		_, _ = h.Write([]byte(value))
	}
	writeTelemetryStreamField("synapse-telemetry-delivery-stream:v1")
	writeTelemetryStreamField(agentID.String())
	writeTelemetryStreamField(string(session))
	writeTelemetryStreamField(strconv.Itoa(int(priority)))
	sum := h.Sum(nil)
	return shared.ID("tds_" + hex.EncodeToString(sum[:16])), nil
}
