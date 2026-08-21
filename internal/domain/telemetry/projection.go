package telemetry

import (
	"fmt"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// ToDetectionEvent projects the richer canonical telemetry envelope onto the deliberately smaller
// detection.Event matcher shape. Raw storage/evidence stays on TelemetryEnvelope; this compatibility
// projection exists so the pre-A3 retro-hunt/rule matcher can consume live transported telemetry while
// the detection pillar migrates independently.
func (e TelemetryEnvelope) ToDetectionEvent(hostID shared.ID) (detection.Event, error) {
	if err := e.Validate(); err != nil {
		return detection.Event{}, err
	}
	if hostID.IsZero() {
		return detection.Event{}, fmt.Errorf("%w: telemetry projection requires authoritative host id", shared.ErrValidation)
	}
	out := detection.Event{Class: e.EventClass, At: e.OccurredAt.UTC(), Host: hostID}
	switch e.EventClass {
	case detection.ClassProcess:
		p := e.Event.Process
		out.Process = &detection.ProcessEvent{PID: p.PID, PPID: p.PPID, Comm: p.Comm, Path: p.Path, Args: append([]string(nil), p.Args...), UID: p.UID}
	case detection.ClassNetwork:
		n := e.Event.Network
		out.Network = &detection.NetworkEvent{Proto: n.Proto, RemoteAddr: n.RemoteAddr, RemotePort: n.RemotePort, Direction: n.Direction, PID: n.PID, Comm: n.Comm}
	case detection.ClassFile:
		f := e.Event.File
		out.File = &detection.FileEvent{Path: f.Path, Op: f.Op, PID: f.PID, Comm: f.Comm}
	case detection.ClassPrivilege:
		p := e.Event.Privilege
		out.Privilege = &detection.PrivilegeEvent{PID: p.PID, Comm: p.Comm, FromUID: p.FromUID, ToUID: p.ToUID, Cap: p.Cap, Kind: p.Kind}
	default:
		return detection.Event{}, fmt.Errorf("%w: telemetry projection has unsupported class %q", shared.ErrValidation, e.EventClass)
	}
	if err := out.Validate(); err != nil {
		return detection.Event{}, err
	}
	return out, nil
}
