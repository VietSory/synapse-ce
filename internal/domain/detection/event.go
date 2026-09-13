package detection

import (
	"fmt"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// Event is one observed host activity, typed by Class. Exactly one of the per-class payloads is set —
// the one matching Class. The payloads are deliberately small and bounded: milestone one ships a
// detection plus a bounded window of these, never the raw stream.
//
// Fields are TYPED, not a free-form map, so a rule matches over a closed, known set (see Field). That is
// what keeps a rule from being an arbitrary expression over untrusted keys.
type Event struct {
	Class Class
	At    time.Time
	Host  shared.ID

	Process   *ProcessEvent
	Network   *NetworkEvent
	File      *FileEvent
	Privilege *PrivilegeEvent
}

// ProcessEvent is an exec/fork observation.
type ProcessEvent struct {
	Kind                 string // exec | fork | exit; empty means legacy exec
	PID                  int
	PPID                 int
	StartTimeNanos       uint64
	ParentStartTimeNanos uint64
	Comm                 string   // short command name (kernel comm)
	Path                 string   // resolved executable path
	Args                 []string // bounded argv
	UID                  int
}

// NetworkEvent is a connect observation.
type NetworkEvent struct {
	Proto      string // tcp | udp
	RemoteAddr string
	RemotePort int
	Direction  string // egress | ingress
	PID        int
	Comm       string
}

// FileEvent is a sensitive-path access observation.
type FileEvent struct {
	Path string
	Op   string // read | write | open | unlink
	PID  int
	Comm string
}

// PrivilegeEvent is a privilege/capability change observation.
type PrivilegeEvent struct {
	PID     int
	Comm    string
	FromUID int
	ToUID   int
	Cap     string // capability gained, if any
	Kind    string // setuid | setgid | capset
}

// RuntimeEvidenceKind names a POSITIVE observation relevant to vulnerability reachability. Runtime
// evidence is deliberately not another detection Class: it never participates in the blue-team rule
// matcher, and it has no negative/unreachable state. If the runtime sensor cannot observe something it
// emits nothing, so an observation gap can never be mistaken for proof that vulnerable code did not run.
type RuntimeEvidenceKind string

const (
	RuntimeEvidenceBinaryExec    RuntimeEvidenceKind = "binary_exec"
	RuntimeEvidenceLibraryLoaded RuntimeEvidenceKind = "library_loaded"
	RuntimeEvidenceSymbolHit     RuntimeEvidenceKind = "symbol_hit"
)

// Valid reports whether k is one of the three positive runtime reachability evidence kinds.
func (k RuntimeEvidenceKind) Valid() bool {
	switch k {
	case RuntimeEvidenceBinaryExec, RuntimeEvidenceLibraryLoaded, RuntimeEvidenceSymbolHit:
		return true
	default:
		return false
	}
}

// RuntimeEvidence is one positive runtime observation. Path is the concrete executable/shared-object
// path as seen through the observed process, while Device+Inode pin the underlying file identity so the
// package-ownership join in #1061 never has to trust a bare path string. Symbol is present only for a
// symbol_hit; library_loaded must never be promoted to the stronger symbol_hit meaning.
//
// Deleted records represent a still-mapped executable/object whose pathname has been unlinked. They
// retain Device+Inode identity for later package-ownership disambiguation.
type RuntimeEvidence struct {
	Kind    RuntimeEvidenceKind
	At      time.Time
	Host    shared.ID
	PID     int
	UID     int
	Comm    string
	Path    string
	Symbol  string
	Device  uint64
	Inode   uint64
	Deleted bool
}

// Validate rejects ambiguous or identity-free runtime evidence. There is intentionally no validation
// path for an absence/negative result: the runtime track is raise-only by construction.
func (e RuntimeEvidence) Validate() error {
	if !e.Kind.Valid() {
		return fmt.Errorf("%w: runtime evidence has unknown kind %q", shared.ErrValidation, e.Kind)
	}
	if e.At.IsZero() {
		return fmt.Errorf("%w: runtime evidence %s has no timestamp", shared.ErrValidation, e.Kind)
	}
	if e.Host.IsZero() {
		return fmt.Errorf("%w: runtime evidence %s has no host", shared.ErrValidation, e.Kind)
	}
	if e.PID <= 0 {
		return fmt.Errorf("%w: runtime evidence %s has non-positive pid %d", shared.ErrValidation, e.Kind, e.PID)
	}
	if e.Path == "" {
		return fmt.Errorf("%w: runtime evidence %s has no path", shared.ErrValidation, e.Kind)
	}
	if e.Inode == 0 {
		return fmt.Errorf("%w: runtime evidence %s has no inode identity", shared.ErrValidation, e.Kind)
	}
	if e.Kind == RuntimeEvidenceSymbolHit {
		if e.Symbol == "" {
			return fmt.Errorf("%w: symbol_hit runtime evidence has no symbol", shared.ErrValidation)
		}
	} else if e.Symbol != "" {
		return fmt.Errorf("%w: runtime evidence %s must not carry a symbol", shared.ErrValidation, e.Kind)
	}
	return nil
}

// payloadClass reports which class actually carries a payload, and whether exactly one does. An event
// whose payload does not match its Class (or sets none/several) cannot be matched and is rejected by
// Validate — a malformed event must never silently match or silently miss.
func (e Event) payloadClass() (Class, bool) {
	set := make([]Class, 0, 1)
	if e.Process != nil {
		set = append(set, ClassProcess)
	}
	if e.Network != nil {
		set = append(set, ClassNetwork)
	}
	if e.File != nil {
		set = append(set, ClassFile)
	}
	if e.Privilege != nil {
		set = append(set, ClassPrivilege)
	}
	if len(set) != 1 {
		return "", false
	}
	return set[0], true
}

// Validate enforces that an event is well-formed: a known class, a non-zero timestamp, and exactly the
// one payload its class names.
func (e Event) Validate() error {
	if !e.Class.Valid() {
		return fmt.Errorf("%w: event has an unknown class %q", shared.ErrValidation, e.Class)
	}
	if e.At.IsZero() {
		return fmt.Errorf("%w: event of class %s has no timestamp", shared.ErrValidation, e.Class)
	}
	pc, ok := e.payloadClass()
	if !ok || pc != e.Class {
		return fmt.Errorf("%w: event of class %s must carry exactly its own payload", shared.ErrValidation, e.Class)
	}
	return nil
}

// clone returns a deep copy of the event: the per-class payload pointers and the argv slice are copied,
// not aliased, so a detection that sealed this event as evidence cannot be mutated by a caller (or a
// sensor pooling/reusing event structs) touching the original afterwards. Evidence that can change after
// it is sealed is not evidence.
func (e Event) clone() Event {
	c := e
	if e.Process != nil {
		p := *e.Process
		p.Args = append([]string(nil), e.Process.Args...)
		c.Process = &p
	}
	if e.Network != nil {
		n := *e.Network
		c.Network = &n
	}
	if e.File != nil {
		f := *e.File
		c.File = &f
	}
	if e.Privilege != nil {
		pr := *e.Privilege
		c.Privilege = &pr
	}
	return c
}

// stringField returns the string form of a known field, and whether the field applies to this event's
// class. An unknown field, or a field belonging to another class, returns ok=false — never a zero value
// that could accidentally match.
func (e Event) stringField(f Field) (string, bool) {
	switch f {
	case FieldProcComm:
		if e.Process != nil {
			return e.Process.Comm, true
		}
	case FieldProcPath:
		if e.Process != nil {
			return e.Process.Path, true
		}
	case FieldNetProto:
		if e.Network != nil {
			return e.Network.Proto, true
		}
	case FieldNetRemoteAddr:
		if e.Network != nil {
			return e.Network.RemoteAddr, true
		}
	case FieldNetDirection:
		if e.Network != nil {
			return e.Network.Direction, true
		}
	case FieldFilePath:
		if e.File != nil {
			return e.File.Path, true
		}
	case FieldFileOp:
		if e.File != nil {
			return e.File.Op, true
		}
	case FieldFileComm:
		if e.File != nil {
			return e.File.Comm, true
		}
	case FieldPrivComm:
		if e.Privilege != nil {
			return e.Privilege.Comm, true
		}
	case FieldPrivCap:
		if e.Privilege != nil {
			return e.Privilege.Cap, true
		}
	case FieldPrivKind:
		if e.Privilege != nil {
			return e.Privilege.Kind, true
		}
	}
	return "", false
}

// stringFields returns every string value a field can take on this event. It exists for the one
// repeated field, a process's argv: a predicate over FieldProcArg matches if ANY arg satisfies it, so a
// scalar accessor would miss.
func (e Event) stringFields(f Field) ([]string, bool) {
	if f == FieldProcArg {
		if e.Process != nil {
			return e.Process.Args, true
		}
		return nil, false
	}
	if v, ok := e.stringField(f); ok {
		return []string{v}, true
	}
	return nil, false
}

// intField returns the integer form of a known numeric field, and whether it applies to this class.
func (e Event) intField(f Field) (int, bool) {
	switch f {
	case FieldProcUID:
		if e.Process != nil {
			return e.Process.UID, true
		}
	case FieldNetRemotePort:
		if e.Network != nil {
			return e.Network.RemotePort, true
		}
	case FieldPrivToUID:
		if e.Privilege != nil {
			return e.Privilege.ToUID, true
		}
	}
	return 0, false
}
