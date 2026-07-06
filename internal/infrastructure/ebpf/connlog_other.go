//go:build !linux

// Package ebpf degrades to a no-op off Linux: the eBPF connect-logger needs cgroup
// v2 + cgroup-bpf, which only exist on Linux. Start returns ErrUnavailable and the caller
// runs without a connect-log (it is observability, never a gate).
package ebpf

import (
	"errors"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// ErrUnavailable means the eBPF connect-logger cannot run here (Linux only).
var ErrUnavailable = errors.New("ebpf connect-logger unavailable: Linux only")

// Monitor is the off-Linux stub.
type Monitor struct{}

// NewMonitor returns a stub monitor.
func NewMonitor() *Monitor { return &Monitor{} }

// Session is the off-Linux stub.
type Session struct{}

// Start always fails off Linux.
func (m *Monitor) Start(string) (*Session, error) { return nil, ErrUnavailable }

// Attach always fails off Linux.
func (m *Monitor) Attach(string) (*Session, error) { return nil, ErrUnavailable }

// CgroupFD is meaningless off Linux.
func (s *Session) CgroupFD() int { return -1 }

// Close returns no events off Linux.
func (s *Session) Close() []ports.ConnEvent { return nil }
