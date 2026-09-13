//go:build linux

package ebpf

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
)

type rawRuntimeSymbol struct {
	Ktime uint64
	PID   uint32
	UID   uint32
	Comm  [16]byte
}

// SymbolHitSensor observes one exact uprobe target. The opened target FD stays live for the
// sensor lifetime, and Device+Inode are captured from that FD before attachment. Path is only
// the attach-time label; stable identity is authoritative if the pathname is later replaced.
type SymbolHitSensor struct {
	mu        sync.Mutex
	probe     RuntimeSymbolProbe
	events    chan detection.RuntimeEvidence
	closeDone chan struct{}
	started   bool
	closed    bool

	file   *os.File
	device uint64
	inode  uint64
	coll   *ebpf.Collection
	lnk    link.Link
	rd     *ringbuf.Reader
	epoch  time.Time
	wg     sync.WaitGroup
}

func NewSymbolHitSensor(raw RuntimeSymbolProbe) (*SymbolHitSensor, error) {
	probe, err := raw.validate()
	if err != nil {
		return nil, err
	}
	return &SymbolHitSensor{
		probe: probe, events: make(chan detection.RuntimeEvidence, 1024), closeDone: make(chan struct{}),
	}, nil
}

// Start pins the target by FD and attaches exactly one uprobe. Setup is serialized with Close,
// so a concurrent shutdown can never close the event channel underneath a late-started drain.
func (s *SymbolHitSensor) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return fmt.Errorf("%w: sensor already closed", ErrSymbolHitUnavailable)
	}
	if s.started {
		return fmt.Errorf("%w: sensor already started", ErrSymbolHitUnavailable)
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("%w: %v", ErrSymbolHitUnavailable, err)
	}
	if embeddedObjectArch == "" {
		return fmt.Errorf("%w: no architecture-matched object for linux/%s", ErrSymbolHitUnavailable, runtime.GOARCH)
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("%w: memlock: %v", ErrSymbolHitUnavailable, err)
	}

	file, err := os.Open(s.probe.Path)
	if err != nil {
		return fmt.Errorf("%w: open target %s: %v", ErrSymbolHitUnavailable, s.probe.Path, err)
	}
	cleanupFile := true
	defer func() {
		if cleanupFile {
			_ = file.Close()
		}
	}()
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("%w: stat target %s: %v", ErrSymbolHitUnavailable, s.probe.Path, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%w: target %s is not a regular file", ErrSymbolHitUnavailable, s.probe.Path)
	}
	device, inode, ok := symbolFileIdentity(info)
	if !ok || inode == 0 {
		return fmt.Errorf("%w: target %s has no stable file identity", ErrSymbolHitUnavailable, s.probe.Path)
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(symbolObj))
	if err != nil {
		return fmt.Errorf("%w: load symbol spec: %v", ErrSymbolHitUnavailable, err)
	}
	if spec.Programs["runtime_symbol_hit"] == nil || spec.Maps["runtime_symbol_events"] == nil {
		return fmt.Errorf("%w: symbol object is missing required program/map", ErrSymbolHitUnavailable)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("%w: load symbol program: %v", ErrSymbolHitUnavailable, err)
	}
	cleanupColl := true
	defer func() {
		if cleanupColl {
			coll.Close()
		}
	}()

	pinnedPath := filepath.Join("/proc/self/fd", strconv.Itoa(int(file.Fd())))
	executable, err := link.OpenExecutable(pinnedPath)
	if err != nil {
		return fmt.Errorf("%w: open pinned uprobe target: %v", ErrSymbolHitUnavailable, err)
	}
	s.epoch = captureKtimeEpoch()
	lnk, err := executable.Uprobe(s.probe.Symbol, coll.Programs["runtime_symbol_hit"], &link.UprobeOptions{PID: s.probe.PID})
	if err != nil {
		return fmt.Errorf("%w: attach %s:%s: %v", ErrSymbolHitUnavailable, s.probe.Path, s.probe.Symbol, err)
	}
	cleanupLink := true
	defer func() {
		if cleanupLink {
			_ = lnk.Close()
		}
	}()
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("%w: %v", ErrSymbolHitUnavailable, err)
	}
	rd, err := ringbuf.NewReader(coll.Maps["runtime_symbol_events"])
	if err != nil {
		return fmt.Errorf("%w: symbol ring buffer: %v", ErrSymbolHitUnavailable, err)
	}

	s.file, s.device, s.inode = file, device, inode
	s.coll, s.lnk, s.rd = coll, lnk, rd
	s.started = true
	cleanupFile, cleanupColl, cleanupLink = false, false, false
	s.wg.Add(1)
	go s.drain()
	return nil
}

func (s *SymbolHitSensor) drain() {
	defer s.wg.Done()
	for {
		rec, err := s.rd.Read()
		if err != nil {
			return
		}
		var raw rawRuntimeSymbol
		if binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &raw) != nil {
			continue
		}
		ev := detection.RuntimeEvidence{
			Kind: detection.RuntimeEvidenceSymbolHit,
			At:   kernelOccurredAt(s.epoch, raw.Ktime), PID: raw.PID, UID: raw.UID,
			Comm: cstr(raw.Comm[:]), Path: s.probe.Path, Symbol: s.probe.Symbol,
			Device: s.device, Inode: s.inode,
		}
		if ev.Validate() != nil {
			continue
		}
		select {
		case s.events <- ev:
		default:
			// Raise-only: losing a positive event can only forgo an urgency raise. It can never
			// become a negative/not_reachable claim.
		}
	}
}

func symbolFileIdentity(info os.FileInfo) (device, inode uint64, ok bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat == nil {
		return 0, 0, false
	}
	return uint64(stat.Dev), uint64(stat.Ino), true
}

func (s *SymbolHitSensor) Events() <-chan detection.RuntimeEvidence { return s.events }

// Close is synchronous and idempotent. Concurrent callers wait for the first close to finish.
func (s *SymbolHitSensor) Close() error {
	s.mu.Lock()
	if s.closed {
		done := s.closeDone
		s.mu.Unlock()
		<-done
		return nil
	}
	s.closed = true
	rd := s.rd
	s.mu.Unlock()

	if rd != nil {
		_ = rd.Close()
	}
	s.wg.Wait()

	s.mu.Lock()
	if s.lnk != nil {
		_ = s.lnk.Close()
		s.lnk = nil
	}
	if s.coll != nil {
		s.coll.Close()
		s.coll = nil
	}
	if s.file != nil {
		_ = s.file.Close()
		s.file = nil
	}
	close(s.events)
	close(s.closeDone)
	s.mu.Unlock()
	return nil
}
