//go:build linux

package ebpf

import (
	"bufio"
	"bytes"
	"context"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

const (
	maxRuntimeMapsBytes = 4 << 20
	maxRuntimeMapLine   = 64 << 10
)

// RuntimeSensor emits POSITIVE runtime reachability observations independently of the blue-team
// detection sensor. It never manufactures a negative result when loading, resolving /proc state, or
// attaching a uprobe fails: the absence of an event remains no evidence.
type RuntimeSensor struct {
	host shared.ID

	mu      sync.Mutex
	started bool
	closed  bool
	core    *loadedRuntimeCore
	probes  map[string]*loadedRuntimeProbe

	ktimeEpoch time.Time
	events     chan detection.RuntimeEvidence
	dropped    atomic.Uint64
	wg         sync.WaitGroup
	procRoot   string
}

type loadedRuntimeCore struct {
	coll   *ebpf.Collection
	links  []link.Link
	execRD *ringbuf.Reader
	mapRD  *ringbuf.Reader
}

type loadedRuntimeProbe struct {
	spec   RuntimeSymbolProbe
	device uint64
	inode  uint64
	file   *os.File
	coll   *ebpf.Collection
	link   link.Link
	rd     *ringbuf.Reader
}

// NewRuntimeSensor constructs the D.1 runtime evidence source. It is intentionally separate from
// NewSensor: runtime evidence is raise-only reachability input, not a fifth detection class.
func NewRuntimeSensor(host shared.ID) (*RuntimeSensor, error) {
	if host.IsZero() {
		return nil, fmt.Errorf("%w: runtime sensor host id is required", shared.ErrValidation)
	}
	return &RuntimeSensor{
		host: host, events: make(chan detection.RuntimeEvidence, 1024),
		probes: make(map[string]*loadedRuntimeProbe), procRoot: "/proc",
	}, nil
}

// Start attaches successful-exec and executable-file-mmap observers. Library mappings created by the
// dynamic loader during process startup therefore appear in the same stream as later dlopen mappings.
func (s *RuntimeSensor) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return fmt.Errorf("%w: sensor already closed", ErrRuntimeSensorUnavailable)
	}
	if s.started {
		s.mu.Unlock()
		return fmt.Errorf("%w: sensor already started", ErrRuntimeSensorUnavailable)
	}
	s.started = true
	s.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return fmt.Errorf("%w: %v", ErrRuntimeSensorUnavailable, err)
	}
	if embeddedObjectArch == "" {
		return fmt.Errorf("%w: no architecture-matched eBPF objects for linux/%s", ErrRuntimeSensorUnavailable, runtime.GOARCH)
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("%w: remove memlock rlimit: %v", ErrRuntimeSensorUnavailable, err)
	}

	s.ktimeEpoch = captureKtimeEpoch()
	core, err := loadRuntimeCore()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrRuntimeSensorUnavailable, err)
	}

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		core.closeAll()
		return fmt.Errorf("%w: sensor closed while starting", ErrRuntimeSensorUnavailable)
	}
	s.core = core
	s.wg.Add(2)
	s.mu.Unlock()
	go s.drainRuntimeExec(core.execRD)
	go s.drainRuntimeMap(core.mapRD)
	return nil
}

func loadRuntimeCore() (*loadedRuntimeCore, error) {
	coll, err := loadRuntimeCollection(
		[]string{"runtime_binary_exec", "runtime_mmap_enter", "runtime_mmap_exit"},
		[]string{"runtime_exec_events", "runtime_mmap_args", "runtime_map_events"},
	)
	if err != nil {
		return nil, err
	}
	core := &loadedRuntimeCore{coll: coll}
	closeOnErr := func(err error) (*loadedRuntimeCore, error) {
		core.closeAll()
		return nil, err
	}

	attachments := []struct {
		program string
		group   string
		name    string
	}{
		{program: "runtime_binary_exec", group: "sched", name: "sched_process_exec"},
		{program: "runtime_mmap_enter", group: "syscalls", name: "sys_enter_mmap"},
		{program: "runtime_mmap_exit", group: "syscalls", name: "sys_exit_mmap"},
	}
	for _, a := range attachments {
		prog := coll.Programs[a.program]
		if prog == nil {
			return closeOnErr(fmt.Errorf("program %q missing from exec object", a.program))
		}
		lnk, err := link.Tracepoint(a.group, a.name, prog, nil)
		if err != nil {
			return closeOnErr(fmt.Errorf("attach %s/%s: %w", a.group, a.name, err))
		}
		core.links = append(core.links, lnk)
	}
	core.execRD, err = ringbuf.NewReader(coll.Maps["runtime_exec_events"])
	if err != nil {
		return closeOnErr(fmt.Errorf("runtime exec ring buffer: %w", err))
	}
	core.mapRD, err = ringbuf.NewReader(coll.Maps["runtime_map_events"])
	if err != nil {
		return closeOnErr(fmt.Errorf("runtime mmap ring buffer: %w", err))
	}
	return core, nil
}

func loadRuntimeCollection(programNames, mapNames []string) (*ebpf.Collection, error) {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(execObj))
	if err != nil {
		return nil, fmt.Errorf("load runtime exec spec: %w", err)
	}
	keepPrograms := make(map[string]bool, len(programNames))
	for _, name := range programNames {
		if spec.Programs[name] == nil {
			return nil, fmt.Errorf("runtime program %q missing from exec object", name)
		}
		keepPrograms[name] = true
	}
	for name := range spec.Programs {
		if !keepPrograms[name] {
			delete(spec.Programs, name)
		}
	}
	keepMaps := make(map[string]bool, len(mapNames))
	for _, name := range mapNames {
		if spec.Maps[name] == nil {
			return nil, fmt.Errorf("runtime map %q missing from exec object", name)
		}
		keepMaps[name] = true
	}
	for name := range spec.Maps {
		if !keepMaps[name] {
			delete(spec.Maps, name)
		}
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("load runtime programs: %w", err)
	}
	return coll, nil
}

// AttachSymbolProbe adds one exact positive symbol-hit observer. The probe target is pinned through an
// open file descriptor before attachment, so a path replacement cannot silently relabel a hit with the
// identity of another file. Duplicate requests are idempotent. Probes live until Close.
func (s *RuntimeSensor) AttachSymbolProbe(ctx context.Context, raw RuntimeSymbolProbe) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("%w: attach symbol probe: %v", ErrRuntimeSensorUnavailable, err)
	}
	probe, err := raw.validate()
	if err != nil {
		return err
	}
	key := runtimeProbeKey(probe)

	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.started || s.core == nil {
		return fmt.Errorf("%w: sensor must be started before attaching symbol probes", ErrRuntimeSensorUnavailable)
	}
	if s.closed {
		return fmt.Errorf("%w: sensor is closed", ErrRuntimeSensorUnavailable)
	}
	if _, ok := s.probes[key]; ok {
		return nil
	}
	if len(s.probes) >= maxRuntimeSymbolProbes {
		return fmt.Errorf("%w: symbol probe limit %d reached", ErrRuntimeSensorUnavailable, maxRuntimeSymbolProbes)
	}
	loaded, err := loadRuntimeProbe(probe)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		loaded.closeAll()
		return fmt.Errorf("%w: attach symbol probe: %v", ErrRuntimeSensorUnavailable, err)
	}
	s.probes[key] = loaded
	s.wg.Add(1)
	go s.drainRuntimeSymbol(loaded)
	return nil
}

func loadRuntimeProbe(probe RuntimeSymbolProbe) (*loadedRuntimeProbe, error) {
	file, err := os.Open(probe.Path)
	if err != nil {
		return nil, fmt.Errorf("%w: open symbol target %s: %v", ErrRuntimeSensorUnavailable, probe.Path, err)
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("%w: stat symbol target %s: %v", ErrRuntimeSensorUnavailable, probe.Path, err)
	}
	device, inode, ok := fileInfoIdentity(info)
	if !ok || inode == 0 {
		_ = file.Close()
		return nil, fmt.Errorf("%w: symbol target %s has no stable file identity", ErrRuntimeSensorUnavailable, probe.Path)
	}

	coll, err := loadRuntimeCollection([]string{"runtime_symbol_hit"}, []string{"runtime_symbol_events"})
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	loaded := &loadedRuntimeProbe{spec: probe, device: device, inode: inode, file: file, coll: coll}
	closeOnErr := func(err error) (*loadedRuntimeProbe, error) {
		loaded.closeAll()
		return nil, err
	}

	pinnedPath := filepath.Join("/proc/self/fd", strconv.Itoa(int(file.Fd())))
	executable, err := link.OpenExecutable(pinnedPath)
	if err != nil {
		return closeOnErr(fmt.Errorf("%w: open pinned uprobe target: %v", ErrRuntimeSensorUnavailable, err))
	}
	prog := coll.Programs["runtime_symbol_hit"]
	if prog == nil {
		return closeOnErr(fmt.Errorf("%w: runtime_symbol_hit missing from exec object", ErrRuntimeSensorUnavailable))
	}
	loaded.link, err = executable.Uprobe(probe.Symbol, prog, &link.UprobeOptions{PID: probe.PID})
	if err != nil {
		return closeOnErr(fmt.Errorf("%w: attach %s:%s: %v", ErrRuntimeSensorUnavailable, probe.Path, probe.Symbol, err))
	}
	loaded.rd, err = ringbuf.NewReader(coll.Maps["runtime_symbol_events"])
	if err != nil {
		return closeOnErr(fmt.Errorf("%w: runtime symbol ring buffer: %v", ErrRuntimeSensorUnavailable, err))
	}
	return loaded, nil
}

type rawRuntimeExec struct {
	Ktime uint64
	PID   uint32
	UID   uint32
	Comm  [16]byte
}

type rawRuntimeMap struct {
	Ktime uint64
	Addr  uint64
	PID   uint32
	UID   uint32
	Comm  [16]byte
}

type rawRuntimeSymbol struct {
	Ktime uint64
	PID   uint32
	UID   uint32
	Comm  [16]byte
}

func (s *RuntimeSensor) drainRuntimeExec(rd *ringbuf.Reader) {
	defer s.wg.Done()
	for {
		record, err := rd.Read()
		if err != nil {
			return
		}
		var raw rawRuntimeExec
		if binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &raw) != nil {
			s.dropped.Add(1)
			continue
		}
		path, device, inode, deleted, err := processExecutableIdentity(s.procRoot, int(raw.PID))
		if err != nil {
			s.dropped.Add(1)
			continue
		}
		s.emit(detection.RuntimeEvidence{
			Kind: detection.RuntimeEvidenceBinaryExec,
			At:   kernelOccurredAt(s.ktimeEpoch, raw.Ktime), Host: s.host,
			PID: int(raw.PID), UID: int(raw.UID), Comm: cstr(raw.Comm[:]), Path: path,
			Device: device, Inode: inode, Deleted: deleted,
		})
	}
}

func (s *RuntimeSensor) drainRuntimeMap(rd *ringbuf.Reader) {
	defer s.wg.Done()
	for {
		record, err := rd.Read()
		if err != nil {
			return
		}
		var raw rawRuntimeMap
		if binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &raw) != nil {
			s.dropped.Add(1)
			continue
		}
		mapping, err := processMappingAt(s.procRoot, int(raw.PID), raw.Addr)
		if err != nil {
			s.dropped.Add(1)
			continue
		}
		if mapping.Inode == 0 || mapping.Path == "" || !strings.Contains(mapping.Perms, "x") {
			continue
		}
		isShared, err := mappingIsELFDynamic(s.procRoot, int(raw.PID), mapping)
		if err != nil {
			s.dropped.Add(1)
			continue
		}
		if !isShared {
			continue
		}
		s.emit(detection.RuntimeEvidence{
			Kind: detection.RuntimeEvidenceLibraryLoaded,
			At:   kernelOccurredAt(s.ktimeEpoch, raw.Ktime), Host: s.host,
			PID: int(raw.PID), UID: int(raw.UID), Comm: cstr(raw.Comm[:]), Path: mapping.Path,
			Device: mapping.Device, Inode: mapping.Inode, Deleted: mapping.Deleted,
		})
	}
}

func (s *RuntimeSensor) drainRuntimeSymbol(probe *loadedRuntimeProbe) {
	defer s.wg.Done()
	for {
		record, err := probe.rd.Read()
		if err != nil {
			return
		}
		var raw rawRuntimeSymbol
		if binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &raw) != nil {
			s.dropped.Add(1)
			continue
		}
		deleted := pathNoLongerNamesIdentity(probe.spec.Path, probe.device, probe.inode)
		s.emit(detection.RuntimeEvidence{
			Kind: detection.RuntimeEvidenceSymbolHit,
			At:   kernelOccurredAt(s.ktimeEpoch, raw.Ktime), Host: s.host,
			PID: int(raw.PID), UID: int(raw.UID), Comm: cstr(raw.Comm[:]),
			Path: probe.spec.Path, Symbol: probe.spec.Symbol,
			Device: probe.device, Inode: probe.inode, Deleted: deleted,
		})
	}
}

func (s *RuntimeSensor) emit(event detection.RuntimeEvidence) {
	if err := event.Validate(); err != nil {
		s.dropped.Add(1)
		return
	}
	select {
	case s.events <- event:
	default:
		s.dropped.Add(1)
	}
}

// Events returns only positive runtime observations. Channel silence is deliberately not a negative
// verdict and must never be interpreted as not_reachable.
func (s *RuntimeSensor) Events() <-chan detection.RuntimeEvidence { return s.events }

// Dropped exposes positive observations the source could not retain/resolve. A non-zero value is an
// observability gap; it is not a count of non-executed code.
func (s *RuntimeSensor) Dropped() uint64 { return s.dropped.Load() }

func (s *RuntimeSensor) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	core := s.core
	probes := make([]*loadedRuntimeProbe, 0, len(s.probes))
	for _, probe := range s.probes {
		probes = append(probes, probe)
	}
	s.mu.Unlock()

	if core != nil {
		core.closeReaders()
	}
	for _, probe := range probes {
		if probe.rd != nil {
			_ = probe.rd.Close()
		}
	}
	s.wg.Wait()
	if core != nil {
		core.closeAll()
	}
	for _, probe := range probes {
		probe.closeAll()
	}
	close(s.events)
	return nil
}

func (core *loadedRuntimeCore) closeReaders() {
	if core.execRD != nil {
		_ = core.execRD.Close()
	}
	if core.mapRD != nil {
		_ = core.mapRD.Close()
	}
}

func (core *loadedRuntimeCore) closeAll() {
	core.closeReaders()
	for _, lnk := range core.links {
		_ = lnk.Close()
	}
	core.links = nil
	if core.coll != nil {
		core.coll.Close()
		core.coll = nil
	}
}

func (probe *loadedRuntimeProbe) closeAll() {
	if probe.rd != nil {
		_ = probe.rd.Close()
		probe.rd = nil
	}
	if probe.link != nil {
		_ = probe.link.Close()
		probe.link = nil
	}
	if probe.coll != nil {
		probe.coll.Close()
		probe.coll = nil
	}
	if probe.file != nil {
		_ = probe.file.Close()
		probe.file = nil
	}
}

func processExecutableIdentity(procRoot string, pid int) (path string, device, inode uint64, deleted bool, err error) {
	linkPath := filepath.Join(procRoot, strconv.Itoa(pid), "exe")
	path, err = os.Readlink(linkPath)
	if err != nil {
		return "", 0, 0, false, err
	}
	path, deleted = splitDeletedPath(path)
	info, err := os.Stat(linkPath)
	if err != nil {
		return "", 0, 0, false, err
	}
	device, inode, ok := fileInfoIdentity(info)
	if !ok || inode == 0 || path == "" {
		return "", 0, 0, false, fmt.Errorf("executable identity is incomplete")
	}
	return path, device, inode, deleted, nil
}

func fileInfoIdentity(info os.FileInfo) (device, inode uint64, ok bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat == nil {
		return 0, 0, false
	}
	return uint64(stat.Dev), uint64(stat.Ino), true
}

func pathNoLongerNamesIdentity(path string, device, inode uint64) bool {
	info, err := os.Stat(path)
	if err != nil {
		return true
	}
	gotDevice, gotInode, ok := fileInfoIdentity(info)
	return !ok || gotDevice != device || gotInode != inode
}

type procMapping struct {
	Range   string
	Start   uint64
	End     uint64
	Perms   string
	Device  uint64
	Inode   uint64
	Path    string
	Deleted bool
}

func processMappingAt(procRoot string, pid int, address uint64) (procMapping, error) {
	file, err := os.Open(filepath.Join(procRoot, strconv.Itoa(pid), "maps"))
	if err != nil {
		return procMapping{}, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(io.LimitReader(file, maxRuntimeMapsBytes))
	scanner.Buffer(make([]byte, 4096), maxRuntimeMapLine)
	for scanner.Scan() {
		mapping, ok := parseProcMapLine(scanner.Text())
		if !ok {
			continue
		}
		if mapping.Start <= address && address < mapping.End {
			return mapping, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return procMapping{}, err
	}
	return procMapping{}, fmt.Errorf("mapping for address %#x not found", address)
}

func parseProcMapLine(line string) (procMapping, bool) {
	fields := strings.Fields(line)
	if len(fields) < 6 {
		return procMapping{}, false
	}
	rangeParts := strings.SplitN(fields[0], "-", 2)
	if len(rangeParts) != 2 {
		return procMapping{}, false
	}
	start, err := strconv.ParseUint(rangeParts[0], 16, 64)
	if err != nil {
		return procMapping{}, false
	}
	end, err := strconv.ParseUint(rangeParts[1], 16, 64)
	if err != nil || end <= start {
		return procMapping{}, false
	}
	devParts := strings.SplitN(fields[3], ":", 2)
	if len(devParts) != 2 {
		return procMapping{}, false
	}
	major, err := strconv.ParseUint(devParts[0], 16, 32)
	if err != nil {
		return procMapping{}, false
	}
	minor, err := strconv.ParseUint(devParts[1], 16, 32)
	if err != nil {
		return procMapping{}, false
	}
	inode, err := strconv.ParseUint(fields[4], 10, 64)
	if err != nil {
		return procMapping{}, false
	}
	path := decodeProcPath(strings.Join(fields[5:], " "))
	path, deleted := splitDeletedPath(path)
	return procMapping{
		Range: fields[0], Start: start, End: end, Perms: fields[1],
		Device: unix.Mkdev(uint32(major), uint32(minor)), Inode: inode,
		Path: path, Deleted: deleted,
	}, true
}

func splitDeletedPath(path string) (string, bool) {
	const suffix = " (deleted)"
	if strings.HasSuffix(path, suffix) {
		return strings.TrimSuffix(path, suffix), true
	}
	return path, false
}

func decodeProcPath(path string) string {
	replacer := strings.NewReplacer(
		`\040`, " ",
		`\011`, "\t",
		`\012`, "\n",
		`\134`, `\`,
	)
	return replacer.Replace(path)
}

func mappingIsELFDynamic(procRoot string, pid int, mapping procMapping) (bool, error) {
	if mapping.Path == "" || !filepath.IsAbs(mapping.Path) {
		return false, nil
	}
	rootPath := filepath.Join(procRoot, strconv.Itoa(pid), "root", strings.TrimPrefix(mapping.Path, string(filepath.Separator)))
	mapFile := filepath.Join(procRoot, strconv.Itoa(pid), "map_files", mapping.Range)
	candidates := []string{rootPath, mapFile}
	var lastErr error
	for _, candidate := range candidates {
		object, err := elf.Open(candidate)
		if err != nil {
			lastErr = err
			continue
		}
		isDynamic := object.FileHeader.Type == elf.ET_DYN
		_ = object.Close()
		return isDynamic, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no ELF candidate")
	}
	return false, lastErr
}
