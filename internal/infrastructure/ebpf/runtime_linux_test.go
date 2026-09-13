//go:build linux

package ebpf

import (
	"bufio"
	"debug/elf"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
)

func TestParseProcMapLinePreservesStableIdentity(t *testing.T) {
	mapping, ok := parseProcMapLine(`7f100000-7f110000 r-xp 00001000 08:01 4242 /usr/lib/libfoo\040bar.so (deleted)`)
	if !ok {
		t.Fatal("expected mapping to parse")
	}
	if mapping.Start != 0x7f100000 || mapping.End != 0x7f110000 {
		t.Fatalf("range = %#x-%#x", mapping.Start, mapping.End)
	}
	if mapping.Perms != "r-xp" {
		t.Fatalf("perms = %q", mapping.Perms)
	}
	if mapping.Path != "/usr/lib/libfoo bar.so" || !mapping.Deleted {
		t.Fatalf("path/deleted = %q/%t", mapping.Path, mapping.Deleted)
	}
	if mapping.Device != unix.Mkdev(8, 1) || mapping.Inode != 4242 {
		t.Fatalf("identity = dev:%d inode:%d", mapping.Device, mapping.Inode)
	}
}

func TestPathMatchesFileIdentityRejectsPathReplacement(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mapped.so")
	original, err := os.Create(path)
	if err != nil {
		t.Fatalf("create original: %v", err)
	}
	defer original.Close()
	info, err := original.Stat()
	if err != nil {
		t.Fatalf("stat original: %v", err)
	}
	device, inode, ok := fileInfoIdentity(info)
	if !ok || inode == 0 {
		t.Fatal("original file has no stable identity")
	}
	if matches, err := pathMatchesFileIdentity(path, device, inode); err != nil || !matches {
		t.Fatalf("original identity mismatch: matches=%t err=%v", matches, err)
	}

	replacement := filepath.Join(dir, "replacement.so")
	if err := os.WriteFile(replacement, []byte("replacement"), 0o600); err != nil {
		t.Fatalf("write replacement: %v", err)
	}
	if err := os.Rename(replacement, path); err != nil {
		t.Fatalf("replace path: %v", err)
	}
	if matches, err := pathMatchesFileIdentity(path, device, inode); err != nil {
		t.Fatalf("check replacement identity: %v", err)
	} else if matches {
		t.Fatal("replacement path incorrectly accepted as the original mapping identity")
	}
}

func TestParseProcMapLineRejectsMalformedInput(t *testing.T) {
	for _, line := range []string{
		"",
		"not-a-range r-xp 0 08:01 1 /lib/x.so",
		"1000-0fff r-xp 0 08:01 1 /lib/x.so",
		"1000-2000 r-xp 0 not-a-device 1 /lib/x.so",
		"1000-2000 r-xp 0 08:01 not-an-inode /lib/x.so",
	} {
		if _, ok := parseProcMapLine(line); ok {
			t.Fatalf("malformed maps line accepted: %q", line)
		}
	}
}

// mappedELFDefiningSymbol finds the file-backed ET_DYN object in pid's current mappings which actually
// DEFINES symbol. Undefined imports have Value==0 and are deliberately ignored: the runtime probe must be
// attached to the shared object that owns the function, not to a caller's PLT entry.
func mappedELFDefiningSymbol(procRoot string, pid int, symbol string) (string, error) {
	mapsPath := filepath.Join(procRoot, strconv.Itoa(pid), "maps")
	file, err := os.Open(mapsPath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	seen := make(map[string]bool)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		mapping, ok := parseProcMapLine(scanner.Text())
		if !ok || mapping.Path == "" || mapping.Deleted || !filepath.IsAbs(mapping.Path) || seen[mapping.Path] {
			continue
		}
		seen[mapping.Path] = true
		candidate := filepath.Join(procRoot, strconv.Itoa(pid), "root", strings.TrimPrefix(mapping.Path, string(filepath.Separator)))
		object, err := elf.Open(candidate)
		if err != nil {
			continue
		}
		if object.FileHeader.Type != elf.ET_DYN {
			_ = object.Close()
			continue
		}
		symbols, err := object.DynamicSymbols()
		_ = object.Close()
		if err != nil {
			continue
		}
		for _, candidateSymbol := range symbols {
			if candidateSymbol.Name == symbol && candidateSymbol.Value != 0 && elf.ST_TYPE(candidateSymbol.Info) == elf.STT_FUNC {
				return mapping.Path, nil
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	return "", fmt.Errorf("no mapped ET_DYN object defines %q", symbol)
}

func waitForMappedELFDefiningSymbol(procRoot string, pid int, symbol string, timeout time.Duration) (string, error) {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for {
		path, err := mappedELFDefiningSymbol(procRoot, pid, symbol)
		if err == nil {
			return path, nil
		}
		lastErr = err
		if time.Now().After(deadline) {
			return "", lastErr
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestRuntimeSensorCapturesExecStartupLibraryAndSymbolHit(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("native eBPF attach test requires root")
	}
	if embeddedObjectArch == "" {
		t.Skip("no embedded eBPF objects for this architecture")
	}
	if _, err := os.Stat("/bin/bash"); err != nil {
		t.Skipf("/bin/bash unavailable: %v", err)
	}

	sensor, err := NewRuntimeSensor("host-runtime-test")
	if err != nil {
		t.Fatalf("new runtime sensor: %v", err)
	}
	if err := sensor.Start(t.Context()); err != nil {
		t.Fatalf("start runtime sensor: %v", err)
	}
	defer func() { _ = sensor.Close() }()

	// Start the fixture before attaching the uprobe so the probe can be PID-scoped. Keeping malloc
	// scoped to this process avoids host-wide libc traffic making the acceptance test noisy/flaky.
	cmd := exec.Command("/bin/bash", "-c", "sleep 2; printf -v synapse_runtime_probe '%65536s' x; : \"$synapse_runtime_probe\"; sleep 1")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start bash fixture: %v", err)
	}
	pid := cmd.Process.Pid
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()

	libraryPath, err := waitForMappedELFDefiningSymbol("/proc", pid, "malloc", 2*time.Second)
	if err != nil {
		t.Fatalf("find mapped shared object defining malloc: %v", err)
	}
	probe := RuntimeSymbolProbe{Path: libraryPath, Symbol: "malloc", PID: pid}
	if err := sensor.AttachSymbolProbe(t.Context(), probe); err != nil {
		t.Fatalf("attach PID-scoped shared-library malloc uprobe: %v", err)
	}
	// Duplicate configuration is deliberately idempotent; it must not install a second symbol observer.
	if err := sensor.AttachSymbolProbe(t.Context(), probe); err != nil {
		t.Fatalf("reattach shared-library malloc uprobe: %v", err)
	}
	executableDevice, executableInode, err := processExecutableFileIdentity("/proc", pid)
	if err != nil {
		t.Fatalf("resolve fixture executable identity: %v", err)
	}

	var sawExec, sawLibrary, sawSymbol bool
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	for !(sawExec && sawLibrary && sawSymbol) {
		select {
		case event, ok := <-sensor.Events():
			if !ok {
				t.Fatal("runtime event stream closed early")
			}
			if event.PID != pid {
				continue
			}
			if err := event.Validate(); err != nil {
				t.Fatalf("invalid runtime evidence: %+v: %v", event, err)
			}
			switch event.Kind {
			case detection.RuntimeEvidenceBinaryExec:
				sawExec = true
			case detection.RuntimeEvidenceLibraryLoaded:
				if event.Symbol != "" {
					t.Fatalf("library evidence upgraded to symbol evidence: %+v", event)
				}
				if event.Device == executableDevice && event.Inode == executableInode {
					t.Fatalf("PIE main executable misclassified as library_loaded: %+v", event)
				}
				sawLibrary = true
			case detection.RuntimeEvidenceSymbolHit:
				if event.Symbol == probe.Symbol && event.Path == probe.Path {
					sawSymbol = true
				}
			}
		case <-deadline.C:
			t.Fatalf("runtime evidence incomplete for pid %d: exec=%t library=%t symbol=%t dropped=%d", pid, sawExec, sawLibrary, sawSymbol, sensor.Dropped())
		}
	}
}
