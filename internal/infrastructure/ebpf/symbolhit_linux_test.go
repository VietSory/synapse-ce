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
)

func mappedELFDefiningRuntimeSymbol(procRoot string, pid int, symbol string) (string, error) {
	f, err := os.Open(filepath.Join(procRoot, strconv.Itoa(pid), "maps"))
	if err != nil {
		return "", err
	}
	defer f.Close()
	seen := map[string]bool{}
	s := bufio.NewScanner(f)
	for s.Scan() {
		fields := strings.Fields(s.Text())
		if len(fields) < 6 || !strings.Contains(fields[1], "x") {
			continue
		}
		path := strings.Join(fields[5:], " ")
		path = strings.TrimSuffix(path, " (deleted)")
		if !filepath.IsAbs(path) || seen[path] {
			continue
		}
		seen[path] = true
		candidate := filepath.Join(procRoot, strconv.Itoa(pid), "root", strings.TrimPrefix(path, "/"))
		obj, err := elf.Open(candidate)
		if err != nil {
			continue
		}
		syms, err := obj.DynamicSymbols()
		_ = obj.Close()
		if err != nil {
			continue
		}
		for _, sym := range syms {
			if sym.Name == symbol && sym.Value != 0 && elf.ST_TYPE(sym.Info) == elf.STT_FUNC {
				return path, nil
			}
		}
	}
	if err := s.Err(); err != nil {
		return "", err
	}
	return "", fmt.Errorf("no mapped object defines %q", symbol)
}

func waitForRuntimeSymbol(procRoot string, pid int, symbol string, timeout time.Duration) (string, error) {
	deadline := time.Now().Add(timeout)
	var last error
	for time.Now().Before(deadline) {
		path, err := mappedELFDefiningRuntimeSymbol(procRoot, pid, symbol)
		if err == nil {
			return path, nil
		}
		last = err
		time.Sleep(10 * time.Millisecond)
	}
	return "", last
}

func TestSymbolHitSensorCapturesPIDScopedSharedLibrarySymbol(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("symbol-hit sensor needs root; run under sudo")
	}
	if embeddedObjectArch == "" {
		t.Skip("no embedded eBPF object for this architecture")
	}
	if _, err := os.Stat("/bin/bash"); err != nil {
		t.Skipf("/bin/bash unavailable: %v", err)
	}

	cmd := exec.Command("/bin/bash", "-c", "sleep 2; printf -v synapse_runtime_probe '%65536s' x; : \"$synapse_runtime_probe\"; sleep 1")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start fixture: %v", err)
	}
	pid := cmd.Process.Pid
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()

	libraryPath, err := waitForRuntimeSymbol("/proc", pid, "malloc", 2*time.Second)
	if err != nil {
		t.Fatalf("find mapped shared object defining malloc: %v", err)
	}
	sensor, err := NewSymbolHitSensor(RuntimeSymbolProbe{Path: libraryPath, Symbol: "malloc", PID: pid})
	if err != nil {
		t.Fatalf("new sensor: %v", err)
	}
	if err := sensor.Start(t.Context()); err != nil {
		t.Fatalf("start symbol-hit sensor: %v", err)
	}
	defer func() { _ = sensor.Close() }()

	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	for {
		select {
		case ev, ok := <-sensor.Events():
			if !ok {
				t.Fatal("event stream closed before symbol hit")
			}
			if err := ev.Validate(); err != nil {
				t.Fatalf("invalid symbol-hit evidence: %+v: %v", ev, err)
			}
			if ev.PID != uint32(pid) {
				t.Fatalf("PID-scoped uprobe emitted another pid: got %d want %d", ev.PID, pid)
			}
			if ev.Symbol != "malloc" || ev.Path != libraryPath || ev.Inode == 0 {
				t.Fatalf("wrong symbol evidence: %+v", ev)
			}
			return
		case <-deadline.C:
			t.Fatalf("timed out waiting for %s:malloc hit from pid %d", libraryPath, pid)
		}
	}
}
