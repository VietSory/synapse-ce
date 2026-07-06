package ownadvisory

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/advisory"
)

const validOSV1 = `{"id":"GHSA-1","aliases":["CVE-2024-1"],"affected":[{"package":{"ecosystem":"Go","name":"github.com/foo/bar"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.2.0"}]}]}]}`
const validOSV2 = `{"id":"GHSA-2","affected":[{"package":{"ecosystem":"npm","name":"left-pad"},"versions":["1.0.0"]}]}`

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestDirFeedParsesAndSkips: two valid OSV JSON files are yielded; a malformed.json is skipped + counted; a
// non-.json file is ignored entirely.
func TestDirFeedParsesAndSkips(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "a.json", validOSV1)
	writeFile(t, dir, "b.json", validOSV2)
	writeFile(t, dir, "bad.json", `{not json`)            // malformed -> skipped + counted
	writeFile(t, dir, "notes.txt", validOSV1)             // wrong extension -> ignored, not counted as skip
	writeFile(t, dir, "noid.json", `{"summary":"no id"}`) // ParseOSV rejects (no id) -> skipped

	var got []string
	skipped, err := NewDirFeed(dir).Each(context.Background(), func(a advisory.Advisory) error {
		got = append(got, a.ID)
		return nil
	})
	if err != nil {
		t.Fatalf("each: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 parsed advisories, got %v", got)
	}
	if skipped != 2 { // bad.json + noid.json; notes.txt is not a.json so not a skip
		t.Fatalf("want skipped=2 (malformed + no-id), got %d", skipped)
	}
}

// TestDirFeedSubdirsWalked: advisories nested in subdirectories (OSV dumps are per-ecosystem folders) are found.
func TestDirFeedSubdirsWalked(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "Go")
	if err := os.Mkdir(sub, 0o750); err != nil {
		t.Fatal(err)
	}
	writeFile(t, sub, "a.json", validOSV1)

	var n int
	skipped, err := NewDirFeed(dir).Each(context.Background(), func(advisory.Advisory) error { n++; return nil })
	if err != nil || n != 1 || skipped != 0 {
		t.Fatalf("nested advisory must be walked: n=%d skipped=%d err=%v", n, skipped, err)
	}
}

// TestDirFeedFnErrorAborts: an error from fn aborts iteration and propagates.
func TestDirFeedFnErrorAborts(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "a.json", validOSV1)
	writeFile(t, dir, "b.json", validOSV2)
	_, err := NewDirFeed(dir).Each(context.Background(), func(advisory.Advisory) error {
		return os.ErrClosed // simulate a fatal writer error bubbling up
	})
	if err == nil {
		t.Fatal("an error from fn must abort + propagate")
	}
}

// TestDirFeedCancelled: a cancelled context aborts the walk.
func TestDirFeedCancelled(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "a.json", validOSV1)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := NewDirFeed(dir).Each(ctx, func(advisory.Advisory) error { return nil }); err == nil {
		t.Fatal("cancelled context must abort")
	}
}

// TestDirFeedNotADir: a non-directory path fails loud.
func TestDirFeedNotADir(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "x.json")
	writeFile(t, dir, "x.json", validOSV1)
	if _, err := NewDirFeed(f).Each(context.Background(), func(advisory.Advisory) error { return nil }); err == nil {
		t.Fatal("a file path (not a dir) must fail loud")
	}
}
