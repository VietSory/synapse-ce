package privacy

import (
	"errors"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/telemetry"
)

func envelope(args ...string) telemetry.TelemetryEnvelope {
	at := time.Unix(1_700_000_000, 0).UTC()
	assetID := shared.ID("asset-1")
	bootID := shared.ID("boot-1")
	streamID := shared.ID("stream-1")
	sequence := uint64(1)
	return telemetry.TelemetryEnvelope{
		SchemaVersion:  telemetry.SchemaVersion,
		EventID:        telemetry.DeriveEventID(assetID, bootID, streamID, sequence, detection.ClassProcess, at.UnixNano()),
		EventType:      "process.exec",
		EventClass:     detection.ClassProcess,
		AgentID:        "agent-1",
		AgentSessionID: "session-1",
		AssetID:        assetID,
		BootID:         bootID,
		StreamID:       streamID,
		SensorID:       "sensor-1",
		SensorVersion:  "1",
		OccurredAt:     at,
		ObservedAt:     at,
		Sequence:       sequence,
		Event: telemetry.TelemetryEvent{Class: detection.ClassProcess, Process: &telemetry.ProcessObservation{
			Kind: "exec", PID: 1, StartTimeNanos: 10,
			EntityID: telemetry.ProcessEntityID(assetID, bootID, 1, 10),
			Comm:     "curl", Path: "/usr/bin/curl", Args: args,
		}},
	}
}

func TestKnownSecretsNeverSurviveSafeDefault(t *testing.T) {
	in := envelope("curl", "--password", "hunter2", "--token=abc123", "postgres://user:pw@db.internal/x", "Authorization: Bearer eyJ.secret.sig")
	out, err := Scrub(in, Policy{})
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(out.Event.Process.Args, " ")
	for _, secret := range []string{"hunter2", "abc123", "user:pw", "eyJ.secret.sig"} {
		if strings.Contains(got, secret) {
			t.Fatalf("secret %q survived: %q", secret, got)
		}
	}
	if out.RedactionPolicyDigest == "" {
		t.Fatal("missing policy digest")
	}
	if strings.Join(in.Event.Process.Args, " ") == got {
		t.Fatal("input must not be mutated")
	}
	if err := out.Validate(); err != nil {
		t.Fatalf("scrubbed canonical envelope must validate: %v", err)
	}
}

func TestEnvironmentDropsByDefault(t *testing.T) {
	got, disposition, err := (Policy{}).Classify(FieldProcessEnv, "DATABASE_URL=postgres://u:p@db/x")
	if err != nil {
		t.Fatal(err)
	}
	if disposition != Drop || got != "" {
		t.Fatalf("got %q/%q", got, disposition)
	}
}

func TestHashUsesKeyedCorrelationAndDigestHidesKey(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	p := DefaultPolicy()
	p.HashKeyID = "tenant-key-v2"
	p.HashKey = key
	p.Overrides = map[Field]FieldDisposition{FieldNetworkRemoteAddr: Hash, FieldNetworkLocalAddr: Hash}
	a, da, err := p.Classify(FieldNetworkRemoteAddr, "10.0.0.7")
	if err != nil {
		t.Fatal(err)
	}
	b, _, _ := p.Classify(FieldNetworkRemoteAddr, "10.0.0.7")
	c, _, _ := p.Classify(FieldNetworkRemoteAddr, "10.0.0.8")
	if da != Hash || a != b || a == c || strings.Contains(a, "10.0.0.7") {
		t.Fatalf("bad correlation hashes: %q %q %q", a, b, c)
	}
	otherField, _, err := p.Classify(FieldNetworkLocalAddr, "10.0.0.7")
	if err != nil {
		t.Fatal(err)
	}
	if otherField == a {
		t.Fatal("hashes must be field-domain separated")
	}
	digest, err := p.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(digest, string(key)) {
		t.Fatal("policy digest exposed key")
	}
}

func TestBoundsAreUTF8SafeAndHonest(t *testing.T) {
	p := DefaultPolicy()
	p.MaxArgs = 2
	p.MaxArgBytes = 5
	p.MaxPathBytes = 6
	in := envelope("ééé", "second", "third")
	in.Event.Process.Path = "/éééé"
	out, err := Scrub(in, p)
	if err != nil {
		t.Fatal(err)
	}
	if !out.Event.Process.ArgsTruncated || !out.DataQuality.Has(telemetry.QualityTruncatedArgv) {
		t.Fatal("argv truncation not recorded")
	}
	if !out.Event.Process.PathTruncated || !out.DataQuality.Has(telemetry.QualityTruncatedPath) {
		t.Fatal("path truncation not recorded")
	}
	if !utf8.ValidString(out.Event.Process.Args[0]) || !utf8.ValidString(out.Event.Process.Path) {
		t.Fatal("truncation broke utf8")
	}
}

func TestExplicitAllowCannotDisableSecretGuard(t *testing.T) {
	p := DefaultPolicy()
	p.Overrides = map[Field]FieldDisposition{FieldProcessArg: Allow}
	got, disposition, err := p.Classify(FieldProcessArg, "token=supersecret")
	if err != nil {
		t.Fatal(err)
	}
	if disposition != Redact || strings.Contains(got, "supersecret") {
		t.Fatalf("allow weakened secret guard: %q/%s", got, disposition)
	}
}

func TestPolicyDigestDeterministicAcrossMapOrder(t *testing.T) {
	key := []byte("0123456789abcdef")
	a := DefaultPolicy()
	a.HashKeyID, a.HashKey = "k1", key
	a.Overrides = map[Field]FieldDisposition{FieldNetworkRemoteAddr: Hash, FieldProcessArg: Redact}
	b := DefaultPolicy()
	b.HashKeyID, b.HashKey = "k1", key
	b.Overrides = map[Field]FieldDisposition{FieldProcessArg: Redact, FieldNetworkRemoteAddr: Hash}
	da, err := a.Digest()
	if err != nil {
		t.Fatal(err)
	}
	db, err := b.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if da != db {
		t.Fatalf("digest depends on map order: %s != %s", da, db)
	}
}

func TestCloneIsIndependentOfCallerMutation(t *testing.T) {
	p := DefaultPolicy()
	p.HashKeyID = "k1"
	p.HashKey = []byte("0123456789abcdef")
	p.Overrides = map[Field]FieldDisposition{FieldProcessPath: Hash}
	clone := p.Clone()
	p.HashKey[0] = 'X'
	p.Overrides[FieldProcessPath] = Allow

	got, disposition, err := clone.Classify(FieldProcessPath, "/bin/sh")
	if err != nil {
		t.Fatal(err)
	}
	if disposition != Hash || !strings.HasPrefix(got, "hmac-sha256:") {
		t.Fatalf("clone was mutated through caller-owned state: %q/%s", got, disposition)
	}
}

func TestInvalidHashPolicyIsValidationError(t *testing.T) {
	p := DefaultPolicy()
	p.Overrides = map[Field]FieldDisposition{FieldProcessPath: Hash}
	if err := p.Validate(); err == nil || !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("expected shared.ErrValidation, got %v", err)
	}
}

func TestDropOfRequiredFieldFailsClosed(t *testing.T) {
	at := time.Unix(1_700_000_000, 0).UTC()
	in := telemetry.TelemetryEnvelope{
		SchemaVersion:  telemetry.SchemaVersion,
		EventID:        telemetry.DeriveEventID("asset-1", "boot-1", "stream-1", 1, detection.ClassFile, at.UnixNano()),
		EventType:      "file.write",
		EventClass:     detection.ClassFile,
		AgentID:        "agent-1",
		AgentSessionID: "session-1",
		AssetID:        "asset-1",
		BootID:         "boot-1",
		StreamID:       "stream-1",
		SensorID:       "sensor-1",
		SensorVersion:  "1",
		OccurredAt:     at,
		ObservedAt:     at,
		Sequence:       1,
		Event: telemetry.TelemetryEvent{Class: detection.ClassFile, File: &telemetry.FileObservation{
			Op: "write", Path: "/etc/shadow", PID: 1, Comm: "vi",
		}},
	}
	p := DefaultPolicy()
	p.Overrides = map[Field]FieldDisposition{FieldFilePath: Drop}
	if _, err := Scrub(in, p); err == nil {
		t.Fatal("dropping a schema-required field must fail closed instead of emitting malformed telemetry")
	}
}

func TestHashAndRedactDoNotInventAbsentOptionalValues(t *testing.T) {
	p := DefaultPolicy()
	p.HashKeyID = "k1"
	p.HashKey = []byte("0123456789abcdef")
	p.Overrides = map[Field]FieldDisposition{
		FieldNetworkLocalAddr:  Hash,
		FieldResourceNamespace: Redact,
	}
	for _, tc := range []struct {
		field Field
		want  FieldDisposition
	}{
		{FieldNetworkLocalAddr, Hash},
		{FieldResourceNamespace, Redact},
	} {
		got, disposition, err := p.Classify(tc.field, "")
		if err != nil {
			t.Fatal(err)
		}
		if got != "" || disposition != tc.want {
			t.Fatalf("empty %s became %q/%s", tc.field, got, disposition)
		}
	}
}

func TestHashOverrideCannotPseudonymizeKnownSecret(t *testing.T) {
	p := DefaultPolicy()
	p.HashKeyID = "k1"
	p.HashKey = []byte("0123456789abcdef")
	p.Overrides = map[Field]FieldDisposition{FieldProcessArg: Hash}
	got, disposition, err := p.Classify(FieldProcessArg, "password=hunter2")
	if err != nil {
		t.Fatal(err)
	}
	if disposition != Redact || strings.Contains(got, "hunter2") || strings.HasPrefix(got, "hmac-sha256:") {
		t.Fatalf("hash override weakened known-secret baseline: %q/%s", got, disposition)
	}
}

func TestAmbiguousShortPortFlagIsNotTreatedAsPassword(t *testing.T) {
	in := envelope("ssh", "-p", "22", "host.example")
	out, err := Scrub(in, Policy{})
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(out.Event.Process.Args, " ")
	if got != "ssh -p 22 host.example" {
		t.Fatalf("ambiguous -p flag was over-redacted: %q", got)
	}
}

func TestCurlUserPasswordPairIsRedactedButBareUserIsNot(t *testing.T) {
	in := envelope("curl", "-u", "alice:hunter2", "https://example.test")
	out, err := Scrub(in, Policy{})
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(out.Event.Process.Args, " ")
	if strings.Contains(got, "alice:hunter2") || !strings.Contains(got, Placeholder) {
		t.Fatalf("curl credential pair survived: %q", got)
	}

	bare := envelope("tool", "--user", "alice")
	bareOut, err := Scrub(bare, Policy{})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(bareOut.Event.Process.Args, " "); got != "tool --user alice" {
		t.Fatalf("bare username was over-redacted: %q", got)
	}
}

func TestPrivateKeyAndConnectionStringAreRedacted(t *testing.T) {
	in := envelope(
		"-----BEGIN PRIVATE KEY-----abc-----END PRIVATE KEY-----",
		"Server=db;User Id=app;Password=s3cr3t;Database=prod",
	)
	out, err := Scrub(in, Policy{})
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(out.Event.Process.Args, " ")
	for _, forbidden := range []string{"PRIVATE KEY", "s3cr3t"} {
		if strings.Contains(got, forbidden) {
			t.Fatalf("sensitive material survived: %q", got)
		}
	}
}
