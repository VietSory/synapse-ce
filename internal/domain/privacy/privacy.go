// Package privacy defines the source-side telemetry privacy policy. It is intentionally pure: callers
// apply it before durable spooling or transport so a secret rejected here never reaches either sink.
package privacy

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/telemetry"
)

// Placeholder replaces a value whose policy disposition is Redact.
const Placeholder = "[REDACTED]"

// Field identifies a string-bearing telemetry field for policy classification. Environment is reserved
// even though the canonical envelope intentionally carries no environment map: its default Drop policy
// makes the no-env-by-default contract explicit and testable rather than relying on an accidental omission.
type Field string

const (
	FieldProcessComm Field = "process.comm"
	FieldProcessPath Field = "process.path"
	FieldProcessArg  Field = "process.arg"
	FieldProcessEnv  Field = "process.env"

	FieldNetworkLocalAddr  Field = "network.local_addr"
	FieldNetworkRemoteAddr Field = "network.remote_addr"
	FieldNetworkComm       Field = "network.comm"
	FieldFilePath          Field = "file.path"
	FieldFileComm          Field = "file.comm"
	FieldPrivilegeComm     Field = "privilege.comm"
	FieldPrivilegeCap      Field = "privilege.cap"

	FieldResourceHost           Field = "resource.host"
	FieldResourceClusterID      Field = "resource.cluster_id"
	FieldResourceNodeUID        Field = "resource.node_uid"
	FieldResourceNamespace      Field = "resource.namespace"
	FieldResourceServiceAccount Field = "resource.service_account"
	FieldResourceWorkloadUID    Field = "resource.workload_uid"
	FieldResourcePodUID         Field = "resource.pod_uid"
	FieldResourceContainerID    Field = "resource.container_id"
	FieldResourceImageDigest    Field = "resource.image_digest"
	FieldResourceRuntime        Field = "resource.runtime"
)

// FieldDisposition is the closed set of source-side privacy actions.
type FieldDisposition string

const (
	Allow  FieldDisposition = "allow"
	Redact FieldDisposition = "redact"
	Hash   FieldDisposition = "hash"
	Drop   FieldDisposition = "drop"
)

func (d FieldDisposition) valid() bool { return d == Allow || d == Redact || d == Hash || d == Drop }

const (
	defaultPolicyID     = "safe-default"
	defaultMaxArgs      = 64
	defaultMaxArgBytes  = 1024
	defaultMaxPathBytes = 4096
)

// Policy is the tenant-selectable source privacy policy. HashKey is secret key material and is NEVER
// included in Digest; HashKeyID is the non-secret rotation identifier that makes digest changes explicit.
type Policy struct {
	ID           string
	Version      uint64
	MaxArgs      int
	MaxArgBytes  int
	MaxPathBytes int
	HashKeyID    string
	HashKey      []byte
	Overrides    map[Field]FieldDisposition
}

// DefaultPolicy returns the safe policy used when no tenant policy is configured.
func DefaultPolicy() Policy {
	return Policy{ID: defaultPolicyID, Version: 1, MaxArgs: defaultMaxArgs, MaxArgBytes: defaultMaxArgBytes, MaxPathBytes: defaultMaxPathBytes}
}

// Clone returns an independent policy value. Mutable key/map inputs are copied so a Normalizer can keep
// deterministic behavior even if the configuration object used to construct it is later reused or mutated.
func (p Policy) Clone() Policy {
	p = p.normalized()
	c := p
	c.HashKey = append([]byte(nil), p.HashKey...)
	if p.Overrides != nil {
		c.Overrides = make(map[Field]FieldDisposition, len(p.Overrides))
		for field, disposition := range p.Overrides {
			c.Overrides[field] = disposition
		}
	}
	return c
}

func (p Policy) normalized() Policy {
	if p.ID == "" && p.Version == 0 && p.MaxArgs == 0 && p.MaxArgBytes == 0 && p.MaxPathBytes == 0 && p.HashKeyID == "" && len(p.HashKey) == 0 && len(p.Overrides) == 0 {
		return DefaultPolicy()
	}
	return p
}

// Validate rejects ambiguous or unsafe policy configuration. A hash action requires keyed HMAC material;
// raw SHA-256 is deliberately not supported because low-entropy values can otherwise be dictionary-reversed.
func (p Policy) Validate() error {
	p = p.normalized()
	if strings.TrimSpace(p.ID) == "" || p.Version == 0 {
		return fmt.Errorf("%w: privacy policy needs a non-empty id and positive version", shared.ErrValidation)
	}
	if p.MaxArgs <= 0 || p.MaxArgBytes <= 0 || p.MaxPathBytes <= 0 {
		return fmt.Errorf("%w: privacy policy bounds must be positive", shared.ErrValidation)
	}
	for field, disposition := range p.Overrides {
		if !knownField(field) {
			return fmt.Errorf("%w: privacy policy contains unknown field %q", shared.ErrValidation, field)
		}
		if !disposition.valid() {
			return fmt.Errorf("%w: privacy policy field %q has invalid disposition %q", shared.ErrValidation, field, disposition)
		}
		if disposition == Hash && (len(p.HashKey) < 16 || strings.TrimSpace(p.HashKeyID) == "") {
			return fmt.Errorf("%w: privacy policy hash disposition for %q needs a >=16-byte key and key id", shared.ErrValidation, field)
		}
	}
	return nil
}

func knownField(field Field) bool {
	switch field {
	case FieldProcessComm, FieldProcessPath, FieldProcessArg, FieldProcessEnv,
		FieldNetworkLocalAddr, FieldNetworkRemoteAddr, FieldNetworkComm,
		FieldFilePath, FieldFileComm, FieldPrivilegeComm, FieldPrivilegeCap,
		FieldResourceHost, FieldResourceClusterID, FieldResourceNodeUID, FieldResourceNamespace,
		FieldResourceServiceAccount, FieldResourceWorkloadUID, FieldResourcePodUID,
		FieldResourceContainerID, FieldResourceImageDigest, FieldResourceRuntime:
		return true
	default:
		return false
	}
}

// Digest returns a deterministic digest of policy semantics, excluding HashKey bytes. HashKeyID is part
// of the digest so a correlation-key rotation produces a distinct RedactionPolicyDigest without exposing it.
func (p Policy) Digest() (string, error) {
	p = p.normalized()
	if err := p.Validate(); err != nil {
		return "", err
	}
	type override struct {
		Field       Field            `json:"field"`
		Disposition FieldDisposition `json:"disposition"`
	}
	keys := make([]string, 0, len(p.Overrides))
	for field := range p.Overrides {
		keys = append(keys, string(field))
	}
	sort.Strings(keys)
	ovs := make([]override, 0, len(keys))
	for _, key := range keys {
		f := Field(key)
		ovs = append(ovs, override{Field: f, Disposition: p.Overrides[f]})
	}
	canonical, err := json.Marshal(struct {
		ID           string     `json:"id"`
		Version      uint64     `json:"version"`
		MaxArgs      int        `json:"max_args"`
		MaxArgBytes  int        `json:"max_arg_bytes"`
		MaxPathBytes int        `json:"max_path_bytes"`
		HashKeyID    string     `json:"hash_key_id,omitempty"`
		Overrides    []override `json:"overrides,omitempty"`
	}{p.ID, p.Version, p.MaxArgs, p.MaxArgBytes, p.MaxPathBytes, p.HashKeyID, ovs})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return "redaction-sha256:" + hex.EncodeToString(sum[:]), nil
}

var (
	assignmentSecretRE = regexp.MustCompile(`(?i)(password|passwd|pwd|token|api[_-]?key|secret|client[_-]?secret)(\s*[:=]\s*)([^\s,;&]+)`)
	bearerSecretRE     = regexp.MustCompile(`(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+`)
	urlCredentialsRE   = regexp.MustCompile(`([A-Za-z][A-Za-z0-9+.-]*://)[^/@\s]+@`)
)

// Classify applies the safe default policy to one field value. Call Policy.Classify for an explicit tenant policy.
func Classify(field Field, value string) (string, FieldDisposition, error) {
	return DefaultPolicy().Classify(field, value)
}

// Classify applies the field policy to one value. Known secret syntax is always scrubbed even when a
// tenant override says Allow: overrides may make policy stricter, never disable the baseline secret guard.
func (p Policy) Classify(field Field, value string) (string, FieldDisposition, error) {
	p = p.normalized()
	if err := p.Validate(); err != nil {
		return "", "", err
	}
	return p.classifyValidated(field, value)
}

func (p Policy) classifyValidated(field Field, value string) (string, FieldDisposition, error) {
	if !knownField(field) {
		return "", "", fmt.Errorf("%w: unknown privacy field %q", shared.ErrValidation, field)
	}
	disposition := Allow
	if field == FieldProcessEnv {
		disposition = Drop
	}
	if override, ok := p.Overrides[field]; ok {
		disposition = override
	}
	if disposition == Drop {
		return "", Drop, nil
	}
	// An absent optional field stays absent. Redaction or hashing must never manufacture a synthetic
	// value that makes downstream readers believe the sensor observed data it did not have.
	if value == "" {
		return "", disposition, nil
	}
	// Known-secret syntax is a hard baseline, not a tenant-tunable preference. Hashing a password/token
	// would hide the plaintext but still create a durable cross-event identifier for the secret itself;
	// the contract says known secrets are redacted (or dropped), so overrides cannot weaken that rule.
	if scrubbed, changed := scrubKnownSecrets(value); changed {
		return scrubbed, Redact, nil
	}
	switch disposition {
	case Hash:
		mac := hmac.New(sha256.New, p.HashKey)
		_, _ = mac.Write([]byte("telemetry-field:v1\x00" + string(field) + "\x00" + value))
		return "hmac-sha256:" + hex.EncodeToString(mac.Sum(nil)), Hash, nil
	case Redact:
		return Placeholder, Redact, nil
	case Allow:
		return value, Allow, nil
	default:
		return "", "", fmt.Errorf("%w: invalid privacy disposition %q", shared.ErrValidation, disposition)
	}
}

func scrubKnownSecrets(value string) (string, bool) {
	out := value
	upper := strings.ToUpper(out)
	if strings.Contains(upper, "-----BEGIN") && strings.Contains(upper, "PRIVATE KEY-----") {
		return Placeholder, true
	}
	out = assignmentSecretRE.ReplaceAllString(out, "$1$2"+Placeholder)
	out = bearerSecretRE.ReplaceAllString(out, "$1"+Placeholder)
	out = urlCredentialsRE.ReplaceAllString(out, "$1"+Placeholder+"@")
	return out, out != value
}

func secretFlag(arg string) bool {
	switch strings.ToLower(strings.TrimSpace(arg)) {
	case "--password", "--passwd", "--pwd", "--token", "--api-key", "--apikey", "--secret", "--client-secret":
		return true
	default:
		return false
	}
}

func credentialPairFlag(arg string) bool {
	switch strings.ToLower(strings.TrimSpace(arg)) {
	case "-u", "--user", "--proxy-user":
		return true
	default:
		return false
	}
}

// Scrub returns a deep-copied, source-safe envelope and records the exact RedactionPolicyDigest applied.
// It never mutates the caller's object. Bounds are UTF-8 safe and update the existing A1 truncation flags.
func Scrub(envelope telemetry.TelemetryEnvelope, policy Policy) (telemetry.TelemetryEnvelope, error) {
	policy = policy.normalized()
	if err := policy.Validate(); err != nil {
		return telemetry.TelemetryEnvelope{}, err
	}
	out := envelope.Clone()
	digest, err := policy.Digest()
	if err != nil {
		return telemetry.TelemetryEnvelope{}, err
	}

	classify := func(field Field, value string) (string, error) {
		v, _, err := policy.classifyValidated(field, value)
		return v, err
	}
	if p := out.Event.Process; p != nil {
		if p.Comm, err = classify(FieldProcessComm, p.Comm); err != nil {
			return telemetry.TelemetryEnvelope{}, err
		}
		path, truncated := truncateUTF8(p.Path, policy.MaxPathBytes)
		if truncated {
			p.PathTruncated = true
			out.DataQuality = out.DataQuality.With(telemetry.QualityTruncatedPath)
		}
		if p.Path, err = classify(FieldProcessPath, path); err != nil {
			return telemetry.TelemetryEnvelope{}, err
		}
		args := p.Args
		if len(args) > policy.MaxArgs {
			args = args[:policy.MaxArgs]
			p.ArgsTruncated = true
			out.DataQuality = out.DataQuality.With(telemetry.QualityTruncatedArgv)
		}
		clean := make([]string, 0, len(args))
		redactNext := false
		credentialNext := false
		for _, raw := range args {
			arg, truncated := truncateUTF8(raw, policy.MaxArgBytes)
			if truncated {
				p.ArgsTruncated = true
				out.DataQuality = out.DataQuality.With(telemetry.QualityTruncatedArgv)
			}
			if redactNext {
				clean = append(clean, Placeholder)
				redactNext = false
				continue
			}
			if credentialNext {
				credentialNext = false
				// curl-style -u/--user values are credentials only when they actually carry a
				// user:secret pair. A bare username remains observable instead of being over-redacted.
				if strings.Contains(arg, ":") {
					clean = append(clean, Placeholder)
					continue
				}
			}
			if secretFlag(arg) {
				clean = append(clean, arg)
				redactNext = true
				continue
			}
			if credentialPairFlag(arg) {
				clean = append(clean, arg)
				credentialNext = true
				continue
			}
			v, disposition, classErr := policy.classifyValidated(FieldProcessArg, arg)
			if classErr != nil {
				return telemetry.TelemetryEnvelope{}, classErr
			}
			if disposition != Drop {
				clean = append(clean, v)
			}
		}
		p.Args = clean
	}
	if n := out.Event.Network; n != nil {
		if n.LocalAddr, err = classify(FieldNetworkLocalAddr, n.LocalAddr); err != nil {
			return telemetry.TelemetryEnvelope{}, err
		}
		if n.RemoteAddr, err = classify(FieldNetworkRemoteAddr, n.RemoteAddr); err != nil {
			return telemetry.TelemetryEnvelope{}, err
		}
		if n.Comm, err = classify(FieldNetworkComm, n.Comm); err != nil {
			return telemetry.TelemetryEnvelope{}, err
		}
	}
	if f := out.Event.File; f != nil {
		path, truncated := truncateUTF8(f.Path, policy.MaxPathBytes)
		if truncated {
			f.PathTruncated = true
			out.DataQuality = out.DataQuality.With(telemetry.QualityTruncatedPath)
		}
		if f.Path, err = classify(FieldFilePath, path); err != nil {
			return telemetry.TelemetryEnvelope{}, err
		}
		if f.Comm, err = classify(FieldFileComm, f.Comm); err != nil {
			return telemetry.TelemetryEnvelope{}, err
		}
	}
	if p := out.Event.Privilege; p != nil {
		if p.Comm, err = classify(FieldPrivilegeComm, p.Comm); err != nil {
			return telemetry.TelemetryEnvelope{}, err
		}
		if p.Cap, err = classify(FieldPrivilegeCap, p.Cap); err != nil {
			return telemetry.TelemetryEnvelope{}, err
		}
	}

	rc := &out.ResourceContext
	fields := []struct {
		field Field
		ptr   *string
	}{
		{FieldResourceHost, &rc.Host}, {FieldResourceClusterID, &rc.ClusterID}, {FieldResourceNodeUID, &rc.NodeUID},
		{FieldResourceNamespace, &rc.Namespace}, {FieldResourceServiceAccount, &rc.ServiceAccount}, {FieldResourceWorkloadUID, &rc.WorkloadUID},
		{FieldResourcePodUID, &rc.PodUID}, {FieldResourceContainerID, &rc.ContainerID}, {FieldResourceImageDigest, &rc.ImageDigest}, {FieldResourceRuntime, &rc.Runtime},
	}
	for _, item := range fields {
		v, classifyErr := classify(item.field, *item.ptr)
		if classifyErr != nil {
			return telemetry.TelemetryEnvelope{}, classifyErr
		}
		*item.ptr = v
	}
	out.RedactionPolicyDigest = digest
	if err := out.Validate(); err != nil {
		return telemetry.TelemetryEnvelope{}, fmt.Errorf("scrubbed telemetry envelope is invalid: %w", err)
	}
	return out, nil
}

func truncateUTF8(value string, maxBytes int) (string, bool) {
	if len(value) <= maxBytes {
		return value, false
	}
	cut := maxBytes
	for cut > 0 && !utf8.ValidString(value[:cut]) {
		cut--
	}
	return value[:cut], true
}
